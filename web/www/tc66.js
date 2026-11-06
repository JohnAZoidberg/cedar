// cedar web UI: Web Serial transport for the RuiDeng TC66 / TC66C USB-C meter.
// It sends 5-byte ASCII commands and reads fixed-size replies; decryption,
// checks and decoding are in the Rust core (tc66.rs, via CurrentMeter.feedTc66).

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isLinux = /Linux/.test(navigator.userAgent) && !/Android/.test(navigator.userAgent);
const errorText = (e) =>
  e instanceof Error || e instanceof DOMException ? e.message || e.name : String(e);

/** Attempts at a `getva` exchange before giving up (as the CLI). */
const ATTEMPTS = 3;
/** How long to wait for a whole reply, in ms. */
const REPLY_TIMEOUT_MS = 1000;

export class Tc66 {
  kind = "tc66";
  name = "TC66 USB-C meter";

  /** `info` is `deviceInfo().tc66`. */
  constructor(port, info) {
    this.port = port;
    this.info = info;
    this.buf = new Uint8Array(0);
    this.wake = null; // resolves the exchange waiting for more bytes
    this.reader = null;
    this.writer = null;
    this.readLoop = null;
    this.ended = null; // why the read loop stopped, once it has
    this.running = false;
    this.loops = [];
  }

  /** Whether `port` is a TC66 (by its USB IDs). */
  static matches(port, info) {
    const { usbVendorId, usbProductId } = port.getInfo();
    return usbVendorId === info.vid && usbProductId === info.pid;
  }

  async open() {
    try {
      // CDC-ACM ignores the baud rate; 115200 matches the vendor software.
      await this.port.open({ baudRate: 115200 });
    } catch (e) {
      throw new Error(
        `Couldn't open the TC66: ${errorText(e)}` +
          (isLinux
            ? "\nOn Linux your user needs access to its serial port (usually the dialout group: " +
              "sudo usermod -aG dialout $USER, then log in again). Close any other program using it."
            : "\nClose any other program using the meter and try again."),
      );
    }
    this.ended = null;
    this.writer = this.port.writable.getWriter();
    this.reader = this.port.readable.getReader();
    this.readLoop = (async () => {
      try {
        for (;;) {
          const { value, done } = await this.reader.read();
          if (done) break;
          if (value?.length) {
            const next = new Uint8Array(this.buf.length + value.length);
            next.set(this.buf);
            next.set(value, this.buf.length);
            this.buf = next;
            this.wake?.();
          }
        }
        this.ended = new Error("the TC66 connection closed");
      } catch (e) {
        this.ended = e;
      }
      this.wake?.();
    })();
  }

  /** Send `cmd` (ASCII) and resolve to its `len`-byte reply. */
  async exchange(cmd, len) {
    this.buf = new Uint8Array(0);
    await this.writer.write(new TextEncoder().encode(cmd));
    const deadline = performance.now() + REPLY_TIMEOUT_MS;
    while (this.buf.length < len) {
      if (this.ended) throw this.ended;
      const left = deadline - performance.now();
      if (left <= 0) {
        throw new Error(`the TC66 sent ${this.buf.length} of ${len} bytes in reply to ${cmd}`);
      }
      await Promise.race([new Promise((r) => (this.wake = r)), sleep(left)]);
    }
    return this.buf.slice(0, len);
  }

  /**
   * Poll the live readings, calling `onReading(reply, performance.now())` for
   * each `getva` reply, as `cedar meter --device tc66`. A reply that
   * `onReading` rejects (by throwing) is retried a few times before
   * `onError` is called.
   */
  async startMeter(onReading, { onError }) {
    await this.open();
    try {
      const mode = new TextDecoder().decode(await this.exchange("query", 4));
      if (mode === "boot") throw new Error("it is in its bootloader; power-cycle it");
    } catch (e) {
      await this.close();
      throw new Error(`Couldn't start the TC66: ${errorText(e)}`);
    }
    this.running = true;
    this.loops = [
      (async () => {
        let failures = 0;
        try {
          while (this.running) {
            try {
              onReading(await this.exchange("getva", this.info.replySize), performance.now());
              failures = 0;
            } catch (e) {
              // A reply can be cut short or misaligned by a late byte.
              if (!this.running || this.ended || ++failures >= ATTEMPTS) throw e;
            }
            await sleep(this.info.pollMs);
          }
        } catch (e) {
          if (this.running) onError(e);
        }
      })(),
    ];
  }

  async stop() {
    this.running = false;
    await Promise.allSettled(this.loops);
    this.loops = [];
    await this.close();
  }

  async close() {
    try {
      await this.reader?.cancel();
    } catch {
      // Already gone.
    }
    await this.readLoop;
    for (const s of [this.reader, this.writer]) {
      try {
        s?.releaseLock();
      } catch {
        // Already released.
      }
    }
    this.reader = this.writer = this.readLoop = null;
    try {
      await this.port.close();
    } catch {
      // Already closed or unplugged.
    }
  }
}
