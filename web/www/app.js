// cedar web UI: WebUSB transports for the CY4500 and KM003C, a live view while
// recording, and the report / text decode / file downloads afterwards. All
// decoding and file formats come from the Rust core (web/src/lib.rs).

import { setupMeter } from "./meter.js";

// Trunk's loader instantiates the wasm module and exposes its bindings; it may
// finish before or after this module runs.
const wasm =
  window.wasmBindings ??
  (await new Promise((resolve) =>
    window.addEventListener("TrunkApplicationStarted", () => resolve(window.wasmBindings), {
      once: true,
    }),
  ));
const INFO = JSON.parse(wasm.deviceInfo());
const CY = INFO.cy4500;
const KM = INFO.km003c;

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const view = (dv) => new Uint8Array(dv.buffer, dv.byteOffset, dv.byteLength);
const isLinux = /Linux/.test(navigator.userAgent) && !/Android/.test(navigator.userAgent);

/** Resolve to `undefined` if `promise` hasn't settled within `ms`. */
function withTimeout(promise, ms) {
  return Promise.race([promise, sleep(ms).then(() => undefined)]);
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function errorText(e) {
  if (e instanceof Error || e instanceof DOMException) return e.message || e.name;
  return String(e);
}

// ---------------------------------------------------------------------------
// Transports

/** Turn an open/claim failure into an actionable message. */
function openError(e, analyzer, rule) {
  const text = errorText(e);
  if (e?.name === "SecurityError" || /access denied/i.test(text)) {
    return new Error(
      `The browser was refused access to the ${analyzer}.` +
        (isLinux
          ? `\nInstall cedar's udev rule, then unplug and replug the analyzer:\n` +
            `  sudo cp contrib/${rule} /etc/udev/rules.d/\n` +
            `  sudo udevadm control --reload-rules`
          : `\nClose any other program using it and try again.`),
    );
  }
  return new Error(`Couldn't open the ${analyzer}: ${text}`);
}

async function openInterface(dev, iface) {
  await dev.open();
  if (dev.configuration === null) await dev.selectConfiguration(1);
  await dev.claimInterface(iface);
}

/**
 * CY4500: one command endpoint plus streaming endpoints for PD records and
 * the oscilloscope trace. WebUSB transfers can't time out, so each IN endpoint
 * gets its own read loop; closing the device ends them.
 */
class Cy4500 {
  kind = "cy4500";
  name = "CY4500 EZ-PD Analyzer";
  constructor(dev) {
    this.dev = dev;
    this.running = false;
    this.loops = [];
  }

  async open() {
    if (this.dev.opened) return;
    try {
      await openInterface(this.dev, 0);
    } catch (e) {
      await this.close();
      throw openError(e, this.name, "71-cy4500.rules");
    }
  }

  async close() {
    try {
      if (this.dev.opened) await this.dev.close();
    } catch {
      // Already gone (unplugged); nothing to release.
    }
  }

  /** Firmware version as "a.b.c.d", or null if the analyzer didn't answer. */
  async version() {
    await this.open();
    try {
      await this.dev.transferOut(CY.epOut, wasm.cy4500CmdVersion());
      const r = await withTimeout(this.dev.transferIn(CY.epResp, 4), 1000);
      if (!r || r.status !== "ok" || r.data.byteLength !== 4) return null;
      return Array.from(view(r.data)).join(".");
    } finally {
      // Closing also cancels the read if it timed out.
      await this.close();
    }
  }

  async start(capture, { scope, onError }) {
    await this.open();
    try {
      await this.dev.transferOut(CY.epOut, wasm.cy4500CmdStart());
    } catch (e) {
      await this.close();
      throw new Error(`Couldn't start the CY4500: ${errorText(e)}`);
    }
    this.running = true;
    const loop = async (ep, size, feed) => {
      while (this.running) {
        let r;
        try {
          r = await this.dev.transferIn(ep, size);
        } catch (e) {
          if (this.running) onError(e);
          return;
        }
        if (r.status === "stall") {
          await this.dev.clearHalt("in", ep).catch(() => {});
          continue;
        }
        // Shorter transfers carry no records (same check as the CLI).
        if (r.data && r.data.byteLength > 8) feed(view(r.data));
      }
    };
    this.loops = [loop(CY.epData, CY.maxRead, (d) => capture.feedCy4500Pd(d))];
    if (scope) {
      this.loops.push(loop(CY.epScope, CY.maxScopeRead, (d) => capture.feedCy4500Scope(d)));
    }
  }

  async stop() {
    this.running = false;
    if (this.dev.opened) {
      await withTimeout(this.dev.transferOut(CY.epOut, wasm.cy4500CmdStop()).catch(() => {}), 1000);
    }
    await this.close();
    await Promise.allSettled(this.loops);
    this.loops = [];
  }
}

/**
 * KM003C: request/response on one bulk pair. A single read loop queues
 * everything that arrives on the IN endpoint; transactions take from the
 * queue with a deadline, skipping responses whose transaction id doesn't
 * match (as the CLI does).
 */
class Km003c {
  kind = "km003c";
  name = "POWER-Z KM003C";
  constructor(dev) {
    this.dev = dev;
    this.running = false;
    this.loops = [];
    this.queue = [];
    this.waiter = null;
    this.reading = false;
    this.reader = null;
    this.readError = null;
    this.nextId = 0;
  }

  async open() {
    if (this.dev.opened) return;
    try {
      await openInterface(this.dev, KM.interface);
    } catch (e) {
      await this.close();
      if (e?.name === "NetworkError" || /claim/i.test(errorText(e))) {
        throw new Error(
          "Couldn't claim the KM003C's USB interface." +
            (isLinux
              ? "\nOn Linux the kernel's powerz driver usually holds it. Release it with:\n" +
                "  sudo modprobe -r powerz\n" +
                "To keep it from loading again, add \"blacklist powerz\" to a file in /etc/modprobe.d/."
              : "\nClose the POWER-Z software or any other program using the meter and try again."),
        );
      }
      throw openError(e, this.name, "71-powerz-km003c.rules");
    }
    this.queue = [];
    this.readError = null;
    this.reading = true;
    this.reader = this.readLoop();
    // Discard anything left in the IN pipe from an earlier session.
    await sleep(50);
    this.queue = [];
  }

  async readLoop() {
    while (this.reading) {
      let r;
      try {
        r = await this.dev.transferIn(KM.epIn, 4096);
      } catch (e) {
        this.readError = e;
        break;
      }
      if (r.status === "stall") {
        await this.dev.clearHalt("in", KM.epIn).catch(() => {});
        continue;
      }
      if (r.data && r.data.byteLength) {
        this.queue.push(view(r.data).slice());
        this.wake();
      }
    }
    this.reading = false;
    this.wake();
  }

  wake() {
    const w = this.waiter;
    this.waiter = null;
    if (w) w();
  }

  async nextChunk(deadline) {
    while (!this.queue.length) {
      if (!this.reading) {
        throw this.readError ?? new Error("the KM003C connection closed");
      }
      const left = deadline - performance.now();
      if (left <= 0) throw new Error("timed out waiting for a KM003C response");
      await new Promise((res) => {
        this.waiter = res;
        setTimeout(res, left);
      });
    }
    return this.queue.shift();
  }

  /** Send command `name` and return its whole response. */
  async transact(name) {
    this.nextId = (this.nextId + 1) & 0xff;
    const id = this.nextId;
    await this.dev.transferOut(KM.epOut, wasm.km003cRequest(name, id));
    const deadline = performance.now() + 1000;
    let msg = new Uint8Array(0);
    for (;;) {
      msg = concat(msg, await this.nextChunk(deadline));
      if (msg.length >= 2 && msg[1] !== id) {
        msg = new Uint8Array(0);
        continue;
      }
      if (wasm.km003cComplete(name, msg)) {
        wasm.km003cCheck(name, msg);
        return msg;
      }
    }
  }

  async start(capture, { onError }) {
    await this.open();
    try {
      await this.transact("connect");
      await this.transact("monitorOn");
    } catch (e) {
      await this.close();
      throw new Error(`Couldn't start the KM003C's PD monitor: ${errorText(e)}`);
    }
    this.monitor = true;
    this.running = true;
    this.loops = [
      (async () => {
        try {
          while (this.running) {
            capture.feedKm003c(await this.transact("poll"));
            await sleep(KM.pollMs);
          }
        } catch (e) {
          if (this.running) onError(e);
        }
      })(),
    ];
  }

  /**
   * Poll the measurement block (µA readings) without the PD monitor, calling
   * `onReading(response, performance.now())` for each, as `cedar meter`.
   */
  async startMeter(onReading, { onError }) {
    await this.open();
    try {
      await this.transact("connect");
    } catch (e) {
      await this.close();
      throw new Error(`Couldn't start the KM003C: ${errorText(e)}`);
    }
    this.monitor = false;
    this.running = true;
    this.loops = [
      (async () => {
        try {
          while (this.running) {
            onReading(await this.transact("adc"), performance.now());
            await sleep(KM.pollMs);
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
    if (this.reading && this.monitor) {
      // Always try to turn the monitor off again, even after an error.
      await this.transact("monitorOff").catch(() => {});
    }
    this.monitor = false;
    await this.close();
  }

  async close() {
    this.reading = false;
    try {
      if (this.dev.opened) await this.dev.close();
    } catch {
      // Already gone.
    }
    await this.reader;
    this.reader = null;
  }
}

const FILTERS = [
  { vendorId: CY.vid, productId: CY.pid },
  { vendorId: CY.vid, productId: CY.pidFirmware },
  { vendorId: KM.vid, productId: KM.pid },
];

function analyzerFor(dev) {
  if (dev.vendorId === CY.vid && dev.productId === CY.pid) return new Cy4500(dev);
  if (dev.vendorId === KM.vid && dev.productId === KM.pid) return new Km003c(dev);
  if (dev.vendorId === CY.vid && dev.productId === CY.pidFirmware) {
    throw new Error(
      "This CY4500 is in firmware-update mode. Load its capture firmware with " +
        "Infineon's EZ-PD Protocol Analyzer utility, then replug it.",
    );
  }
  return null;
}

// ---------------------------------------------------------------------------
// State

/** @type {Cy4500 | Km003c | null} */
let analyzer = null;
let state = "idle"; // idle | ready | starting | recording | stopping
let capture = null; // the Capture being recorded
let recordScope = true;
let liveTimer = null;
let liveFrom = 0;
let firstPacketTime = null;
let recordStart = 0;
/** Shown below the bench: { items: [{label, capture}], recorded, kind, saved } */
let results = null;

// ---------------------------------------------------------------------------
// UI helpers

function showError(text) {
  const n = $("notice");
  n.textContent = text;
  n.hidden = !text;
}

let deviceDetail = "Plug in a CY4500 or KM003C, then choose it.";

function setDevice(name, detail) {
  deviceDetail = detail;
  $("device-name").textContent = name;
  $("device-detail").textContent = detail;
}

function render() {
  const recording = state === "recording" || state === "stopping";
  const busy = state === "starting" || state === "stopping";
  // The current meter uses the same KM003C; one or the other runs.
  const measuring = meterView?.busy ?? false;
  $("btn-record").hidden = recording;
  $("btn-stop").hidden = !recording;
  $("btn-record").disabled = !analyzer || busy || measuring;
  $("btn-stop").disabled = state === "stopping";
  $("btn-choose").disabled = recording || busy || measuring;
  $("opt-scope").disabled = recording || busy;
  $("file-input").disabled = recording || busy;
  $("rec-dot").className = "dot" + (recording ? " live" : analyzer ? " ready" : "");
  $("device-detail").textContent =
    state === "starting"
      ? "Starting…"
      : recording
        ? "Recording."
        : measuring
          ? "Measuring current in the Current meter view. Stop it to record."
          : deviceDetail;
  document.querySelector(".readout").classList.toggle("idle", !recording);
  meterView?.render();
}

function localStamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function fmtElapsed(ms) {
  const s = Math.floor(ms / 1000);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

const mvNumber = (s) => Number(String(s).replace(/,/g, ""));

// ---------------------------------------------------------------------------
// Choosing an analyzer

async function adopt(dev) {
  let a;
  try {
    a = analyzerFor(dev);
  } catch (e) {
    showError(errorText(e));
    return;
  }
  if (!a) return;
  analyzer = a;
  showError("");
  setDevice(a.name, "Checking…");
  render();
  if (a.kind === "cy4500") {
    try {
      const v = await a.version();
      setDevice(a.name, v ? `Firmware ${v}. Ready to record.` : "Ready to record.");
    } catch (e) {
      setDevice(a.name, "Couldn't open it.");
      showError(errorText(e));
    }
  } else {
    const v = `${dev.deviceVersionMajor}.${dev.deviceVersionMinor}${dev.deviceVersionSubminor}`;
    setDevice(a.name, `USB device version ${v}. Ready to record.`);
  }
  if (analyzer === a && state === "idle") state = "ready";
  render();
}

async function chooseAnalyzer(filters = FILTERS) {
  let dev;
  try {
    dev = await navigator.usb.requestDevice({ filters });
  } catch (e) {
    if (e?.name !== "NotFoundError") showError(errorText(e)); // NotFoundError: picker cancelled
    return;
  }
  await adopt(dev);
}

// ---------------------------------------------------------------------------
// Recording

function freeResults() {
  if (!results) return;
  for (const it of results.items) it.capture.free();
  results = null;
  $("results").hidden = true;
  $("report-frame").srcdoc = "";
}

function resetLive() {
  $("log-body").replaceChildren();
  $("log-empty").hidden = false;
  liveFrom = 0;
  firstPacketTime = null;
  $("r-vbus").textContent = "0.00";
  $("r-ibus").textContent = "0.00";
  $("r-power").textContent = "0.0";
  document.querySelector(".readout").classList.add("blank");
  $("r-cc1").textContent = "–";
  $("r-cc2").textContent = "–";
  $("r-elapsed").textContent = "0:00";
  $("r-packets").textContent = "0";
  $("s-contract").textContent = "none yet";
  $("s-cable").textContent = "not discovered";
  $("s-partner").textContent = "not discovered";
  $("s-display-row").hidden = true;
}

async function startRecording() {
  if (!analyzer || state !== "ready" || meterView.busy) return;
  if (results?.recorded && !results.saved && !confirm("Discard the capture you haven't saved?")) return;
  freeResults();
  showError("");
  state = "starting";
  render();

  capture = new wasm.Capture();
  recordScope = $("opt-scope").checked;
  resetLive();
  document.querySelector(".bench").classList.add("armed");
  try {
    await analyzer.start(capture, {
      scope: recordScope,
      onError: (e) => stopRecording(`Recording stopped: ${errorText(e)}`),
    });
  } catch (e) {
    capture.free();
    capture = null;
    state = "ready";
    render();
    showError(errorText(e));
    return;
  }
  state = "recording";
  recordStart = performance.now();
  liveTimer = setInterval(refreshLive, 200);
  render();
}

async function stopRecording(reason) {
  if (state !== "recording") return;
  state = "stopping";
  render();
  clearInterval(liveTimer);
  await analyzer.stop();
  // The KM003C reports levels with every poll; drop them if unwanted.
  if (analyzer.kind === "km003c" && !recordScope) capture.clearScope();
  refreshLive();
  state = analyzer ? "ready" : "idle";
  render();
  if (reason) showError(reason);

  const kind = analyzer.kind;
  const c = capture;
  capture = null;
  showResults([{ label: `capture-${localStamp()}`, capture: c }], { recorded: true, kind });
}

function refreshLive() {
  if (!capture) return;
  const live = JSON.parse(capture.liveJson(liveFrom));
  $("r-elapsed").textContent = fmtElapsed(performance.now() - recordStart);
  $("r-packets").textContent = live.packets.toLocaleString();

  const lv = live.levels;
  if (lv) {
    document.querySelector(".readout").classList.remove("blank");
    const v = lv.vbus / 1000;
    const i = lv.ibus / 1000;
    $("r-vbus").textContent = v.toFixed(2);
    $("r-ibus").textContent = i.toFixed(2);
    $("r-power").textContent = (v * i).toFixed(1);
    $("r-cc1").textContent = `${(lv.cc1 / 1000).toFixed(2)} V`;
    $("r-cc2").textContent = `${(lv.cc2 / 1000).toFixed(2)} V`;
  }
  $("s-contract").textContent = live.contract ?? "none yet";
  $("s-cable").textContent = live.cable ?? "not discovered";
  $("s-partner").textContent = live.partner ?? "not discovered";
  $("s-display-row").hidden = !live.display;
  $("s-display").textContent = live.display ?? "";

  if (live.rows.length) appendRows(live.rows);
  liveFrom = live.packets;
}

const MAX_LOG_ROWS = 500;

function appendRows(rows) {
  const wrap = $("log-wrap");
  const body = $("log-body");
  const atBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 24;
  const frag = document.createDocumentFragment();
  for (const r of rows) {
    const t = Number(r.t);
    if (firstPacketTime === null) firstPacketTime = t;
    const tr = document.createElement("tr");
    let msg = r.msg;
    if (r.ok === "VBUS_UP" || r.ok === "VBUS_DN") {
      tr.className = "attach";
      msg = r.ok === "VBUS_UP" ? "VBUS up" : "VBUS down";
    } else if (r.ok !== "OK") {
      tr.className = "bad";
      msg = `${r.msg} (${r.ok})`;
    } else if (r.msg === "GOODCRC") {
      tr.className = "quiet";
    }
    if (r.event) tr.classList.add("has-event");
    const cells = [
      [((t - firstPacketTime) / 1e6).toFixed(4), "num"],
      [r.sop, ""],
      [msg, "msg"],
      [(mvNumber(r.vbus) / 1000).toFixed(2), "num"],
      [tr.className === "attach" ? "" : r.data, "data"],
      [r.event ?? "", "event"],
    ];
    for (const [text, cls] of cells) {
      const td = document.createElement("td");
      td.textContent = text;
      if (cls) td.className = cls;
      if (cls === "data") td.title = text;
      tr.append(td);
    }
    frag.append(tr);
  }
  body.append(frag);
  while (body.childElementCount > MAX_LOG_ROWS) body.firstElementChild.remove();
  $("log-empty").hidden = true;
  if (atBottom) wrap.scrollTop = wrap.scrollHeight;
}

// ---------------------------------------------------------------------------
// Results: report, text decode, downloads

function showResults(items, { recorded, kind }) {
  freeResults();
  results = { items, recorded, kind, saved: !recorded };
  const single = items.length === 1;
  $("results-title").textContent = recorded
    ? "Recorded capture"
    : single
      ? items[0].label
      : `${items.length} captures`;
  $("out-name").value = single ? items[0].label : "report";
  $("dl-ccgx3").hidden = !recorded;
  $("dl-csv").hidden = !single;
  $("dl-raw").hidden = !(recorded && kind === "km003c" && items[0].capture.rawLog());
  $("results").hidden = false;
  renderReport();
  renderDump();
  selectTab(recorded && items[0].capture.packetCount === 0 ? "text" : "report");
}

function outName() {
  const n = $("out-name").value.trim().replace(/\.(ccgx3|csv|html|txt)$/i, "").replace(/[\\/:*?"<>|]/g, "_");
  return n || "capture";
}

/** Labels for the report: a recorded capture takes the chosen file name. */
function labelled() {
  if (results.recorded) return [{ label: outName(), capture: results.items[0].capture }];
  return results.items;
}

function reportHtml() {
  const r = new wasm.Report();
  try {
    for (const it of labelled()) r.add(it.label, it.capture);
    return r.html(Date.now() / 1000);
  } finally {
    r.free();
  }
}

function renderReport() {
  $("report-frame").srcdoc = reportHtml();
}

function renderDump() {
  const events = $("opt-events").checked;
  const levels = $("opt-levels").checked;
  const multi = results.items.length > 1;
  $("dump").textContent = results.items
    .map((it) => (multi ? `== ${it.label} ==\n` : "") + it.capture.dump(events, levels))
    .join("\n");
}

function selectTab(which) {
  const report = which === "report";
  $("tab-report").setAttribute("aria-selected", String(report));
  $("tab-text").setAttribute("aria-selected", String(!report));
  $("pane-report").hidden = !report;
  $("pane-text").hidden = report;
}

function download(name, data, type) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

function saveCcgx3() {
  try {
    download(`${outName()}.ccgx3`, results.items[0].capture.ccgx3(Date.now() / 1000), "application/zip");
    results.saved = true;
  } catch (e) {
    showError(`Couldn't build the .ccgx3 file: ${errorText(e)}`);
  }
}

// ---------------------------------------------------------------------------
// Opening .ccgx3 files

async function openFiles(files) {
  files = [...files].filter((f) => f.size > 0);
  if (!files.length) return;
  if (state === "recording" || state === "starting" || state === "stopping") {
    showError("Stop recording before opening captures.");
    return;
  }
  if (results?.recorded && !results.saved && !confirm("Discard the capture you haven't saved?")) return;
  if (location.hash === "#meter") location.hash = "#capture";
  const items = [];
  const errors = [];
  for (const f of files) {
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      items.push({ label: f.name.replace(/\.ccgx3$/i, ""), capture: wasm.Capture.fromCcgx3(bytes) });
    } catch (e) {
      errors.push(`${f.name}: ${errorText(e)}`);
    }
  }
  showError(errors.length ? `Couldn't open ${errors.join("\n")}` : "");
  if (items.length) showResults(items, { recorded: false });
}

// ---------------------------------------------------------------------------
// Views: PD capture and current meter, selected by the URL hash

const meterView = setupMeter({
  wasm,
  meter: () => (analyzer?.kind === "km003c" ? analyzer : null),
  other: () => (analyzer && analyzer.kind !== "km003c" ? analyzer.name : null),
  choose: () => chooseAnalyzer([{ vendorId: KM.vid, productId: KM.pid }]),
  captureBusy: () => state === "starting" || state === "recording" || state === "stopping",
  changed: render,
  showError,
  download,
  stamp: localStamp,
  errorText,
});

function showView(name) {
  const meter = name === "meter";
  $("view-capture").hidden = meter;
  $("view-meter").hidden = !meter;
  $("open-btn").hidden = meter;
  for (const [id, on] of [["nav-capture", !meter], ["nav-meter", meter]]) {
    if (on) $(id).setAttribute("aria-current", "page");
    else $(id).removeAttribute("aria-current");
  }
  if (meter) meterView.shown();
}

const hashView = () => (location.hash === "#meter" ? "meter" : "capture");
window.addEventListener("hashchange", () => showView(hashView()));
showView(hashView());

// ---------------------------------------------------------------------------
// Wiring

$("btn-choose").addEventListener("click", chooseAnalyzer);
$("btn-record").addEventListener("click", startRecording);
$("btn-stop").addEventListener("click", () => stopRecording());
$("file-input").addEventListener("change", (e) => {
  openFiles(e.target.files);
  e.target.value = "";
});
$("tab-report").addEventListener("click", () => selectTab("report"));
$("tab-text").addEventListener("click", () => selectTab("text"));
document.querySelector(".tabs").addEventListener("keydown", (e) => {
  if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
  const next = $("tab-report").getAttribute("aria-selected") === "true" ? "text" : "report";
  selectTab(next);
  $(`tab-${next}`).focus();
});
$("opt-events").addEventListener("change", renderDump);
$("opt-levels").addEventListener("change", renderDump);
$("out-name").addEventListener("change", () => {
  if (results?.recorded) renderReport();
});
$("dl-ccgx3").addEventListener("click", saveCcgx3);
$("dl-csv").addEventListener("click", () =>
  download(`${outName()}.csv`, labelled()[0].capture.csv(), "text/csv"),
);
$("dl-html").addEventListener("click", () => download(`${outName()}.html`, reportHtml(), "text/html"));
$("dl-raw").addEventListener("click", () =>
  download(`${outName()}.km003c.txt`, results.items[0].capture.rawLog(), "text/plain"),
);

// Drag and drop .ccgx3 files anywhere on the page.
let dragDepth = 0;
const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes("Files");
window.addEventListener("dragenter", (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth++;
  $("drop").hidden = false;
});
window.addEventListener("dragover", (e) => {
  if (hasFiles(e)) e.preventDefault();
});
window.addEventListener("dragleave", () => {
  if (--dragDepth <= 0) {
    dragDepth = 0;
    $("drop").hidden = true;
  }
});
window.addEventListener("drop", (e) => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth = 0;
  $("drop").hidden = true;
  openFiles(e.dataTransfer.files);
});

window.addEventListener("beforeunload", (e) => {
  if (state === "recording" || meterView.busy || (results?.recorded && !results.saved)) e.preventDefault();
});

if (!("usb" in navigator)) {
  $("no-webusb").hidden = false;
  $("btn-choose").disabled = true;
  setDevice("Recording unavailable", "Open .ccgx3 captures with the button above or by dropping them here.");
} else {
  navigator.usb.addEventListener("connect", (e) => {
    if (!analyzer) adopt(e.device);
  });
  navigator.usb.addEventListener("disconnect", async (e) => {
    if (!analyzer || e.device !== analyzer.dev) return;
    if (state === "recording") {
      await stopRecording("The analyzer was unplugged. The capture up to that point is below.");
    }
    await meterView.stop("The meter was unplugged. Its figures up to that point are kept.");
    analyzer = null;
    state = "idle";
    setDevice("No analyzer selected", "Plug in a CY4500 or KM003C, then choose it.");
    render();
  });
  // Reconnect to an analyzer this site was already allowed to use, preferring
  // the CY4500 like the CLI does (the KM003C on the meter view).
  const known = await navigator.usb.getDevices();
  const cy = known.find((d) => d.vendorId === CY.vid && d.productId === CY.pid);
  const km = known.find((d) => d.vendorId === KM.vid && d.productId === KM.pid);
  const pick = hashView() === "meter" ? (km ?? cy) : (cy ?? km);
  if (pick) await adopt(pick);
  render();
}
