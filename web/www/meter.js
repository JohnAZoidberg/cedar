// cedar web UI: the current-meter view. Polls a POWER-Z KM003C's measurement
// block (µA resolution, over WebUSB) or a TC66's readings (10 µA, over Web
// Serial) and shows the rolling window average against a limit, as `cedar
// meter` does. The statistics come from the Rust core (CurrentMeter in
// web/src/lib.rs, src/meter.rs); this module is the view.

import { Tc66 } from "./tc66.js";

const $ = (id) => document.getElementById(id);

/** Seconds of history the trace shows. */
const TRACE_SPAN_S = 30;
/** Readings kept for the trace (100 Hz × span, with headroom). */
const TRACE_MAX = 4000;

const STORE_OFFSET = "cedar.meter.offsetUa";
const STORE_LIMIT = "cedar.meter.limit";

function load(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function store(key, value) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Storage unavailable (private window, blocked): settings just don't persist.
  }
}

/** µA → "1.234" (mA, µA resolution). */
const mA = (ua) => (ua / 1000).toFixed(3);
const mAUnit = (ua) => `${mA(ua)} mA`;

function fmtElapsed(s) {
  const t = Math.floor(s);
  return `${Math.floor(t / 60)}:${String(t % 60).padStart(2, "0")}`;
}

const fmtWindow = (s) => `${Number(s.toFixed(2))} s`;

/**
 * Set up the meter view. `host` connects it to the page:
 *   wasm          the Rust bindings
 *   meter()       the selected analyzer if it is a KM003C, else null
 *   other()       the selected analyzer's name if it isn't a KM003C, else null
 *   choose()      ask the browser for a KM003C and select it
 *   captureBusy() whether a PD capture is running (the KM003C can't measure)
 *
 * A TC66 is a serial port, separate from the selected analyzer, so the view
 * manages it here; it can measure while the analyzer records.
 *   changed()     the meter started or stopped (the capture view re-renders)
 *   showError(t)  show (or with "" clear) the page's error notice
 *   download(name, data, type), stamp(), errorText(e)
 */
export function setupMeter(host) {
  const { wasm } = host;
  const TC66 = JSON.parse(wasm.deviceInfo()).tc66;
  const hasSerial = "serial" in navigator;
  let state = "idle"; // idle | starting | measuring | stopping
  let meter = null; // wasm CurrentMeter: kept after Stop for the figures and CSV
  let device = null; // the Km003c or Tc66 being polled
  let tc66 = null; // a TC66 this page may use (a Tc66), if any
  let preferTc66 = false; // the TC66 was chosen last (else the KM003C wins, as in the CLI)
  let timer = null;
  let trace = []; // {t, i, w}: elapsed s, reading µA, window average µA or null
  let last = null; // the latest reading (JSON from the core)
  let limitUa = 2500;
  let hoverX = null;

  // --- Settings -----------------------------------------------------------

  let offsetUa = Number(load(STORE_OFFSET)) || 0;
  const savedLimit = load(STORE_LIMIT);
  if (savedLimit) $("m-limit").value = savedLimit;

  function readLimit() {
    const input = $("m-limit");
    try {
      limitUa = Math.abs(wasm.parseCurrent(input.value));
      input.removeAttribute("aria-invalid");
      store(STORE_LIMIT, input.value.trim());
    } catch {
      input.setAttribute("aria-invalid", "true");
    }
    update();
  }

  function readWindow() {
    const input = $("m-window-s");
    const v = Number(input.value);
    const ok = Number.isFinite(v) && v >= 0.1 && v <= 60;
    input.toggleAttribute("aria-invalid", !ok);
    return ok ? v : 1;
  }

  // --- Measuring ----------------------------------------------------------

  const busy = () => state !== "idle";

  /** The meter to measure with: the KM003C analyzer or the TC66. */
  function source() {
    const km = host.meter();
    return preferTc66 ? (tc66 ?? km) : (km ?? tc66);
  }

  /** Whether `src` is free to start (the KM003C is shared with PD capture). */
  const canStart = (src) => src && !busy() && !(src.kind === "km003c" && host.captureBusy());

  async function start() {
    const km = source();
    if (!canStart(km)) return;
    host.showError("");
    meter?.free();
    meter = new wasm.CurrentMeter(readWindow(), offsetUa);
    trace = [];
    last = null;
    device = km;
    state = "starting";
    render();
    host.changed();
    try {
      await km.startMeter(
        (resp, tMs) => {
          if (km.kind === "tc66") {
            // The TC66 repeats its reading between refreshes; skip repeats.
            if (!meter.feedTc66(resp, tMs)) return;
          } else {
            meter.feed(resp, tMs);
          }
          const r = JSON.parse(meter.readingJson());
          trace.push({ t: r.elapsed, i: r.ibus, w: r.window });
          if (trace.length > TRACE_MAX) trace.splice(0, trace.length - TRACE_MAX);
        },
        { onError: (e) => stop(`Measuring stopped: ${host.errorText(e)}`) },
      );
    } catch (e) {
      state = "idle";
      device = null;
      render();
      host.changed();
      host.showError(host.errorText(e));
      return;
    }
    state = "measuring";
    timer = setInterval(update, 200);
    render();
  }

  async function stop(reason) {
    if (state !== "measuring") return;
    state = "stopping";
    render();
    clearInterval(timer);
    await device.stop();
    device = null;
    state = "idle";
    update();
    render();
    host.changed();
    if (reason) host.showError(reason);
  }

  function zero() {
    if (!meter) return;
    const z = meter.zero();
    if (z === undefined) return;
    setOffset(z);
  }

  function setOffset(ua) {
    offsetUa = ua;
    store(STORE_OFFSET, ua ? String(ua) : null);
    if (meter) meter.setOffset(ua);
    trace = [];
    last = null;
    update();
  }

  function resetStats() {
    if (!meter) return;
    meter.reset();
    trace = [];
    last = null;
    update();
  }

  // --- Rendering ----------------------------------------------------------

  /** Device bar and buttons. */
  function render() {
    const km = busy() ? device : source();
    const measuring = state === "measuring" || state === "stopping";
    const other = host.other();
    const coarse = km?.kind === "tc66" ? " (10 µA steps, about two readings a second)" : "";
    $("m-device-name").textContent = km ? km.name : other ?? "No meter selected";
    $("m-device-detail").textContent =
      state === "starting"
        ? "Starting…"
        : measuring
          ? `Measuring${coarse}.`
          : km
            ? km.kind === "km003c" && host.captureBusy()
              ? "Recording a PD capture. Stop it to measure."
              : `Ready to measure${coarse}.`
            : other
              ? "The current meter needs a POWER-Z KM003C or a TC66."
              : "Plug in a POWER-Z KM003C or TC66, then choose it.";
    $("m-dot").className = "dot" + (measuring ? " live" : km ? " ready" : "");
    $("m-start").hidden = measuring;
    $("m-stop").hidden = !measuring;
    $("m-start").disabled = !canStart(km);
    $("m-stop").disabled = state === "stopping";
    $("m-choose").disabled = busy() || host.captureBusy() || !("usb" in navigator);
    $("m-choose-tc66").hidden = !hasSerial;
    $("m-choose-tc66").disabled = busy();
    // Only the KM003C reports its own 1 s average.
    const ownAvg = last ? last.meterAvg !== null : km?.kind !== "tc66";
    $("m-meteravg-fig").hidden = !ownAvg;
    $("m-window-s").disabled = busy();
    $("m-zero").disabled = !(measuring && last && last.samples > 1);
    $("m-reset").disabled = !(measuring && last);
    $("m-clear-zero").hidden = !offsetUa;
    $("m-csv").disabled = !meter || !last;
    const readout = document.querySelector(".meter-readout");
    readout.classList.toggle("idle", !measuring);
    readout.classList.toggle("no-own-avg", !ownAvg);
  }

  /** Figures, verdict and trace. */
  function update() {
    if (meter) {
      const r = JSON.parse(meter.readingJson());
      if (r) last = r;
    }
    const r = last;
    const win = fmtWindow(r ? r.windowS : readWindow());
    $("m-window-label").textContent = `${win} average`;
    $("m-worst-label").textContent = `Worst ${win} average`;
    $("m-legend-avg").textContent = `${win} average`;
    document.querySelector(".meter-readout").classList.toggle("blank", !r);
    $("m-offset").textContent = offsetUa ? mAUnit(offsetUa) : "none";

    if (!r) {
      for (const id of ["m-window", "m-now", "m-meteravg"]) $(id).textContent = "0.000";
      for (const id of ["m-vbus", "m-readings", "m-elapsed", "m-mean", "m-std", "m-min", "m-max", "m-worst", "m-worst-meter"]) {
        $(id).textContent = "–";
      }
    } else {
      $("m-window").textContent = r.window === null ? "…" : mA(r.window);
      $("m-now").textContent = mA(r.ibus);
      $("m-meteravg").textContent = r.meterAvg === null ? "–" : mA(r.meterAvg);
      $("m-vbus").textContent = `${r.vbus.toFixed(3)} V`;
      $("m-readings").textContent = `${r.samples.toLocaleString()} (${Math.round(r.rate)}/s)`;
      $("m-elapsed").textContent = fmtElapsed(r.elapsed);
      $("m-mean").textContent = mAUnit(r.mean);
      $("m-std").textContent = mAUnit(r.std);
      $("m-min").textContent = mAUnit(r.min);
      $("m-max").textContent = mAUnit(r.max);
      $("m-worst").textContent =
        r.worst === null ? `waiting for ${win}` : `${mAUnit(r.worst)} at ${r.worstAt.toFixed(1)} s`;
      $("m-worst-meter").textContent =
        r.meterAvg === null
          ? "not reported by the TC66"
          : r.worstMeter === null
            ? "waiting"
            : mAUnit(r.worstMeter);
    }
    renderVerdict(r, win);
    renderTrace();
    render();
  }

  function renderVerdict(r, win) {
    const box = $("m-verdict");
    const text = $("m-verdict-text");
    const lim = mAUnit(limitUa);
    let kind = "pending";
    if ($("m-limit").getAttribute("aria-invalid") === "true") {
      text.textContent = "Enter a limit such as 2.5mA or 2500uA.";
    } else if (!r) {
      text.textContent = `Start measuring to compare the ${win} average with ${lim}.`;
    } else {
      kind = meter.verdict(limitUa);
      const worst = Math.max(r.worst ?? 0, r.worstMeter ?? 0);
      if (kind === "pending") {
        text.textContent = `Waiting for a full ${win} window…`;
      } else if (kind === "pass") {
        text.textContent = `Below the limit: worst ${win} average ${mAUnit(worst)}, limit ${lim}.`;
      } else {
        text.textContent = `Over the limit: worst ${win} average ${mAUnit(worst)}, limit ${lim}.`;
      }
    }
    box.className = `verdict ${kind}`;
    $("m-verdict-icon").textContent = kind === "pass" ? "✓" : kind === "fail" ? "✕" : "…";
    $("m-verdict-label").textContent = kind === "pass" ? "Pass" : kind === "fail" ? "Fail" : "Pending";
  }

  // --- Trace chart ----------------------------------------------------------

  const svg = $("m-chart");
  const NS = "http://www.w3.org/2000/svg";
  const el = (name, attrs, parent = svg) => {
    const e = document.createElementNS(NS, name);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    parent.append(e);
    return e;
  };
  const gGrid = el("g", { class: "grid" });
  const band = el("path", { class: "band" });
  const avgLine = el("path", { class: "avg" });
  const limitLine = el("line", { class: "limit" });
  const limitText = el("text", { class: "limit-label", "text-anchor": "end" });
  const cross = el("line", { class: "cross" });
  const dot = el("circle", { class: "cross-dot", r: 4 });
  const tip = $("m-tip");
  const PAD = { l: 58, r: 12, t: 12, b: 26 };

  /** About `n` round tick values covering [lo, hi], and their step. */
  function ticks(lo, hi, n) {
    const raw = (hi - lo) / n;
    const mag = 10 ** Math.floor(Math.log10(raw));
    const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) ?? raw;
    const out = [];
    for (let k = Math.ceil(lo / step); k * step <= hi + step / 1e6; k++) out.push(k * step);
    return { values: out, step };
  }

  let geom = null;

  function renderTrace() {
    const w = svg.clientWidth || 600;
    const h = svg.clientHeight || 220;
    svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
    const tEnd = trace.length ? Math.max(trace[trace.length - 1].t, TRACE_SPAN_S) : TRACE_SPAN_S;
    const tStart = tEnd - TRACE_SPAN_S;
    const pts = trace.filter((p) => p.t >= tStart);
    $("m-trace-empty").hidden = pts.length > 0;

    // Power can flow either way through the meter; plot the limit on the
    // side the current is on.
    const sign = last && last.mean < 0 ? -1 : 1;
    let lo = 0;
    let hi = 0;
    for (const p of pts) {
      lo = Math.min(lo, p.i);
      hi = Math.max(hi, p.i);
    }
    lo = Math.min(lo, sign * limitUa);
    hi = Math.max(hi, sign * limitUa);
    const span = hi - lo || 1000;
    lo -= span * 0.06 * (lo < 0);
    hi += span * 0.08;

    const x = (t) => PAD.l + ((t - tStart) / TRACE_SPAN_S) * (w - PAD.l - PAD.r);
    const y = (ua) => PAD.t + (1 - (ua - lo) / (hi - lo)) * (h - PAD.t - PAD.b);
    geom = { x, y, pts };

    gGrid.replaceChildren();
    const yt = ticks(lo, hi, 4);
    // Just enough decimals (of mA) to tell the ticks apart.
    const digits = Math.max(0, Math.ceil(-Math.log10(yt.step / 1000) - 1e-9));
    for (const v of yt.values) {
      el("line", { x1: PAD.l, x2: w - PAD.r, y1: y(v), y2: y(v), class: v === 0 ? "zero" : "" }, gGrid);
      el("text", { x: PAD.l - 8, y: y(v) + 4, "text-anchor": "end" }, gGrid).textContent =
        (v / 1000).toFixed(digits);
    }
    for (let t = Math.ceil(tStart / 5) * 5; t <= tEnd; t += 5) {
      if (t < 0) continue;
      el("text", { x: x(t), y: h - 8, "text-anchor": "middle" }, gGrid).textContent = `${t} s`;
    }

    // Readings as a min–max band per 2 px column, the window average as a line.
    const cols = new Map();
    for (const p of pts) {
      const c = Math.round(x(p.t) / 2);
      const b = cols.get(c);
      if (b) {
        b.lo = Math.min(b.lo, p.i);
        b.hi = Math.max(b.hi, p.i);
      } else {
        cols.set(c, { lo: p.i, hi: p.i });
      }
    }
    const keys = [...cols.keys()];
    if (keys.length) {
      const top = keys.map((c) => `${c * 2},${y(cols.get(c).hi) - 0.75}`);
      const bot = keys.reverse().map((c) => `${c * 2},${y(cols.get(c).lo) + 0.75}`);
      band.setAttribute("d", `M${top.join("L")}L${bot.join("L")}Z`);
    } else {
      band.setAttribute("d", "");
    }
    const avg = pts.filter((p) => p.w !== null);
    avgLine.setAttribute("d", avg.length ? "M" + avg.map((p) => `${x(p.t)},${y(p.w)}`).join("L") : "");

    const ly = y(sign * limitUa);
    for (const [k, v] of Object.entries({ x1: PAD.l, x2: w - PAD.r, y1: ly, y2: ly })) limitLine.setAttribute(k, v);
    limitText.setAttribute("x", w - PAD.r - 4);
    limitText.setAttribute("y", ly - 6);
    limitText.textContent = `limit ${mAUnit(sign * limitUa)}`;
    drawHover();
  }

  function drawHover() {
    const show = hoverX !== null && geom !== null && geom.pts.length > 0;
    cross.style.display = dot.style.display = show ? "" : "none";
    tip.hidden = !show;
    if (!show) return;
    const { x, y, pts } = geom;
    let best = pts[0];
    for (const p of pts) if (Math.abs(x(p.t) - hoverX) < Math.abs(x(best.t) - hoverX)) best = p;
    const px = x(best.t);
    const h = svg.clientHeight || 220;
    for (const [k, v] of Object.entries({ x1: px, x2: px, y1: PAD.t, y2: h - PAD.b })) cross.setAttribute(k, v);
    const dy = best.w ?? best.i;
    dot.setAttribute("cx", px);
    dot.setAttribute("cy", y(dy));
    $("m-tip-t").textContent = `${best.t.toFixed(2)} s`;
    $("m-tip-i").textContent = mAUnit(best.i);
    $("m-tip-w").textContent = best.w === null ? "filling" : mAUnit(best.w);
    const w = svg.clientWidth;
    tip.style.left = `${Math.min(px + 12, w - tip.offsetWidth - 4)}px`;
    if (px + 12 + tip.offsetWidth > w) tip.style.left = `${px - tip.offsetWidth - 12}px`;
  }

  svg.addEventListener("pointermove", (e) => {
    const r = svg.getBoundingClientRect();
    hoverX = e.clientX - r.left;
    drawHover();
  });
  svg.addEventListener("pointerleave", () => {
    hoverX = null;
    drawHover();
  });
  window.addEventListener("resize", renderTrace);

  // --- TC66 (Web Serial) ----------------------------------------------------

  /** Use `port` as the TC66. `chosen`: picked by the user, so prefer it. */
  function adoptTc66(port, chosen) {
    if (busy() && device === tc66) return;
    if (!tc66 || tc66.port !== port) tc66 = new Tc66(port, TC66);
    if (chosen) preferTc66 = true;
    host.showError("");
    render();
  }

  async function chooseTc66() {
    let port;
    try {
      port = await navigator.serial.requestPort({
        filters: [{ usbVendorId: TC66.vid, usbProductId: TC66.pid }],
      });
    } catch (e) {
      if (e?.name !== "NotFoundError") host.showError(host.errorText(e)); // NotFoundError: cancelled
      return;
    }
    adoptTc66(port, true);
  }

  async function chooseKm003c() {
    preferTc66 = false;
    render();
    await host.choose();
  }

  if (hasSerial) {
    navigator.serial.addEventListener("connect", (e) => {
      if (!tc66 && Tc66.matches(e.target, TC66)) adoptTc66(e.target, false);
    });
    navigator.serial.addEventListener("disconnect", async (e) => {
      if (!tc66 || e.target !== tc66.port) return;
      if (device === tc66) await stop("The TC66 was unplugged. Its figures up to that point are kept.");
      tc66 = null;
      render();
    });
    // Reconnect to a TC66 this site was already allowed to use.
    navigator.serial
      .getPorts()
      .then((ports) => {
        const port = ports.find((p) => Tc66.matches(p, TC66));
        if (port && !tc66) adoptTc66(port, false);
      })
      .catch(() => {});
  }

  // --- Wiring -------------------------------------------------------------

  $("m-choose").addEventListener("click", chooseKm003c);
  $("m-choose-tc66").addEventListener("click", chooseTc66);
  $("m-start").addEventListener("click", start);
  $("m-stop").addEventListener("click", () => stop());
  $("m-zero").addEventListener("click", zero);
  $("m-clear-zero").addEventListener("click", () => setOffset(0));
  $("m-reset").addEventListener("click", resetStats);
  $("m-limit").addEventListener("input", readLimit);
  $("m-window-s").addEventListener("change", () => {
    readWindow();
    update();
  });
  $("m-csv").addEventListener("click", () =>
    host.download(`meter-${host.stamp()}.csv`, meter.csv(), "text/csv"),
  );

  readLimit();
  update();

  return {
    get busy() {
      return busy();
    },
    /** Whether the meter is measuring with the selected (KM003C) analyzer. */
    get holdsAnalyzer() {
      return busy() && device !== null && device === host.meter();
    },
    render,
    /** Re-draw once the view is visible (the trace needs its size). */
    shown: update,
    stop,
  };
}
