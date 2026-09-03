/* caddy-waf dashboard — behaviour only, decoupled from markup and styling.
 *
 * Modules (no build step, no dependencies):
 *   config  — runtime config, read from the page (not hard-coded)
 *   store   — client state: counter history + derived per-minute rates
 *   fmt     — pure formatting helpers
 *   charts  — hand-rolled SVG sparklines and CSS bars
 *   view    — DOM rendering, one function per section
 *   api     — the metrics source (swappable; the demo replaces just this)
 *   app     — wiring: poll loop, controls, lifecycle
 * The data source (api) is isolated so the same view renders live metrics or,
 * in the docs demo, a generated sample — nothing else changes.
 */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);

  const config = {
    metricsPath: (document.querySelector('meta[name="waf-metrics-path"]') || {}).content || "",
    histCap: 180,
  };

  const store = {
    hist: [], lastUptime: null,
    push(m) {
      if (this.lastUptime != null && m.uptime_seconds != null && m.uptime_seconds < this.lastUptime) this.hist = [];
      this.lastUptime = m.uptime_seconds;
      this.hist.push({ t: m.server_time_ms || Date.now(), total: m.total_requests || 0, blocked: m.blocked_requests || 0, allowed: m.allowed_requests || 0 });
      if (this.hist.length > config.histCap) this.hist.shift();
    },
    ratePerMin(key) {
      const h = this.hist; if (h.length < 2) return null;
      const dv = h[h.length - 1][key] - h[0][key], dt = (h[h.length - 1].t - h[0].t) / 1000;
      return dt > 0 && dv >= 0 ? dv / dt * 60 : null;
    },
    series(key) {
      const h = this.hist, out = [];
      for (let i = 1; i < h.length; i++) { const dv = h[i][key] - h[i - 1][key], dt = (h[i].t - h[i - 1].t) / 1000; out.push(dt > 0 && dv >= 0 ? dv / dt : 0); }
      return out;
    },
  };

  const fmt = {
    num(n) {
      if (n == null) return "—"; n = Number(n);
      if (n >= 1e9) return (n / 1e9).toFixed(2) + "B";
      if (n >= 1e6) return (n / 1e6).toFixed(2) + "M";
      if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
      return n.toLocaleString();
    },
    esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); },
    flag(cc) {
      if (!cc || cc.length !== 2) return ""; const A = 0x1F1E6, up = cc.toUpperCase();
      return String.fromCodePoint(A + up.charCodeAt(0) - 65) + String.fromCodePoint(A + up.charCodeAt(1) - 65);
    },
    uptime(u) { if (u == null) return "uptime —"; const d = Math.floor(u / 86400), h = Math.floor(u % 86400 / 3600), mi = Math.floor(u % 3600 / 60); return "uptime " + (d ? d + "d " : "") + (h || d ? h + "h " : "") + mi + "m"; },
  };

  const charts = {
    spark(id, key) {
      const svg = $(id), vals = store.series(key); svg.innerHTML = "";
      if (vals.length < 2) return;
      const W = 100, H = 34, pad = 2, n = vals.length, max = Math.max(1, ...vals);
      let d = "";
      for (let i = 0; i < n; i++) { const x = pad + (W - 2 * pad) * (n === 1 ? 0 : i / (n - 1)); const y = H - pad - (H - 2 * pad) * (vals[i] / max); d += (i ? "L" : "M") + x.toFixed(1) + "," + y.toFixed(1) + " "; }
      const col = getComputedStyle(document.documentElement).getPropertyValue(id.includes("blocked") ? "--bad" : id.includes("allowed") ? "--ok" : "--accent").trim();
      svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
      svg.innerHTML = `<path d="${d}L${(W - pad).toFixed(1)},${H - pad} L${pad},${H - pad} Z" fill="${col}" opacity="0.12"/><path d="${d}" fill="none" stroke="${col}" stroke-width="1.6" vector-effect="non-scaling-stroke"/>`;
    },
    bars(id, items, { label, value, cls } = {}) {
      const el = $(id);
      if (!items || !items.length) { el.innerHTML = '<div class="empty">no data yet</div>'; return; }
      const max = Math.max(1, ...items.map(value));
      el.innerHTML = items.map((it) => {
        const v = value(it), w = Math.max(2, (v / max) * 100), c = cls ? cls(it) : "";
        return `<div class="row"><span class="lbl" title="${fmt.esc(label(it))}">${fmt.esc(label(it))}</span>` +
          `<span class="track"><span class="fill ${c}" style="width:${w}%"></span></span>` +
          `<span class="val">${fmt.num(v)}</span></div>`;
      }).join("");
    },
  };

  const view = {
    header(m) {
      $("ver").textContent = m.version || "—";
      $("uptime").textContent = fmt.uptime(m.uptime_seconds);
      $("f-schema").textContent = "schema " + (m.schema_version != null ? m.schema_version : "—");
      $("f-endpoint").textContent = config.metricsPath ? "source " + config.metricsPath : "";
    },
    kpis(m) {
      const total = m.total_requests || 0, blocked = m.blocked_requests || 0;
      $("k-total").textContent = fmt.num(total);
      $("k-blocked").textContent = fmt.num(blocked);
      $("k-allowed").textContent = fmt.num(m.allowed_requests || 0);
      $("k-ratio").textContent = total ? (blocked / total * 100).toFixed(blocked / total < 0.1 ? 1 : 0) + "%" : "0%";
      const rt = store.ratePerMin("total"), rb = store.ratePerMin("blocked");
      $("r-total").textContent = rt == null ? "—" : Math.round(rt);
      $("r-blocked").textContent = rb == null ? "—" : Math.round(rb);
      $("s-allowed").textContent = total ? fmt.num(total - blocked) + " passed" : "—";
      charts.spark("sp-total", "total"); charts.spark("sp-blocked", "blocked"); charts.spark("sp-allowed", "allowed");
    },
    breakdowns(m) {
      const reasons = Object.entries(m.blocked_by_reason || {}).map(([k, v]) => ({ k, v })).filter((x) => x.v > 0).sort((a, b) => b.v - a.v);
      charts.bars("reasons", reasons, { label: (x) => x.k, value: (x) => x.v, cls: (x) => x.k });
      const ph = Object.entries(m.rule_hits_by_phase || {}).map(([k, v]) => ({ k: "phase " + k, v })).sort((a, b) => b.v - a.v);
      charts.bars("phases", ph, { label: (x) => x.k, value: (x) => x.v });
      charts.bars("rules", (m.top_rules || []).slice(0, 12), { label: (x) => x.id, value: (x) => x.hits });
      charts.bars("ips", (((m.top_ips || {}).items) || []).slice(0, 12), { label: (x) => x.ip, value: (x) => x.blocked, cls: () => "ip_blacklist" });
      charts.bars("countries", (m.by_country || []).slice(0, 16), { label: (x) => fmt.flag(x.country) + " " + x.country, value: (x) => x.blocked, cls: () => "country" });
    },
    recent(m) {
      const items = (((m.recent || {}).items) || []), tb = $("recent");
      if (!items.length) { tb.innerHTML = '<tr><td colspan="8" class="empty">no blocks recorded yet</td></tr>'; return; }
      tb.innerHTML = items.map((it) => {
        const t = new Date(it.ts_ms || 0).toLocaleTimeString();
        const src = `<span class="ip">${fmt.esc(it.ip)}</span>` + (it.country ? ` <span title="${fmt.esc(it.country)}">${fmt.flag(it.country)}</span>` : "");
        return `<tr><td class="mono">${fmt.esc(t)}</td><td>${src}</td><td class="mono">${fmt.esc(it.method)}</td>` +
          `<td class="path" title="${fmt.esc(it.path)}">${fmt.esc(it.path)}</td>` +
          `<td><span class="pill ${fmt.esc(it.reason)}">${fmt.esc(it.reason)}</span></td>` +
          `<td class="mono">${fmt.esc(it.rule_id || "")}</td><td class="val">${fmt.esc(it.score)}</td>` +
          `<td class="status">${fmt.esc(it.status)}</td></tr>`;
      }).join("");
    },
    render(m) { this.header(m); this.kpis(m); this.breakdowns(m); this.recent(m); },
    live(cls, text) { const el = $("live"); el.className = "live " + cls; $("livetext").textContent = text; },
    banner(msg) { const b = $("banner"); if (!msg) { b.className = "banner"; return; } b.textContent = msg; b.className = "banner show"; },
  };

  // The only server-coupled module. Returns a metrics object or throws.
  const api = {
    async fetchMetrics() {
      const res = await fetch(config.metricsPath, { headers: { Accept: "application/json" }, cache: "no-store" });
      if (!res.ok) throw new Error("HTTP " + res.status);
      return res.json();
    },
  };

  const app = {
    timer: null, interval: 5000, paused: false,
    async tick() {
      if (!config.metricsPath) { view.live("err", "no endpoint"); view.banner("Metrics endpoint is not configured. Add `metrics_endpoint /waf_metrics` to the WAF block."); return; }
      try {
        const m = await (window.__wafMetricsSource || api.fetchMetrics)();
        store.push(m); view.render(m); view.banner(""); view.live("on", "live");
      } catch (e) { view.live("err", "disconnected"); view.banner("Cannot reach " + config.metricsPath + " — " + e.message + ". Showing last data."); }
    },
    schedule() { clearInterval(this.timer); if (!this.paused) this.timer = setInterval(() => this.tick(), this.interval); },
    start() {
      $("interval").addEventListener("change", (e) => { this.interval = Number(e.target.value) * 1000; this.schedule(); });
      $("pause").addEventListener("click", (e) => {
        this.paused = !this.paused; e.target.textContent = this.paused ? "Resume" : "Pause";
        if (this.paused) { clearInterval(this.timer); view.live("", "paused"); } else { this.tick(); this.schedule(); }
      });
      this.tick(); this.schedule();
    },
  };

  window.wafDashboard = { store, view, app }; // exposed for the demo to drive
  app.start();
})();
