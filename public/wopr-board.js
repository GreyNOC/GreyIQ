/* GreyNOC threat board — a character-grid renderer drawn on a canvas.
 *
 * One module behind every surface that shows the board: the boot splash, the hunt cockpit, and the
 * landing page. Its terminal twin is scripts/fx_gallery.py (and, for live hunts, backend/gn_fx.py);
 * the two share a grid (78x24), a glyph set, and xterm-256 colour codes, so a colour or a glyph is
 * decided once and both follow it.
 *
 * Two modes, one renderer:
 *
 *   demo()   a scripted sequence, for a surface with no hunt behind it. Loops.
 *   live     track()/launch()/resolve()/log(), driven by whatever the engine is actually doing.
 *            Nothing animates that was not pushed in: an arc exists because an asset is being
 *            verified, and it lands because a finding did.
 *
 * DEFCON is the worst CONFIRMED severity (critical 1 … nothing 5), never a count of arcs — on a
 * live board a number that only counts motion is theatre, and this one has to survive someone
 * asking what it means.
 *
 * Every arc is a pure function of (now - its own launch), so a dropped frame costs nothing, the
 * board can be seeked for a still, and nothing accumulates drift over a hunt that runs for hours.
 */
(function (global) {
  "use strict";

  var COLS = 78, ROWS = 24;
  var MAP_W = 72, MAP_H = 17;
  var FLIGHT = 1.7;          // seconds an arc is in the air
  var ERODE = 0.9;           // seconds for a spent trail to drain into its target

  /* --- the world ------------------------------------------------------------------------------
   * Inclusive land spans on a 72x17 equirectangular grid: a continent is a number to nudge rather
   * than a column to count. */
  var LAND_SPANS = {
    0: [[25, 30], [46, 62]],
    1: [[7, 12], [14, 25], [26, 31], [35, 40], [41, 65]],
    2: [[8, 24], [27, 30], [34, 34], [36, 39], [40, 66]],
    3: [[9, 23], [32, 40], [41, 67]],
    4: [[10, 22], [32, 39], [41, 66], [67, 68]],
    5: [[11, 21], [31, 34], [37, 45], [52, 64], [66, 67]],
    6: [[12, 19], [30, 44], [47, 52], [54, 63]],
    7: [[14, 18], [30, 44], [48, 52], [55, 60]],
    8: [[16, 19], [30, 41], [49, 52], [56, 61]],
    9: [[19, 23], [29, 42], [57, 62]],
    10: [[20, 26], [31, 41], [58, 64]],
    11: [[20, 27], [32, 40], [59, 63]],
    12: [[20, 26], [32, 39], [61, 68]],
    13: [[21, 26], [33, 38], [60, 69]],
    14: [[21, 25], [34, 37], [62, 68]],
    15: [[22, 24], [70, 71]],
    16: [[22, 23]]
  };

  var LAND = (function () {
    var rows = [];
    for (var y = 0; y < MAP_H; y++) {
      var cells = new Array(MAP_W);
      for (var i = 0; i < MAP_W; i++) cells[i] = " ";
      var spans = LAND_SPANS[y] || [];
      for (var s = 0; s < spans.length; s++) {
        for (var x = Math.max(0, spans[s][0]); x <= Math.min(MAP_W - 1, spans[s][1]); x++) {
          cells[x] = "#";
        }
      }
      rows.push(cells.join(""));
    }
    return rows;
  })();

  // Sites an asset can be placed on: hand-picked, spread across the continents, none of them on
  // top of the node. Hashing over every land cell instead looks principled and isn't — the
  // northern landmass holds most of the cells, so three assets in a row land in Siberia on top of
  // each other. A curated list is what makes an unseen set of hostnames lay out like a map.
  var SITES = [
    [14, 3], [18, 5], [13, 7], [22, 10], [24, 12], [23, 14],
    [28, 1], [33, 2], [35, 4], [38, 3], [41, 6], [33, 8],
    [36, 10], [35, 12], [45, 2], [50, 3], [50, 7], [55, 5],
    [57, 8], [58, 11], [62, 4], [65, 6], [64, 12], [67, 13], [70, 15]
  ];

  var ORIGIN = [12, 4];

  /* --- glyphs and colour ---------------------------------------------------------------------- */
  var G = {
    edges: ["│", "│"],
    corners: ["┌", "┐", "└", "┘"],
    hbar: "─",
    land: "▒",
    arc: ["●", "▪", "·"],
    head: "◉",
    blip: "◆",
    ring: "○",
    cursor: "█"
  };

  var SEV = {
    critical: "1;38;5;196",
    high: "38;5;202",
    medium: "38;5;214",
    low: "38;5;228",
    info: "38;5;109"
  };
  var SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  var DEFCON_FOR = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };

  var CUBE = [0, 95, 135, 175, 215, 255];
  function xterm(index) {
    if (index >= 232) { var v = 8 + 10 * (index - 232); return hex(v, v, v); }
    var n = index - 16;
    return hex(CUBE[Math.floor(n / 36)], CUBE[Math.floor(n / 6) % 6], CUBE[n % 6]);
  }
  function hex(r, g, b) {
    return "#" + [r, g, b].map(function (v) { return v.toString(16).padStart(2, "0"); }).join("");
  }

  var SGR = new Map();
  function sgr(code) {
    var hit = SGR.get(code);
    if (hit) return hit;
    hit = { fg: "#9fb0b8", bold: false, rev: false };
    var parts = code.split(";");
    for (var i = 0; i < parts.length; i++) {
      if (parts[i] === "1") hit.bold = true;
      else if (parts[i] === "7") hit.rev = true;
      else if (parts[i] === "38" && parts[i + 1] === "5") { hit.fg = xterm(+parts[i + 2]); i += 2; }
    }
    SGR.set(code, hit);
    return hit;
  }

  /* --- helpers ---------------------------------------------------------------------------------- */
  function clamp(v, lo, hi) {
    lo = lo === undefined ? 0 : lo; hi = hi === undefined ? 1 : hi;
    return v < lo ? lo : v > hi ? hi : v;
  }
  function easeOut(x) { x = clamp(x); return 1 - (1 - x) * (1 - x); }
  function typed(s, elapsed, cps) { return elapsed <= 0 ? "" : s.slice(0, Math.floor(elapsed * cps)); }
  function two(n) { return String(n).padStart(2, "0"); }

  // A name always lands on the same patch of the world, so an operator learns where their assets
  // live and a redraw never teleports one.
  function hashName(name) {
    var acc = 0x9e3779b9;
    for (var i = 0; i < name.length; i++) {
      acc = (Math.imul(acc, 1664525) + Math.imul(name.charCodeAt(i), 1013904223) + 0x9e37) >>> 0;
      acc = (acc ^ (acc >>> 15)) >>> 0;
    }
    return acc;
  }

  function bezier(p0, p1, p2, s) {
    var inv = 1 - s;
    return [inv * inv * p0[0] + 2 * inv * s * p1[0] + s * s * p2[0],
      inv * inv * p0[1] + 2 * inv * s * p1[1] + s * s * p2[1]];
  }

  /* --- the grid ---------------------------------------------------------------------------------- */
  function Grid(cols, rows) {
    this.cols = cols; this.rows = rows;
    this.ch = new Array(cols * rows).fill(" ");
    this.co = new Array(cols * rows).fill(null);
  }
  Grid.prototype.clear = function () { this.ch.fill(" "); this.co.fill(null); };
  Grid.prototype.put = function (x, y, ch, color) {
    x = Math.round(x); y = Math.round(y);
    if (x < 0 || y < 0 || x >= this.cols || y >= this.rows || !ch) return;
    var i = y * this.cols + x;
    this.ch[i] = ch[0];
    this.co[i] = color || null;
  };
  Grid.prototype.text = function (x, y, s, color) {
    for (var i = 0; i < s.length; i++) this.put(x + i, y, s[i], color);
  };

  /* --- the board ----------------------------------------------------------------------------------
   * options: { scope, title, footer, cols, rows, maxScale, onIdle }
   */
  function WoprBoard(canvas, options) {
    options = options || {};
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d", { alpha: false });
    this.cols = options.cols || COLS;
    this.rows = options.rows || ROWS;
    this.grid = new Grid(this.cols, this.rows);
    this.scope = options.scope || "";
    this.title = options.title || "GREYNOC // WOPR-IQ";
    this.footer = options.footer || "AUTHORIZED SCOPE ONLY  ::  READ-ONLY PROOF";
    this.maxScale = options.maxScale || 2;
    this.onIdle = options.onIdle || null;

    this.assets = [];          // {name, x, y, severity, label, launchAt, resolveAt}
    this.byName = new Map();
    this.taken = new Set();    // site slots in use, so two assets never share a cell
    this.lines = [];           // {text, color, at}
    this.running = false;
    this.startedAt = 0;
    this.demoLoop = false;
    this.clockBase = 2 * 3600 + 17 * 60 + 9;

    this._frame = this._frame.bind(this);
    this.resize();
  }

  WoprBoard.prototype.now = function () { return (performance.now() - this.startedAt) / 1000; };

  WoprBoard.prototype.resize = function () {
    var ctx = this.ctx;
    var probe = 18;
    ctx.font = probe + 'px "Noto Sans Mono", ui-monospace, "Cascadia Mono", Consolas, monospace';
    this.fontSize = probe;
    this.cw = ctx.measureText("M").width || probe * 0.6;
    this.chh = Math.round(probe * 1.26);
    var w = Math.ceil(this.cw * this.cols), h = this.chh * this.rows;
    this.scale = Math.min(this.maxScale, global.devicePixelRatio || 1);
    this.canvas.width = Math.ceil(w * this.scale);
    this.canvas.height = Math.ceil(h * this.scale);
    this.canvas.style.aspectRatio = w + " / " + h;
    ctx.setTransform(this.scale, 0, 0, this.scale, 0, 0);
    ctx.textBaseline = "top";
  };

  /* --- live feed ---------------------------------------------------------------------------------- */

  /** Put assets on the map. Accepts names, or {name, severity} for findings already known. */
  WoprBoard.prototype.track = function (assets) {
    for (var i = 0; i < assets.length; i++) {
      var raw = assets[i];
      var name = typeof raw === "string" ? raw : raw.name;
      if (!name || this.byName.has(name)) continue;
      // Linear probing off the name's own hash: the same host always lands on the same site, and a
      // second host never lands on top of the first.
      var slot = hashName(name) % SITES.length;
      for (var probe = 0; probe < SITES.length && this.taken.has(slot); probe++) {
        slot = (slot + 1) % SITES.length;
      }
      var crowded = this.taken.has(slot);   // more assets than sites: nudge rather than stack
      this.taken.add(slot);
      var spot = SITES[slot];
      var hash = hashName(name);
      var asset = {
        name: name,
        x: spot[0] + (crowded ? (hash % 3) - 1 : 0),
        y: spot[1] + (crowded ? ((hash >>> 3) % 3) - 1 : 0),
        severity: (raw && raw.severity) || null,
        label: (raw && raw.label) || "",
        launchAt: null, resolveAt: null
      };
      this.assets.push(asset);
      this.byName.set(name, asset);
    }
    return this;
  };

  /** An asset has gone into active verification: send the arc. */
  WoprBoard.prototype.launch = function (name) {
    this.track([name]);
    var asset = this.byName.get(name);
    if (asset && asset.launchAt === null) asset.launchAt = this.now();
    return this;
  };

  /** A finding landed. The arc impacts and the marker starts blinking in its severity. */
  WoprBoard.prototype.resolve = function (name, severity, label) {
    this.track([name]);
    var asset = this.byName.get(name);
    if (!asset) return this;
    var t = this.now();
    if (asset.launchAt === null) asset.launchAt = t;              // resolved without a prior launch
    asset.severity = SEV[severity] ? severity : "info";
    asset.label = label || asset.label;
    asset.resolveAt = Math.max(t, asset.launchAt + FLIGHT);
    return this;
  };

  /** One teletype line. Typed out at the bottom of the board; the previous one greys above it. */
  WoprBoard.prototype.log = function (text, color) {
    if (!text) return this;
    this.lines.push({ text: String(text), color: color || "38;5;214", at: this.now() });
    if (this.lines.length > 24) this.lines.shift();
    return this;
  };

  WoprBoard.prototype.reset = function () {
    this.assets = [];
    this.byName = new Map();
    this.taken = new Set();
    this.lines = [];
    this.startedAt = performance.now();
    return this;
  };

  /* --- demo --------------------------------------------------------------------------------------
   * Ordered so DEFCON descends honestly: each finding is worse than the one before it. */
  var DEMO = [
    ["cdn.acme-corp.io", "info", "CACHE KEY NORMALISATION", 1.2],
    ["legacy.acme-corp.io", "low", "STACK TRACE DISCLOSURE", 2.8],
    ["vpn.acme-corp.io", "medium", "IKE FINGERPRINT LEAK", 4.4],
    ["api.acme-corp.io", "high", "SSRF -> CLOUD METADATA", 6.0],
    ["sso.acme-corp.io", "critical", "AUTH BYPASS -> ADMIN", 7.6]
  ];
  var DEMO_SPAN = 7.6 + FLIGHT + 3.4;

  WoprBoard.prototype.demo = function (options) {
    options = options || {};
    this.demoLoop = options.loop !== false;
    this.scope = this.scope || "acme-corp.io";
    this._arm();
    return this.start();
  };

  WoprBoard.prototype._arm = function () {
    this.reset();
    this.log("> WOPR-IQ ONLINE  ::  SCOPE " + (this.scope || "local") +
      "  ::  AUTHORIZATION ON FILE", "38;5;214");
    var self = this;
    this._timers = (this._timers || []).filter(function (id) { clearTimeout(id); return false; });
    DEMO.forEach(function (row) {
      var name = row[0], severity = row[1], label = row[2], at = row[3];
      self._timers.push(setTimeout(function () {
        self.launch(name);
        self.log("> PLOTTING TRAJECTORY  " + name, "38;5;214");
      }, at * 1000));
      self._timers.push(setTimeout(function () {
        self.resolve(name, severity, label);
        self.log("> " + label + "  ::  CONFIRMED  ::  " + severity.toUpperCase(),
          severity === "critical" || severity === "high" ? "1;38;5;196" : "38;5;214");
      }, (at + FLIGHT) * 1000));
    });
    this._timers.push(setTimeout(function () {
      self.log("> 5 OF 5 ARCS RESOLVED  ::  PROOF CHAIN COMPLETE  ::  NO FABRICATION",
        "1;38;5;196");
      if (self.onIdle) self.onIdle();
    }, (7.6 + FLIGHT + 1.0) * 1000));
    if (this.demoLoop) {
      this._timers.push(setTimeout(function () { self._arm(); }, DEMO_SPAN * 1000));
    }
  };

  /* --- loop ---------------------------------------------------------------------------------------- */
  WoprBoard.prototype.start = function () {
    if (this.running) return this;
    this.running = true;
    if (!this.startedAt) this.startedAt = performance.now();
    requestAnimationFrame(this._frame);
    return this;
  };

  WoprBoard.prototype.stop = function () { this.running = false; return this; };

  WoprBoard.prototype.destroy = function () {
    this.stop();
    (this._timers || []).forEach(clearTimeout);
    this._timers = [];
  };

  WoprBoard.prototype._frame = function () {
    if (!this.running) return;
    this.paint(this.now());
    requestAnimationFrame(this._frame);
  };

  /* --- draw ------------------------------------------------------------------------------------------ */
  WoprBoard.prototype.paint = function (t) {
    var g = this.grid, cols = this.cols, rows = this.rows;
    g.clear();

    var chrome = "38;5;178", dim = "38;5;58";
    var boxW = Math.min(cols, MAP_W + 2);
    var boxX = Math.max(0, (cols - boxW) >> 1);
    var mapH = Math.min(MAP_H, Math.max(6, rows - 6));
    var boxH = mapH + 5;
    var boxY = Math.max(0, (rows - boxH) >> 1);
    this._frameBox(g, boxX, boxY, boxW, boxH, chrome);

    var resolved = this.assets.filter(function (a) { return a.resolveAt !== null && t >= a.resolveAt; });
    var counts = {};
    var defcon = 5;
    for (var i = 0; i < resolved.length; i++) {
      var sev = resolved[i].severity || "info";
      counts[sev] = (counts[sev] || 0) + 1;
      defcon = Math.min(defcon, DEFCON_FOR[sev] || 5);
    }

    // header
    g.text(boxX + 2, boxY, " " + this.title + " ", "1;38;5;214");
    var label = " DEFCON " + defcon + " ";
    g.text(boxX + boxW - 13 - label.length, boxY, label,
      defcon <= 2 ? "1;7;38;5;196" : "1;38;5;214");
    var secs = Math.floor(this.clockBase + t);
    g.text(boxX + boxW - 12, boxY,
      " " + two(Math.floor(secs / 3600) % 24) + ":" + two(Math.floor(secs / 60) % 60) + ":" +
      two(secs % 60) + " ", chrome);

    // map, with a CRT band walking down it
    var mx = boxX + 1, my = boxY + 1;
    var sweep = Math.floor((t * 7.0) % (mapH + 6)) - 3;
    for (var y = 0; y < mapH; y++) {
      var lit = y === sweep;
      var row = LAND[y].slice(0, boxW - 2);
      for (var x = 0; x < row.length; x++) {
        if (row[x] === "#") g.put(mx + x, my + y, G.land, lit ? "38;5;108" : "38;5;23");
        else if (lit) g.put(mx + x, my + y, G.hbar, "38;5;236");
      }
    }

    // Everything below plots in MAP coordinates, clipped to the map: an impact ring near the right
    // limb reaches seven columns past its target, which is enough to punch through the frame.
    function plot(px, py, glyph, color) {
      var rx = Math.round(px), ry = Math.round(py);
      if (rx >= 0 && rx <= boxW - 3 && ry >= 0 && ry < mapH) g.put(mx + rx, my + ry, glyph, color);
    }
    function plotText(px, py, s, color) {
      for (var k = 0; k < s.length; k++) plot(px + k, py, s[k], color);
    }

    for (var a = 0; a < this.assets.length; a++) {
      var asset = this.assets[a];
      if (asset.launchAt === null) { plot(asset.x, asset.y, "+", dim); continue; }
      var progress = clamp((t - asset.launchAt) / FLIGHT);
      var paint = SEV[asset.severity] || "38;5;214";
      if (progress <= 0) { plot(asset.x, asset.y, "+", dim); continue; }

      var landed = asset.resolveAt !== null && t >= asset.resolveAt;
      var lift = 3.0 + Math.abs(asset.x - ORIGIN[0]) / 11.0;
      var control = [(ORIGIN[0] + asset.x) / 2.0, Math.min(ORIGIN[1], asset.y) - lift];
      var erode = landed ? clamp((t - asset.resolveAt) / ERODE) : 0;
      var steps = 130;
      for (var step = 0; step <= Math.floor(progress * steps); step++) {
        var s = step / steps;
        if (s < erode) continue;
        var pt = bezier(ORIGIN, control, [asset.x, asset.y], s);
        var age = progress - s;
        var glyph, color;
        if (age < 0.015) { glyph = G.head; color = "1;38;5;231"; }
        else if (age < 0.10) { glyph = G.arc[0]; color = "1;38;5;214"; }
        else if (age < 0.30) { glyph = G.arc[1]; color = "38;5;208"; }
        else { glyph = G.arc[2]; color = "38;5;94"; }
        plot(pt[0], pt[1], glyph, color);
      }

      if (!landed) {
        // In flight, or verified with nothing to report: a dim cross, not a severity marker.
        if (progress >= 1 && asset.resolveAt === null) plot(asset.x, asset.y, "+", "38;5;240");
        else if (progress < 1) plot(asset.x, asset.y, "+", dim);
        continue;
      }
      var since = t - asset.resolveAt;
      if (since < 0.55) {
        var radius = 1.0 + easeOut(since / 0.55) * 2.6;
        for (var deg = 0; deg < 360; deg += 24) {
          var rad = (deg * Math.PI) / 180;
          plot(asset.x + Math.cos(rad) * radius * 2.0, asset.y + Math.sin(rad) * radius,
            G.ring, since < 0.2 ? "1;38;5;231" : paint);
        }
      }
      if (Math.floor(t * 2.6) % 2 === 0 || since < 0.55) {
        plot(asset.x, asset.y, G.blip, paint);
        var tag = asset.name.split(".")[0].toUpperCase().slice(0, 9);
        // Near the right limb the label would be clipped mid-word, so it flips to the other side.
        var at = asset.x + 2 + tag.length <= boxW - 3 ? asset.x + 2 : asset.x - 1 - tag.length;
        plotText(at, asset.y, tag, paint);
      }
    }
    plotText(ORIGIN[0] - 7, ORIGIN[1] - 1, "GREYNOC", "38;5;51");
    plot(ORIGIN[0], ORIGIN[1], G.blip, "1;38;5;51");

    // footer
    var barY = boxY + mapH + 1;
    this._hrule(g, boxX, barY, boxW, chrome);
    var tally = SEV_ORDER.filter(function (s) { return counts[s]; })
      .map(function (s) { return counts[s] + s[0].toUpperCase(); }).join("  ");
    g.text(boxX + 2, barY, " CONFIRMED  " + (tally || "--") + " ", chrome);
    var verified = this.assets.filter(function (x2) {
      return x2.launchAt !== null && t >= x2.launchAt + FLIGHT;
    }).length;
    var assets = " ASSETS " + verified + "/" + this.assets.length + " ";
    g.text(boxX + boxW - 2 - assets.length, barY, assets, chrome);

    var shown = this.lines.filter(function (line) { return line.at <= t; });
    if (shown.length > 1) {
      g.text(boxX + 2, barY + 1, shown[shown.length - 2].text.slice(0, boxW - 5), "38;5;240");
    }
    if (shown.length) {
      var last = shown[shown.length - 1];
      var text = typed(last.text, t - last.at, 62.0);
      g.text(boxX + 2, barY + 2, text.slice(0, boxW - 5), last.color);
      if (Math.floor(t * 3) % 2 === 0) {
        g.put(boxX + 2 + Math.min(text.length, boxW - 6), barY + 2, G.cursor, last.color);
      }
    }
    this._hrule(g, boxX, boxY + boxH - 1, boxW, chrome);
    g.text(boxX + 2, boxY + boxH - 1, " " + this.footer + " ", dim);

    this._blit();
  };

  WoprBoard.prototype._hrule = function (g, x, y, w, color) {
    for (var i = 0; i < w; i++) g.put(x + i, y, G.hbar, color);
  };

  WoprBoard.prototype._frameBox = function (g, x, y, w, h, color) {
    this._hrule(g, x, y, w, color);
    this._hrule(g, x, y + h - 1, w, color);
    for (var r = 1; r < h - 1; r++) {
      g.put(x, y + r, G.edges[0], color);
      g.put(x + w - 1, y + r, G.edges[1], color);
    }
    g.put(x, y, G.corners[0], color);
    g.put(x + w - 1, y, G.corners[1], color);
    g.put(x, y + h - 1, G.corners[2], color);
    g.put(x + w - 1, y + h - 1, G.corners[3], color);
  };

  WoprBoard.prototype._blit = function () {
    var ctx = this.ctx, g = this.grid;
    var w = this.cw * this.cols, h = this.chh * this.rows;
    var stack = '"Noto Sans Mono", ui-monospace, "Cascadia Mono", Consolas, monospace';
    var regular = this.fontSize + "px " + stack;
    var heavy = "600 " + this.fontSize + "px " + stack;
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
    ctx.font = regular;
    var fill = null, bold = false;
    for (var y = 0; y < this.rows; y++) {
      for (var x = 0; x < this.cols; x++) {
        var i = y * this.cols + x;
        var code = g.co[i];
        if (!code) continue;
        var ch = g.ch[i];
        var style = sgr(code);
        var px = x * this.cw, py = y * this.chh;
        if (style.rev) {
          ctx.fillStyle = style.fg;
          ctx.fillRect(px, py, this.cw + 0.5, this.chh);
          fill = style.fg;
          if (ch === " ") continue;
          ctx.fillStyle = "#000";
          fill = "#000";
        } else {
          if (ch === " ") continue;
          if (fill !== style.fg) { ctx.fillStyle = style.fg; fill = style.fg; }
        }
        var wantBold = style.bold && !style.rev;
        if (bold !== wantBold) { ctx.font = wantBold ? heavy : regular; bold = wantBold; }
        ctx.fillText(ch, px, py + 1);
      }
    }
    // One-pass CRT bloom: a blurred copy of the frame, added back over itself.
    try {
      ctx.save();
      ctx.globalCompositeOperation = "lighter";
      ctx.globalAlpha = 0.28;
      ctx.filter = "blur(2.5px)";
      ctx.drawImage(this.canvas, 0, 0, w, h);
      ctx.restore();
      ctx.filter = "none";
    } catch (err) {
      try { ctx.restore(); } catch (ignored) { /* a context that will not restore is still drawn */ }
    }
  };

  WoprBoard.COLS = COLS;
  WoprBoard.ROWS = ROWS;
  WoprBoard.FLIGHT = FLIGHT;
  WoprBoard.DEMO_SPAN = DEMO_SPAN;
  WoprBoard.SEVERITIES = SEV_ORDER;

  global.WoprBoard = WoprBoard;
  if (typeof module !== "undefined" && module.exports) module.exports = WoprBoard;
})(typeof window !== "undefined" ? window : globalThis);
