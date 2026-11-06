(function () {
  "use strict";
  var D = JSON.parse(document.getElementById("data").textContent);
  var SEV = ["critical", "high", "medium", "low", "info"];
  var RANK = {}; SEV.forEach(function (s, i) { RANK[s] = i; });
  var COLS = ["Vendor / supplier", "Trust anchor", "Source", "Software", "Service", "Listener"];

  // ---------- helpers (all data goes through textContent; never innerHTML) ----------
  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === "class") e.className = attrs[k];
      else if (k === "text") e.textContent = attrs[k];
      else if (k.slice(0, 2) === "on") e.addEventListener(k.slice(2), attrs[k]);
      else if (attrs[k] !== null && attrs[k] !== undefined) e.setAttribute(k, attrs[k]);
    }
    (kids || []).forEach(function (c) { if (c !== null && c !== undefined) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return e;
  }
  function sev(s) { return s ? el("span", { class: "sev " + s, text: s }) : el("span", { class: "muted", text: "–" }); }
  function pill(t, cls) { return el("span", { class: "pill " + (cls || ""), text: String(t) }); }
  function safeUrl(u) { return /^https?:\/\//i.test(u || "") ? u : null; }
  function link(u, text) { var s = safeUrl(u); return s ? el("a", { href: s, target: "_blank", rel: "noopener noreferrer", text: text || u }) : el("span", { text: text || String(u) }); }
  function fmt(v) { if (v === null || v === undefined) return ""; if (typeof v === "object") return JSON.stringify(v, null, 1); return String(v); }
  function kv(obj, skip) {
    var g = el("div", { class: "kv" });
    Object.keys(obj || {}).forEach(function (k) {
      if ((skip || []).indexOf(k) >= 0 || obj[k] === null || obj[k] === undefined || obj[k] === "") return;
      var v = obj[k];
      g.appendChild(el("div", { class: "k", text: k.replace(/_/g, " ") }));
      g.appendChild(typeof v === "object" ? el("pre", { class: "ev", text: JSON.stringify(v, null, 1) }) : el("div", { class: "mono", text: String(v) }));
    });
    return g;
  }
  function table(cols, rows, opts) {
    opts = opts || {};
    var t = el("table"), th = el("tr");
    cols.forEach(function (c) { th.appendChild(el("th", { text: c })); });
    t.appendChild(el("thead", null, [th]));
    var tb = el("tbody");
    rows.forEach(function (r) {
      var tr = el("tr");
      r.forEach(function (c, i) {
        var td = el("td", (opts.num || []).indexOf(i) >= 0 ? { class: "num" } : null);
        if (c instanceof Node) td.appendChild(c); else td.textContent = fmt(c);
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    return el("div", { class: "tbl-wrap" }, [t]);
  }
  function $(id) { return document.getElementById(id); }

  // ---------- header ----------
  var m = D.meta;
  $("host").textContent = m.hostname;
  $("when").textContent = m.collected_at + " · run as " + m.run_as + (m.online && m.online.length ? " · online: " + m.online.join(",") : " · offline") +
    " · secdepmap " + m.tool_version;
  var tiles = $("tiles");
  SEV.forEach(function (s) {
    tiles.appendChild(el("div", { class: "tile sev-" + s }, [el("div", { class: "n", text: D.summary.findings_by_severity[s] }), el("div", { class: "l", text: s + " findings" })]));
  });
  var pk = D.summary.packages_by_ecosystem, total = 0; Object.keys(pk).forEach(function (k) { total += pk[k]; });
  tiles.appendChild(el("div", { class: "tile" }, [el("div", { class: "n", text: total }), el("div", { class: "l", text: "packages · " + Object.keys(pk).map(function (k) { return k + " " + pk[k]; }).join(", ") })]));
  tiles.appendChild(el("div", { class: "tile" }, [el("div", { class: "n", text: D.sources.length }), el("div", { class: "l", text: "sources (" + D.sources.filter(function (s) { return s.enabled; }).length + " active)" })]));
  tiles.appendChild(el("div", { class: "tile" }, [el("div", { class: "n", text: D.vendors.filter(function (v) { return !v.pseudo; }).length }), el("div", { class: "l", text: "vendors / suppliers" })]));
  var chips = $("chips");
  Object.keys(D.collectors).forEach(function (k) {
    var c = D.collectors[k];
    chips.appendChild(el("span", { class: "chip " + c.status, title: (c.notes || []).join("\n"), text: k + ": " + c.status }));
  });
  var partial = Object.keys(D.collectors).filter(function (k) { return D.collectors[k].status === "partial" || (D.collectors[k].notes || []).length && D.collectors[k].status !== "skipped" && D.collectors[k].status !== "disabled"; });
  var notes = [];
  Object.keys(D.collectors).forEach(function (k) { (D.collectors[k].notes || []).forEach(function (n) { notes.push(k + ": " + n); }); });
  if (notes.length) $("notes").textContent = "Coverage notes — " + notes.join(" · ");

  // theme toggle
  var root = document.documentElement;
  try { var saved = localStorage.getItem("secdepmap-theme"); if (saved) root.setAttribute("data-theme", saved); } catch (e) { }
  $("theme").addEventListener("click", function () {
    var dark = root.getAttribute("data-theme") ? root.getAttribute("data-theme") === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    var next = dark ? "light" : "dark"; root.setAttribute("data-theme", next);
    try { localStorage.setItem("secdepmap-theme", next); } catch (e) { }
  });

  // ---------- tabs ----------
  var tabs = [
    ["findings", "Findings", D.findings.length], ["map", "Dependency map", null], ["sources", "Sources & trust", D.sources.length],
    ["vendors", "Vendors", D.vendors.length], ["exposure", "Network exposure", D.exposure.length],
    ["inventory", "Inventory", D.inventory.rows.length], ["platform", "Platform", null]
  ];
  if (D.diff) tabs.push(["changes", "Changes", D.diff.empty ? 0 : null]);
  var nav = $("tabs");
  tabs.forEach(function (t) {
    var b = el("button", { role: "tab", "data-tab": t[0], "aria-selected": "false" }, [t[1], t[2] !== null ? el("span", { class: "count", text: t[2] }) : null]);
    b.addEventListener("click", function () { show(t[0]); });
    nav.appendChild(b);
  });
  var built = {};
  function show(id, noHash) {
    [].forEach.call(nav.children, function (b) { b.setAttribute("aria-selected", b.getAttribute("data-tab") === id ? "true" : "false"); });
    [].forEach.call(document.querySelectorAll("section.panel"), function (p) { p.classList.toggle("active", p.id === "p-" + id); });
    if (!built[id] && builders[id]) { builders[id]($("p-" + id)); built[id] = true; }
    if (!noHash) { try { history.replaceState(null, "", "#" + id); } catch (e) { } }
  }

  var builders = {};

  // ---------- findings ----------
  builders.findings = function (p) {
    var cats = {}; D.findings.forEach(function (f) { cats[f.category] = 1; });
    var q = el("input", { type: "search", placeholder: "Filter findings…", "aria-label": "Filter findings" });
    var sevSel = el("select", { "aria-label": "Minimum severity" }, SEV.map(function (s) { return el("option", { value: s, text: "≥ " + s }); }));
    sevSel.value = "low";
    var catSel = el("select", { "aria-label": "Category" }, [el("option", { value: "", text: "all categories" })].concat(Object.keys(cats).sort().map(function (c) { return el("option", { value: c, text: c }); })));
    p.appendChild(el("div", { class: "toolbar" }, [q, sevSel, catSel]));
    var list = el("div"); p.appendChild(list);
    var cnt = el("div", { class: "sub" }); p.appendChild(cnt);
    function draw() {
      list.textContent = "";
      var min = RANK[sevSel.value], term = q.value.toLowerCase(), n = 0;
      D.findings.forEach(function (f) {
        if (RANK[f.severity] > min || (catSel.value && f.category !== catSel.value)) return;
        if (term && (f.title + " " + f.detail + " " + f.id).toLowerCase().indexOf(term) < 0) return;
        n++;
        var body = el("div", { class: "body" });
        if (f.detail) body.appendChild(el("p", { text: f.detail }));
        if (f.evidence) body.appendChild(el("pre", { class: "ev", text: typeof f.evidence === "string" ? f.evidence : JSON.stringify(f.evidence, null, 1) }));
        if (f.remediation) body.appendChild(el("div", { class: "fix" }, [el("b", { text: "Fix: " }), f.remediation]));
        if (f.refs && f.refs.length) body.appendChild(el("div", { class: "sub" }, ["References: "].concat(f.refs.map(function (r) { return link(r, r); }))));
        if (f.nodes.length) {
          var nd = el("div", { class: "nodes" }, [el("span", { class: "sub", text: "Related: " })]);
          f.nodes.slice(0, 12).forEach(function (x) { nd.appendChild(el("a", { href: "#", text: x.label, onclick: function (ev) { ev.preventDefault(); focusNode(x.id); } })); });
          if (f.nodes.length > 12 || f.more_nodes) nd.appendChild(el("span", { class: "sub", text: "+" + (f.nodes.length - 12 + f.more_nodes) + " more" }));
          body.appendChild(nd);
        }
        body.appendChild(el("div", { class: "sub mono", text: f.id }));
        list.appendChild(el("details", { class: "finding " + f.severity }, [el("summary", null, [sev(f.severity), el("span", { class: "t", text: f.title }), el("span", { class: "cat", text: f.category })]), body]));
      });
      cnt.textContent = n + " of " + D.findings.length + " findings shown";
    }
    [q, sevSel, catSel].forEach(function (x) { x.addEventListener("input", draw); });
    draw();
  };

  // ---------- map ----------
  var svgNS = "http://www.w3.org/2000/svg", mapState = null;
  function S(tag, attrs) { var e = document.createElementNS(svgNS, tag); for (var k in attrs) e.setAttribute(k, attrs[k]); return e; }
  builders.map = function (p) {
    p.appendChild(el("p", { class: "sub", text: "Read left → right: who supplies and vouches for software, where it comes from, what is installed, which services run it and what listens on the network. Click a node to trace its dependency chain; hatched edges are inferred, dashed edges show trust by key." }));
    p.appendChild(el("div", { class: "legend" }, [
      el("span", null, [el("i", { class: "sw-critical" }), "critical"]), el("span", null, [el("i", { class: "sw-high" }), "high"]),
      el("span", null, [el("i", { class: "sw-medium" }), "medium"]), el("span", null, [el("i", { class: "sw-low" }), "low"]),
      el("span", null, [el("i", { class: "sw-none" }), "no finding"]),
      el("label", null, [el("input", { type: "checkbox", id: "onlyrisk" }), " only chains with findings"])]));
    var box = el("div", { class: "map-box", id: "mapbox" }), side = el("div", { class: "side", id: "side" }, [el("div", { class: "empty", text: "Select a node to see details, findings and its upstream/downstream chain." })]);
    p.appendChild(el("div", { class: "map-shell" }, [box, side]));
    drawMap(false);
    $("onlyrisk").addEventListener("change", function () { drawMap(this.checked); });
  };
  function drawMap(onlyRisk) {
    var M = D.map, nodes = M.nodes, edges = M.edges;
    var adj = nodes.map(function () { return []; });
    edges.forEach(function (e) { adj[e[0]].push(e[1]); adj[e[1]].push(e[0]); });
    var keep = nodes.map(function () { return true; });
    if (onlyRisk) {
      // keep each risky node plus its directed upstream and downstream chain (edges run low col -> high col)
      var upA = nodes.map(function () { return []; }), dnA = nodes.map(function () { return []; });
      edges.forEach(function (e) { dnA[e[0]].push(e[1]); upA[e[1]].push(e[0]); });
      var seen = nodes.map(function () { return false; });
      function walk(start, A) { var q = [start]; while (q.length) { var c = q.pop(); A[c].forEach(function (nb) { if (!seen[nb]) { seen[nb] = true; q.push(nb); } }); } }
      nodes.forEach(function (n, i) { if (n.risk && RANK[n.risk] <= 2) { seen[i] = true; walk(i, upA); walk(i, dnA); } });
      keep = seen;
    }
    var cols = [[], [], [], [], [], []];
    nodes.forEach(function (n, i) { if (keep[i]) cols[n.col].push(i); });
    // order: barycenter against the left column, risky first within ties
    var pos = {};
    cols.forEach(function (c, ci) {
      if (ci === 0) c.sort(function (a, b) { return (nodes[b].count || 0) - (nodes[a].count || 0) || nodes[a].label.localeCompare(nodes[b].label); });
      else c.sort(function (a, b) {
        function bc(i) { var l = adj[i].filter(function (x) { return nodes[x].col < ci && pos[x] !== undefined; }); return l.length ? l.reduce(function (s, x) { return s + pos[x]; }, 0) / l.length : 1e6; }
        return bc(a) - bc(b) || (RANK[nodes[a].risk || "info"] - RANK[nodes[b].risk || "info"]) || nodes[a].label.localeCompare(nodes[b].label);
      });
      c.forEach(function (i, r) { pos[i] = r; });
    });
    var W = 218, GAP = 78, H = 26, VG = 7, TOP = 28, PAD = 12;
    var xs = [], used = cols.map(function (c) { return c.length > 0; }), x = PAD;
    cols.forEach(function (c, ci) { xs[ci] = x; if (used[ci]) x += W + GAP; });
    var maxRows = Math.max.apply(null, cols.map(function (c) { return c.length; }).concat([1]));
    var height = TOP + maxRows * (H + VG) + PAD, width = x - GAP + PAD;
    var svg = S("svg", { width: width, height: height, viewBox: "0 0 " + width + " " + height, role: "img", "aria-label": "Security dependency map" });
    cols.forEach(function (c, ci) { if (used[ci]) { var t = S("text", { x: xs[ci], y: 16, class: "colhead" }); t.textContent = COLS[ci]; svg.appendChild(t); } });
    var geo = {};
    cols.forEach(function (c, ci) { c.forEach(function (i, r) { geo[i] = { x: xs[ci], y: TOP + r * (H + VG) }; }); });
    var gE = S("g"), gN = S("g"), eEls = [], nEls = {};
    edges.forEach(function (e) {
      if (!keep[e[0]] || !keep[e[1]]) return;
      var a = geo[e[0]], b = geo[e[1]], x1 = a.x + W, y1 = a.y + H / 2, x2 = b.x, y2 = b.y + H / 2, mx = (x1 + x2) / 2;
      var pth = S("path", { d: "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2, class: "e " + (e[2] === "solid" ? "" : e[2]) });
      gE.appendChild(pth); eEls.push({ el: pth, a: e[0], b: e[1] });
    });
    nodes.forEach(function (n, i) {
      if (!keep[i]) return;
      var g = S("g", { class: "node r-" + (n.risk || "none"), transform: "translate(" + geo[i].x + "," + geo[i].y + ")", tabindex: 0 });
      g.appendChild(S("rect", { class: "box", width: W, height: H, rx: 5 }));
      g.appendChild(S("rect", { class: "bar", width: 4, height: H, rx: 2 }));
      var lab = n.label.length > 33 ? n.label.slice(0, 32) + "…" : n.label;
      var t = S("text", { x: 11, y: 17 }); t.textContent = lab; g.appendChild(t);
      var tt = S("title", {}); tt.textContent = n.label + (n.risk ? " — worst finding: " + n.risk : ""); g.appendChild(tt);
      g.addEventListener("click", function () { selectNode(i); });
      g.addEventListener("keydown", function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); selectNode(i); } });
      gN.appendChild(g); nEls[i] = g;
    });
    svg.appendChild(gE); svg.appendChild(gN);
    var box = $("mapbox"); box.textContent = ""; box.appendChild(svg);
    mapState = { svg: svg, adj: adj, nEls: nEls, eEls: eEls, keep: keep, geo: geo, H: H };
    svg.addEventListener("click", function (ev) { if (ev.target === svg) clearSel(); });
  }
  function reach(start, dirFn) {
    var seen = {}, q = [start]; seen[start] = true;
    while (q.length) { var c = q.pop(); dirFn(c).forEach(function (n) { if (!seen[n]) { seen[n] = true; q.push(n); } }); }
    return seen;
  }
  function selectNode(i) {
    var M = D.map, ms = mapState;
    var up = {}, down = {};
    D.map.edges.forEach(function (e) { (down[e[0]] = down[e[0]] || []).push(e[1]); (up[e[1]] = up[e[1]] || []).push(e[0]); });
    var u = reach(i, function (c) { return up[c] || []; }), d = reach(i, function (c) { return down[c] || []; });
    ms.svg.classList.add("focus");
    Object.keys(ms.nEls).forEach(function (k) { var on = u[k] || d[k]; ms.nEls[k].classList.toggle("hi", !!on); ms.nEls[k].classList.toggle("sel", +k === i); });
    ms.eEls.forEach(function (e) { e.el.classList.toggle("hi", !!((u[e.a] && u[e.b]) || (d[e.a] && d[e.b]))); });
    showDetail(M.nodes[i].ref, M.nodes[i]);
  }
  function clearSel() {
    if (!mapState) return; mapState.svg.classList.remove("focus");
    Object.keys(mapState.nEls).forEach(function (k) { mapState.nEls[k].classList.remove("hi", "sel"); });
  }
  function focusNode(id) {
    show("map");
    var idx = -1; D.map.nodes.forEach(function (n, i) { if (n.id === id || n.ref === id) idx = i; });
    if (idx >= 0 && mapState && mapState.nEls[idx]) { selectNode(idx); mapState.nEls[idx].scrollIntoView({ block: "center", inline: "center" }); }
    else showDetail(id, null);
  }
  function showDetail(id, mn) {
    var s = $("side"); if (!s) return; s.textContent = "";
    var d = D.details[id];
    if (!d) { s.appendChild(el("div", { class: "empty", text: "No further details." })); return; }
    s.appendChild(el("h4", { text: d.label }));
    s.appendChild(el("div", { class: "sub", text: (d.type || "") + (d.risk ? " · " : "") }, d.risk ? [sev(d.risk)] : []));
    if (d.type === "group") {
      s.appendChild(el("p", { text: d.label }));
      var ul = el("pre", { class: "ev", text: d.packages.slice(0, 400).join("\n") + (d.packages.length > 400 ? "\n… " + (d.packages.length - 400) + " more (see Inventory)" : "") });
      s.appendChild(ul);
    } else {
      s.appendChild(kv(d.attrs, ["release", "list_files", "subkeys"]));
    }
    var fs = (d.findings || []).map(function (fid) { return D.findings.filter(function (f) { return f.id === fid; })[0]; }).filter(Boolean);
    if (fs.length) {
      s.appendChild(el("h3", { text: "Findings" }));
      fs.slice(0, 20).forEach(function (f) { s.appendChild(el("div", null, [sev(f.severity), " ", f.title])); });
    }
  }

  // ---------- sources ----------
  builders.sources = function (p) {
    var q = el("input", { type: "search", placeholder: "Filter sources…" }), eco = {};
    D.sources.forEach(function (s) { eco[s.eco || "?"] = 1; });
    var sel = el("select", null, [el("option", { value: "", text: "all ecosystems" })].concat(Object.keys(eco).sort().map(function (e) { return el("option", { value: e, text: e }); })));
    var act = el("input", { type: "checkbox" });
    p.appendChild(el("div", { class: "toolbar" }, [q, sel, el("label", null, [act, " only enabled"])]));
    var out = el("div"); p.appendChild(out);
    function draw() {
      out.textContent = "";
      var rows = D.sources.filter(function (s) {
        return (!sel.value || (s.eco || "?") === sel.value) && (!act.checked || s.enabled) &&
          (!q.value || (s.label + " " + (s.uri || "") + " " + s.vendor).toLowerCase().indexOf(q.value.toLowerCase()) >= 0);
      }).map(function (s) {
        var trust = el("div");
        (s.signers || []).slice(0, 3).forEach(function (x) { trust.appendChild(el("div", { class: "mono", text: x })); });
        if (!(s.signers || []).length) trust.appendChild(pill(s.trust || "none", "warn"));
        if (s.trusts > 1) trust.appendChild(pill("trusts " + s.trusts + " keys (global)", "warn"));
        var flags = el("div");
        flags.appendChild(pill(s.enabled ? "enabled" : "disabled" + (s.disabled_reason ? ": " + s.disabled_reason : ""), s.enabled ? "good" : "bad"));
        if (s.transport === "http") flags.appendChild(pill("http", "warn"));
        if (s.uu) flags.appendChild(pill("auto-updates", "good"));
        if (s.official) flags.appendChild(pill("official", "good"));
        return [sev(s.risk), el("div", null, [el("div", { text: s.label }), el("div", { class: "sub mono", text: s.uri || "" })]), s.eco || "", flags, s.vendor, trust, s.packages];
      });
      out.appendChild(table(["Risk", "Source", "Type", "State", "Operated by", "Signed by / trust", "Pkgs"], rows, { num: [6] }));
    }
    [q, sel, act].forEach(function (x) { x.addEventListener("input", draw); }); draw();
    p.appendChild(el("h3", { text: "Signing keys & trust anchors" }));
    var ar = D.anchors.sort(function (a, b) { return (RANK[a.risk || "info"] - RANK[b.risk || "info"]); }).map(function (a) {
      var exp = a.expires ? a.expires.slice(0, 10) : (a.kind === "openpgp-key" ? "never" : "");
      return [sev(a.risk), el("div", null, [el("div", { text: a.label }), a.fpr ? el("div", { class: "sub mono", text: a.fpr }) : null]),
      (a.algo ? a.algo + (a.bits ? "-" + a.bits : "") : a.kind || ""), exp, el("div", null, [pill(a.scope || a.kind || "", a.scope === "global" ? "warn" : ""), a.scope === "unreferenced" ? pill("not used", "warn") : null]),
      a.vendor, (a.used_by || []).slice(0, 4).join(", ") + ((a.used_by || []).length > 4 ? " …" : "")];
    });
    p.appendChild(table(["Risk", "Key", "Algorithm", "Expires", "Scope", "Issued by", "Used by"], ar));
  };

  // ---------- vendors ----------
  builders.vendors = function (p) {
    p.appendChild(el("p", { class: "sub", text: "Every supplier your software depends on, with where it publishes security information. Links come from the curated knowledge base (kb/vendors.json) and are re-verified with “secdepmap kb verify”." }));
    var grid = el("div", { class: "cards" });
    D.vendors.filter(function (v) { return !v.pseudo; }).forEach(function (v) {
      var head = el("h4", null, [el("span", { text: v.label }), v.risk ? sev(v.risk) : null]);
      var card = el("div", { class: "card" }, [head, el("div", { class: "meta", text: [v.kind || "", v.packages ? v.packages + " package(s)" : "", v.exposed ? v.exposed + " network-facing" : ""].filter(Boolean).join(" · ") })]);
      if (!v.kb) card.appendChild(pill("not in knowledge base", "warn"));
      var eco = Object.keys(v.by_eco || {}); if (eco.length) card.appendChild(el("div", null, eco.map(function (e) { return pill(e + " " + v.by_eco[e]); })));
      if (v.support) card.appendChild(el("p", { text: v.support }));
      var ls = Object.keys(v.links || {});
      if (ls.length) card.appendChild(el("ul", null, ls.map(function (k) { return el("li", null, [el("span", { class: "muted", text: k.replace(/_/g, " ") + ": " }), link(v.links[k], v.links[k].replace(/^https?:\/\//, ""))]); })));
      if (v.security_txt) Object.keys(v.security_txt).forEach(function (dom) {
        var st = v.security_txt[dom];
        if (st.found) card.appendChild(el("div", { class: "sub" }, ["security.txt (" + dom + "): "].concat((st.Contact || []).map(function (c) { return /^https?:/.test(c) ? link(c, c) : el("span", { text: c + " " }); }))));
      });
      if (v.sources && v.sources.length) card.appendChild(el("div", { class: "sub", text: "Sources: " + v.sources.slice(0, 4).join("; ") }));
      if (v.verified) card.appendChild(el("div", { class: "sub", text: "links verified " + v.verified }));
      if (v.notes) card.appendChild(el("div", { class: "sub", text: v.notes }));
      grid.appendChild(card);
    });
    p.appendChild(grid);
  };

  // ---------- exposure ----------
  builders.exposure = function (p) {
    var loop = el("input", { type: "checkbox" });
    p.appendChild(el("div", { class: "toolbar" }, [el("label", null, [loop, " include loopback-only listeners"])]));
    var out = el("div"); p.appendChild(out);
    var fw = (D.platform.host[0] || { attrs: {} }).attrs.firewall;
    if (fw) p.insertBefore(el("p", null, ["Host firewall filtering: ", pill(fw.filtering, fw.filtering === "no" ? "bad" : fw.filtering === "yes" ? "good" : "warn"), " ", el("span", { class: "sub", text: (fw.evidence || []).join("; ") })]), out);
    function draw() {
      out.textContent = "";
      var rows = D.exposure.filter(function (x) { return loop.checked || x.scope !== "loopback"; }).map(function (x) {
        return [sev(x.risk), x.proto + "/" + x.port, el("span", null, [x.addr === "*" || x.addr === "0.0.0.0" || x.addr === "::" ? "all interfaces" : x.addr, " ", pill(x.scope, x.scope === "loopback" ? "good" : "warn")]),
        x.service, x.user || "", x.exposure !== null && x.exposure !== undefined ? x.exposure + " " + (x.rating || "") : "", x.package, x.source, x.vendor];
      });
      out.appendChild(table(["Risk", "Port", "Bound to", "Service / process", "Runs as", "Sandboxing score", "Package", "Package source", "Vendor"], rows));
    }
    loop.addEventListener("input", draw); draw();
  };

  // ---------- inventory ----------
  builders.inventory = function (p) {
    var rows = D.inventory.rows, q = el("input", { type: "search", placeholder: "Filter by name, source, vendor…" }), eco = {};
    rows.forEach(function (r) { eco[r[2]] = 1; });
    var sel = el("select", null, [el("option", { value: "", text: "all ecosystems" })].concat(Object.keys(eco).sort().map(function (e) { return el("option", { value: e, text: e }); })));
    var risk = el("input", { type: "checkbox" });
    p.appendChild(el("div", { class: "toolbar" }, [q, sel, el("label", null, [risk, " only with findings"])]));
    var out = el("div"), info = el("div", { class: "sub" }), more = el("div", { class: "more" }); p.appendChild(out); p.appendChild(info); p.appendChild(more);
    var limit = 300;
    function draw() {
      var t = q.value.toLowerCase();
      var f = rows.filter(function (r) { return (!sel.value || r[2] === sel.value) && (!risk.checked || r[6]) && (!t || (r[0] + " " + r[3] + " " + r[4] + " " + r[5]).toLowerCase().indexOf(t) >= 0); });
      out.textContent = ""; more.textContent = "";
      out.appendChild(table(["Package", "Version", "Eco", "Class", "Source", "Vendor", "Risk", "Scope"], f.slice(0, limit).map(function (r) { return [r[0], r[1], r[2], r[3], r[4], r[5], sev(r[6]), r[7]]; })));
      info.textContent = "Showing " + Math.min(limit, f.length) + " of " + f.length;
      if (f.length > limit) more.appendChild(el("button", { text: "Show 500 more", onclick: function () { limit += 500; draw(); } }));
    }
    [q, sel, risk].forEach(function (x) { x.addEventListener("input", function () { limit = 300; draw(); }); }); draw();
  };

  // ---------- platform ----------
  builders.platform = function (p) {
    var P = D.platform;
    function block(title, arr, skip) {
      p.appendChild(el("h3", { text: title }));
      arr.forEach(function (n) { p.appendChild(el("div", { class: "card", style: "margin-bottom:8px" }, [el("h4", { text: n.label }), kv(n.attrs, skip)])); });
    }
    block("Host", P.host, ["firewall", "hsi_failures"]); block("Operating system", P.os); block("Kernel", P.kernel, ["sysctl"]);
    block("CPU", P.cpu, ["vulnerabilities"]);
    if (P.cpu[0] && P.cpu[0].attrs.vulnerabilities) {
      p.appendChild(el("h3", { text: "CPU vulnerability status (kernel-reported)" }));
      var v = P.cpu[0].attrs.vulnerabilities;
      p.appendChild(table(["Issue", "State"], Object.keys(v).sort().map(function (k) { return [k, el("span", null, [pill(v[k], /^Vulnerable/.test(v[k]) ? "bad" : /SMT vulnerable/.test(v[k]) ? "warn" : "good")])]; })));
    }
    if (P.kernel[0] && P.kernel[0].attrs.sysctl) { p.appendChild(el("h3", { text: "Kernel hardening (sysctl)" })); p.appendChild(table(["Key", "Value"], Object.keys(P.kernel[0].attrs.sysctl).sort().map(function (k) { return [k, P.kernel[0].attrs.sysctl[k]]; }))); }
    if (P.firmware.length) { p.appendChild(el("h3", { text: "Firmware (fwupd)" })); p.appendChild(table(["Device", "Vendor", "Version", "Updatable"], P.firmware.map(function (f) { return [f.label, f.attrs.vendor, f.attrs.version, f.attrs.updatable ? "yes" : "no"]; }))); }
    var h = P.host[0] && P.host[0].attrs.hsi_failures;
    if (h) { p.appendChild(el("h3", { text: "Platform security checks not passing (fwupd HSI)" })); p.appendChild(table(["Check", "Result", "HSI level", "Remedy"], h.map(function (x) { return [x.name, x.result, x.level || "runtime", (x.actions || []).join(", ")]; }))); }
    if (P.accounts.length) { p.appendChild(el("h3", { text: "Interactive accounts" })); p.appendChild(table(["User", "UID", "Groups"], P.accounts.map(function (a) { return [a.label, a.attrs.uid, (a.attrs.groups || []).join(", ")]; }))); }
  };

  // ---------- changes ----------
  builders.changes = function (p) {
    var d = D.diff; if (!d) return;
    p.appendChild(el("p", { class: "sub", text: "Compared with the previous snapshot taken " + d.from }));
    if (d.empty) { p.appendChild(el("p", { text: "No changes." })); return; }
    function sect(title, items) { if (!items || !items.length) return; p.appendChild(el("h3", { text: title + " (" + items.length + ")" })); p.appendChild(el("pre", { class: "ev", text: items.slice(0, 300).map(function (x) { return typeof x === "string" ? x : "[" + x.severity + "] " + x.title; }).join("\n") + (items.length > 300 ? "\n… " + (items.length - 300) + " more" : "") })); }
    sect("New findings", d.findings_new); sect("Resolved findings", d.findings_resolved); sect("Severity changes", d.findings_severity_changed);
    sect("Trust changes on sources", d.trust_changed); sect("Sources added", d.sources_added); sect("Sources removed", d.sources_removed); sect("Sources enabled/disabled", d.sources_toggled);
    sect("Signing keys added", d.anchors_added); sect("Signing keys removed", d.anchors_removed);
    sect("Listeners added", d.listeners_added); sect("Listeners removed", d.listeners_removed);
    sect("Provenance changed", d.provenance_changed); sect("Packages added", d.packages_added); sect("Packages removed", d.packages_removed); sect("Packages changed", d.packages_changed);
  };

  var start = (location.hash || "").replace("#", "");
  show(tabs.some(function (t) { return t[0] === start; }) ? start : "findings", true);
})();
