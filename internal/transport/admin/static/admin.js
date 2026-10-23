// Copy-to-clipboard buttons and confirmation for destructive actions.
// Loaded from 'self' only (strict CSP, no inline scripts).
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-copy]");
  if (!btn) return;
  navigator.clipboard.writeText(btn.getAttribute("data-copy")).then(function () {
    var old = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(function () { btn.textContent = old; }, 1200);
  });
});
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});

// Keep the current page's sections beside its navigation link.
(function () {
  var current = document.querySelector('.nav > a[aria-current="page"]');
  if (!current) return;
  var headings = Array.from(document.querySelectorAll(".page h2"));
  var sections = document.createElement("div");
  sections.className = "section-nav";
  var links = headings.map(function (heading, index) {
    if (!heading.id) {
      var base = "section-" + heading.textContent.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/-$/, "");
      var id = base;
      var suffix = 2;
      while (document.getElementById(id)) id = base + "-" + suffix++;
      heading.id = id;
    }
    var link = document.createElement("a");
    link.href = "#" + heading.id;
    link.textContent = heading.textContent.trim();
    sections.appendChild(link);
    return link;
  });
  if (headings.length) current.after(sections);

  var scheduled = false;
  function updateSection() {
    scheduled = false;
    var active = -1;
    headings.forEach(function (heading, index) {
      if (heading.getBoundingClientRect().top <= 100) active = index;
    });
    links.forEach(function (link, index) {
      if (index === active) link.setAttribute("aria-current", "location");
      else link.removeAttribute("aria-current");
    });
  }
  window.addEventListener("scroll", function () {
    if (!scheduled) {
      scheduled = true;
      window.requestAnimationFrame(updateSection);
    }
  }, { passive: true });
  updateSection();

  var menu = document.querySelector(".sidebar-menu");
  var mobile = window.matchMedia("(max-width: 760px)");
  function syncMenu() { menu.open = !mobile.matches; }
  syncMenu();
  mobile.addEventListener("change", syncMenu);
  sections.addEventListener("click", function (e) {
    if (e.target.closest("a") && mobile.matches) menu.open = false;
  });
  // Generated anchors also work when opened directly or after a refresh.
  if (window.location.hash) {
    var target = document.getElementById(window.location.hash.slice(1));
    if (target) target.scrollIntoView();
  }
})();

// Code editors for email templates: line numbers and highlighting for HTML,
// Go template actions and variables. The textarea stays the real input
// (forms, undo, accessibility); a highlighted copy is drawn behind it.
(function () {
  var areas = document.querySelectorAll("textarea[data-code]");
  if (!areas.length) return;

  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function span(cls, s) {
    return '<span class="' + cls + '">' + esc(s) + "</span>";
  }
  var KEYWORDS = /^(if|else|end|range|with|template|define|block|eq|ne|lt|le|gt|ge|and|or|not|len|index|print|printf)$/;

  // {{ .Data.Link }} -> braces, keywords and variables in their own colors.
  function action(src) {
    var out = "";
    var re = /(\.[A-Za-z_][\w.]*)|("[^"]*")|([A-Za-z_]\w*)|([^.A-Za-z_"]+)/g;
    var inner = src.slice(2, src.endsWith("}}") ? -2 : src.length);
    var m;
    while ((m = re.exec(inner))) {
      if (m[1]) out += span("tok-var", m[1]);
      else if (m[2]) out += span("tok-str", m[2]);
      else if (m[3]) out += KEYWORDS.test(m[3]) ? span("tok-kw", m[3]) : esc(m[3]);
      else out += esc(m[4]);
    }
    return '<span class="tok-tpl">' + esc("{{") + out + (src.endsWith("}}") ? esc("}}") : "") + "</span>";
  }

  function highlight(src, mode) {
    var out = "", i = 0, n = src.length, state = "text", quote = "";
    while (i < n) {
      if (src.startsWith("{{", i)) {
        var close = src.indexOf("}}", i + 2);
        var j = close < 0 ? n : close + 2;
        out += action(src.slice(i, j));
        i = j;
        continue;
      }
      var next = src.indexOf("{{", i);
      if (next < 0) next = n;
      if (mode !== "html") {
        out += esc(src.slice(i, next));
        i = next;
        continue;
      }
      if (state === "text") {
        if (src.startsWith("<!--", i)) {
          var endc = src.indexOf("-->", i);
          var k = endc < 0 ? n : endc + 3;
          out += span("tok-comment", src.slice(i, k));
          i = k;
        } else if (src[i] === "<" && /[A-Za-z\/!]/.test(src[i + 1] || "")) {
          var tag = /^<\/?[!A-Za-z][\w-]*/.exec(src.slice(i))[0];
          out += span("tok-tag", tag);
          i += tag.length;
          state = "tag";
        } else {
          var lt = src.indexOf("<", i + 1);
          var stop = Math.min(next, lt < 0 ? n : lt);
          out += esc(src.slice(i, stop));
          i = stop;
        }
      } else if (state === "tag") {
        var rest = src.slice(i, next);
        var m = /^\/?>/.exec(rest) || /^[\w:-]+/.exec(rest) || /^["']/.exec(rest);
        if (!m) {
          out += esc(src[i]);
          i++;
        } else if (m[0] === '"' || m[0] === "'") {
          quote = m[0];
          out += span("tok-str", quote);
          i++;
          state = "str";
        } else if (m[0].endsWith(">")) {
          out += span("tok-tag", m[0]);
          i += m[0].length;
          state = "text";
        } else {
          out += span("tok-attr", m[0]);
          i += m[0].length;
        }
      } else {
        var q = src.indexOf(quote, i);
        var to = Math.min(next, q < 0 ? n : q + 1);
        out += span("tok-str", src.slice(i, to));
        i = to;
        if (q >= 0 && q < next) state = "tag";
      }
    }
    return out + "\n";
  }

  var lastFocused = null;
  areas.forEach(function (ta) {
    var mode = ta.getAttribute("data-code");
    var wrap = document.createElement("div");
    wrap.className = "code-editor is-live";
    var gutter = document.createElement("div");
    gutter.className = "code-gutter";
    gutter.setAttribute("aria-hidden", "true");
    var body = document.createElement("div");
    body.className = "code-body";
    var pre = document.createElement("pre");
    pre.className = "code-hl";
    pre.setAttribute("aria-hidden", "true");
    ta.parentNode.insertBefore(wrap, ta);
    body.appendChild(pre);
    body.appendChild(ta);
    wrap.appendChild(gutter);
    wrap.appendChild(body);
    ta.classList.add("code-input");

    function render() {
      pre.innerHTML = highlight(ta.value, mode);
      var lines = ta.value.split("\n").length;
      var nums = "";
      for (var l = 1; l <= lines; l++) nums += l + "\n";
      gutter.textContent = nums;
      sync();
    }
    function sync() {
      pre.scrollTop = ta.scrollTop;
      pre.scrollLeft = ta.scrollLeft;
      gutter.scrollTop = ta.scrollTop;
    }
    ta.addEventListener("input", render);
    ta.addEventListener("scroll", sync);
    ta.addEventListener("focus", function () { lastFocused = ta; });
    // Tab indents instead of leaving the field; Escape then Tab leaves it.
    var escaped = false;
    ta.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { escaped = true; return; }
      if (e.key === "Tab" && !escaped && !e.shiftKey) {
        e.preventDefault();
        document.execCommand("insertText", false, "  ");
      }
      if (e.key !== "Tab") escaped = false;
    });
    new ResizeObserver(sync).observe(ta);
    render();
  });

  // Variable chips insert at the caret of the last focused editor.
  document.addEventListener("click", function (e) {
    var chip = e.target.closest("[data-insert]");
    if (!chip) return;
    var ta = lastFocused || areas[0];
    ta.focus();
    document.execCommand("insertText", false, chip.getAttribute("data-insert"));
  });
})();

// Syntax colors for read-only code samples (docs, integrate, webhooks).
// Small on purpose: comments, strings, keywords, numbers, properties,
// calls, shell flags and variables. The language comes from data-lang, the
// sample's label, or a guess from the first line.
(function () {
  var blocks = document.querySelectorAll(".page pre:not(.code-hl):not(.env-preview):not([data-plain])");
  if (!blocks.length) return;

  var KW = {
    js: "import|from|export|default|const|let|var|function|return|if|else|await|async|new|try|catch|throw|for|of|in|typeof|class|extends|null|undefined|true|false|this",
    go: "package|import|func|return|if|else|err|nil|var|const|type|struct|range|for|go|defer|true|false",
    py: "import|from|def|return|if|else|raise|try|except|with|as|None|True|False|class|for|in",
    sh: "curl|export|echo|npm|npx|go|docker|grpcurl",
    json: "true|false|null",
  };

  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function guess(text, label) {
    var l = (label || "").toLowerCase();
    if (/curl|shell|bash/.test(l)) return "sh";
    if (/event|json/.test(l)) return "json";
    if (/go\b/.test(l)) return "go";
    if (/python/.test(l)) return "py";
    if (/express|node|sdk|browser|react|js|ts/.test(l)) return "js";
    var t = text.trimStart();
    if (/^(curl|#|grpcurl|npm|docker|go run)/.test(t)) return "sh";
    if (/^(POST|GET|PUT|PATCH|DELETE) \//.test(t)) return "http";
    if (/^[{\[]/.test(t)) return "json";
    if (/^(package|jwks, _ :=|jwks, err :=|import \(|token, err)/.test(t) || /:= /.test(t)) return "go";
    if (/^(import jwt|def )/.test(t)) return "py";
    return "js";
  }

  var RULES = [
    ["tok-comment", /^(\/\/[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/)/],
    ["tok-str", /^("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`)/],
    ["tok-var", /^\$[A-Za-z_][A-Za-z0-9_]*/],
    ["tok-num", /^\b\d+(?:\.\d+)?\b/],
    ["tok-flag", /^(?:--?[A-Za-z][\w-]*)/],
    ["word", /^[A-Za-z_][\w]*/],
  ];

  function highlight(text, lang) {
    var kw = new RegExp("^(?:" + (KW[lang] || KW.js) + ")$");
    var out = "", i = 0, n = text.length, lineStart = true;
    while (i < n) {
      var rest = text.slice(i), m = null, cls = null;
      if (lang === "http" && lineStart && (m = /^(POST|GET|PUT|PATCH|DELETE|HTTP\/1\.1)\b[^\n]*/.exec(rest))) {
        out += '<span class="tok-kw">' + esc(m[1]) + "</span>" + esc(m[0].slice(m[1].length));
        i += m[0].length; lineStart = false; continue;
      }
      if (lang === "http" && lineStart && (m = /^[A-Za-z][\w-]*(?=:)/.exec(rest))) {
        out += '<span class="tok-prop">' + esc(m[0]) + "</span>"; i += m[0].length; lineStart = false; continue;
      }
      for (var r = 0; r < RULES.length; r++) {
        m = RULES[r][1].exec(rest);
        if (!m) continue;
        cls = RULES[r][0];
        // "#" starts a comment only in shell/python and at a word boundary.
        if (cls === "tok-comment" && m[0][0] === "#" && !(lang === "sh" || lang === "py") ) { m = null; continue; }
        if (cls === "tok-comment" && m[0][0] === "#" && i > 0 && /\S/.test(text[i - 1])) { m = null; continue; }
        // "//" is a comment only in JS and Go, and never inside a URL ("https://").
        if (cls === "tok-comment" && m[0][0] === "/" && m[0][1] === "/" && (!(lang === "js" || lang === "go") || (i > 0 && text[i - 1] === ":"))) { m = null; continue; }
        if (cls === "tok-flag" && (lang !== "sh" || (i > 0 && /[\w-]/.test(text[i - 1])))) { m = null; continue; }
        if (cls === "tok-var" && lang !== "sh") { m = null; continue; }
        break;
      }
      if (!m) {
        out += esc(text[i]);
        lineStart = text[i] === "\n" ? true : lineStart && /\s/.test(text[i]);
        i++;
        continue;
      }
      var tok = m[0], after = text.slice(i + tok.length);
      if (cls === "word") {
        if (kw.test(tok)) cls = "tok-kw";
        else if (/^\s*\(/.test(after)) cls = "tok-fn";
        else if (/^\s*:(?!=)/.test(after) && lang !== "sh" && lang !== "py") cls = "tok-prop";
        else cls = null;
      } else if (cls === "tok-str" && lang === "json" && /^\s*:/.test(after)) {
        cls = "tok-prop";
      }
      out += cls ? '<span class="' + cls + '">' + esc(tok) + "</span>" : esc(tok);
      i += tok.length;
      lineStart = false;
    }
    return out;
  }

  blocks.forEach(function (pre) {
    var label = pre.querySelector(".code-label");
    if (label) label.remove();
    var text = pre.textContent;
    var lang = pre.dataset.lang || guess(text, label && label.textContent);
    pre.innerHTML = highlight(text, lang);
    pre.classList.add("code-sample");
    if (label) pre.insertBefore(label, pre.firstChild);
  });
})();

// Full screen toggle for the email preview.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-fullscreen]");
  if (!btn) return;
  var el = document.getElementById(btn.getAttribute("data-fullscreen"));
  if (document.fullscreenElement) document.exitFullscreen();
  else if (el.requestFullscreen) el.requestFullscreen();
});
document.addEventListener("fullscreenchange", function () {
  document.querySelectorAll("[data-fullscreen]").forEach(function (b) {
    b.textContent = document.fullscreenElement ? "Exit full screen" : "Full screen";
  });
});
