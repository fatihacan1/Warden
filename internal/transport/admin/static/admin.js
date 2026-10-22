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
