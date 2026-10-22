// Warden setup wizard. Without JavaScript the page is one long form; with it,
// an onboarding flow: one step at a time, a progress bar, and each connection
// tested when you press Continue.
(function () {
  var form = document.getElementById("setup-form");
  if (!form) return;

  function test(kind) {
    var out = form.querySelector('[data-result="' + kind + '"]');
    out.className = "check-result";
    out.textContent = "Testing…";
    return fetch("/check/" + kind, { method: "POST", body: new URLSearchParams(new FormData(form)) })
      .then(function (r) { return r.json(); })
      .catch(function () { return { ok: false, message: "The setup server did not answer." }; })
      .then(function (d) {
        out.className = "check-result " + (d.ok ? "check-ok" : "check-err");
        out.textContent = d.message;
        return d.ok;
      });
  }

  form.addEventListener("click", function (e) {
    var btn = e.target.closest("button");
    if (!btn) return;

    if (btn.dataset.toggle) {
      var input = document.getElementById(btn.dataset.toggle);
      var hidden = input.type === "password";
      input.type = hidden ? "text" : "password";
      btn.textContent = hidden ? "Hide" : "Show";
      return;
    }

    if (btn.dataset.generate) {
      btn.disabled = true;
      fetch("/generate/" + btn.dataset.generate, { method: "POST" })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var target = document.getElementById(btn.dataset.target);
          target.value = d.value;
          target.type = "text";
        })
        .finally(function () { btn.disabled = false; });
      return;
    }

    if (btn.dataset.check) {
      btn.disabled = true;
      test(btn.dataset.check).finally(function () { btn.disabled = false; });
    }
  });

  // ---------------------------------------------------------------------
  // Onboarding flow. Validation errors from the server show the whole form.
  if (document.querySelector(".notice-err")) return;
  var steps = Array.prototype.slice.call(form.querySelectorAll("[data-step]"));
  if (steps.length < 2) return;

  var bar = document.getElementById("onboard-bar");
  var fill = document.getElementById("onboard-fill");
  var count = document.getElementById("onboard-count");
  var submitRow = form.querySelector(".onboard-submit");
  var current = 0;

  document.body.classList.add("onboarding");
  bar.hidden = false;
  submitRow.hidden = true;
  steps.forEach(function (s, i) {
    var nav = s.querySelector(".onboard-nav");
    if (nav) nav.hidden = false;
    if (i === steps.length - 1) {
      var next = s.querySelector("[data-next]");
      if (next) next.textContent = "Review .env";
    }
  });

  function show(i) {
    current = Math.max(0, Math.min(i, steps.length - 1));
    steps.forEach(function (s, j) { s.hidden = j !== current; });
    fill.style.width = Math.round((current / (steps.length - 1)) * 100) + "%";
    count.textContent = current === 0 ? "" : "Step " + current + " of " + (steps.length - 1) + " · " + steps[current].dataset.step;
    var first = steps[current].querySelector("input:not([type=hidden]):not([type=radio]):not([type=checkbox]), input[type=radio]:checked");
    if (first && current > 0) first.focus({ preventScroll: true });
    window.scrollTo({ top: 0 });
    try { history.replaceState(null, "", "#" + (steps[current].id || "welcome")); } catch (e) { /* file:// */ }
  }

  function advance() {
    if (current === steps.length - 1) {
      form.requestSubmit ? form.requestSubmit() : form.submit();
      return;
    }
    show(current + 1);
  }

  form.addEventListener("click", function (e) {
    var btn = e.target.closest("button");
    if (!btn) return;
    var step = steps[current];
    if (btn.hasAttribute("data-back")) {
      show(current - 1);
    } else if (btn.hasAttribute("data-skip-test")) {
      advance();
    } else if (btn.hasAttribute("data-next")) {
      var kind = step.dataset.check;
      if (!kind) return advance();
      btn.disabled = true;
      test(kind).then(function (ok) {
        btn.disabled = false;
        if (ok) return setTimeout(advance, 450);
        // Failed: stay, show why. Optional steps can still be skipped.
        var skip = step.querySelector("[data-skip-test]");
        if (skip) skip.textContent = step.hasAttribute("data-required") ? "Continue without a working connection" : "Skip for now";
      });
    }
  });

  // Enter moves forward instead of submitting the whole form early.
  form.addEventListener("keydown", function (e) {
    if (e.key === "Enter" && e.target.tagName === "INPUT" && e.target.type !== "checkbox" && e.target.type !== "radio") {
      e.preventDefault();
      var next = steps[current].querySelector("[data-next]");
      if (next) next.click();
    }
  });

  var start = steps.findIndex(function (s) { return location.hash && "#" + s.id === location.hash; });
  show(start > 0 ? start : 0);
})();
