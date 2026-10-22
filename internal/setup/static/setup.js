// Warden setup wizard: connection tests, secret generation, show/hide.
(function () {
  var form = document.getElementById("setup-form");
  if (!form) return;

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
      var out = form.querySelector('[data-result="' + btn.dataset.check + '"]');
      out.className = "check-result";
      out.textContent = "Testing…";
      btn.disabled = true;
      fetch("/check/" + btn.dataset.check, { method: "POST", body: new URLSearchParams(new FormData(form)) })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          out.className = "check-result " + (d.ok ? "check-ok" : "check-err");
          out.textContent = d.message;
        })
        .catch(function () {
          out.className = "check-result check-err";
          out.textContent = "The setup server did not answer.";
        })
        .finally(function () { btn.disabled = false; });
    }
  });
})();
