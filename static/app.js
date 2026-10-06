(() => {
  const $ = (id) => document.getElementById(id);
  const COLORS = ["--l0", "--l1", "--l2", "--l3", "--l4"];
  const LEVELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"];
  const pw = $("pw");
  let timer = null, reqId = 0;

  const post = (url, body) =>
    fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      cache: "no-store",
      body: JSON.stringify(body),
    }).then(async (r) => {
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Request failed");
      return data;
    });

  const color = (idx) => getComputedStyle(document.documentElement).getPropertyValue(COLORS[idx]);

  function fillList(el, items) {
    el.replaceChildren(...items.map((t) => {
      const li = document.createElement("li");
      li.textContent = t;               // textContent: never interpret as HTML
      return li;
    }));
  }

  function render(r) {
    const idx = LEVELS.indexOf(r.level);
    $("result").hidden = false;
    $("error").hidden = true;
    const lvl = $("level");
    lvl.textContent = r.level;
    lvl.style.color = color(idx);
    [...$("gauge").children].forEach((seg, i) => {
      seg.style.background = i <= idx ? color(idx) : "";
    });
    $("gauge").setAttribute("aria-label", `Strength: ${r.level}`);
    $("score").textContent = r.score;
    $("crack").textContent = r.crack_time;
    $("entropy").textContent = r.entropy_bits;
    document.querySelectorAll("#checks li").forEach((li) =>
      li.classList.toggle("pass", !!r.checks[li.dataset.check]));
    fillList($("findings"), r.findings.length ? r.findings : ["Nothing risky detected."]);
    fillList($("suggestions"), r.suggestions);
  }

  function analyze() {
    const value = pw.value;
    if (!value) { $("result").hidden = true; return; }
    const id = ++reqId;
    post("/api/analyze", { password: value })
      .then((r) => { if (id === reqId) render(r); })
      .catch((e) => { $("error").textContent = e.message; $("error").hidden = false; });
  }

  pw.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(analyze, 150); });

  $("toggle").addEventListener("click", (e) => {
    const show = pw.type === "password";
    pw.type = show ? "text" : "password";
    e.target.textContent = show ? "Hide" : "Show";
    e.target.setAttribute("aria-pressed", show);
  });

  document.querySelectorAll(".chip").forEach((b) =>
    b.addEventListener("click", () => { pw.value = b.dataset.demo; analyze(); }));

  // ----- generator -----
  $("len").addEventListener("input", (e) => ($("len-val").textContent = e.target.value));

  $("gen").addEventListener("click", () => {
    post("/api/generate", { length: +$("len").value, symbols: $("sym").checked })
      .then((r) => {
        $("gen-out").hidden = false;
        $("gen-pw").textContent = r.password;
        $("gen-level").textContent = r.level;
        $("gen-score").textContent = r.score;
        $("gen-crack").textContent = r.crack_time;
      })
      .catch((e) => { $("error").textContent = e.message; $("error").hidden = false; });
  });

  $("copy").addEventListener("click", async (e) => {
    try { await navigator.clipboard.writeText($("gen-pw").textContent); e.target.textContent = "Copied"; }
    catch { e.target.textContent = "Press Ctrl+C"; }
    setTimeout(() => (e.target.textContent = "Copy"), 1500);
  });

  $("use").addEventListener("click", () => { pw.value = $("gen-pw").textContent; analyze(); pw.focus(); });
})();
