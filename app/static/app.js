(function () {
  "use strict";

  // ---------------- State & Helpers ----------------
  const state = { clusters: [], frontends: [], backends: [], certs: [], providers: {} };
  const App = {};
  window.App = App;

  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = (v) =>
    String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  const js = (v) => String(v == null ? "" : v).replace(/\\/g, "\\\\").replace(/'/g, "\\'");

  async function api(path, method, body) {
    const opts = { method: method || "GET", headers: {} };
    const token = localStorage.getItem("hg_token");
    if (token) opts.headers["Authorization"] = "Bearer " + token;
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    if (res.status === 401) {
      showLogin();
      throw new Error("Nicht authentifiziert");
    }
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (e) {
      data = text;
    }
    if (!res.ok) {
      const detail =
        data && data.detail ? data.detail : typeof data === "string" ? data : res.statusText;
      throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
    }
    return data;
  }

  function toast(msg, type) {
    const el = document.createElement("div");
    el.className = "toast " + (type || "ok");
    el.textContent = msg;
    $("#toast-root").appendChild(el);
    setTimeout(() => el.classList.add("show"), 10);
    setTimeout(() => {
      el.classList.remove("show");
      setTimeout(() => el.remove(), 300);
    }, 6000);
  }

  function statusBadge(status) {
    const s = String(status || "").toUpperCase();
    let cls = "muted";
    if (["UP", "OPEN", "ACTIVE", "READY", "ONLINE"].includes(s)) cls = "ok";
    else if (["DRAIN", "NOLB", "ISSUING", "PENDING"].includes(s)) cls = "warn";
    else if (["DOWN", "MAINT", "ERROR", "OFFLINE"].includes(s)) cls = "err";
    return `<span class="badge ${cls}">${esc(status || "?")}</span>`;
  }

  function showLogin() {
    $("#login-view").classList.remove("hidden");
    $("#app").classList.add("hidden");
  }

  function showApp() {
    $("#login-view").classList.add("hidden");
    $("#app").classList.remove("hidden");
  }

  // ---------------- Modal ----------------
  function openModal(title, bodyHtml, submitLabel) {
    const root = $("#modal-root");
    root.innerHTML = `
      <div class="modal-overlay">
        <div class="modal">
          <div class="modal-head"><h3>${esc(title)}</h3>
            <button type="button" class="btn ghost" data-close>✕</button></div>
          <form id="modal-form">
            <div class="modal-body">${bodyHtml}</div>
            <div class="modal-foot">
              <button type="button" class="btn ghost" data-close>Abbrechen</button>
              <button type="submit" class="btn primary">${esc(submitLabel || "Speichern")}</button>
            </div>
          </form>
        </div>
      </div>`;
    const close = () => {
      root.innerHTML = "";
    };
    $$("[data-close]", root).forEach((b) => (b.onclick = close));
    $(".modal-overlay", root).addEventListener("mousedown", (e) => {
      if (e.target.classList.contains("modal-overlay")) close();
    });
    const form = $("#modal-form", root);
    // Zeilen-Löschbuttons in dynamischen Editoren
    form.addEventListener("click", (e) => {
      const del = e.target.closest(".del-row");
      if (del) {
        e.preventDefault();
        del.closest("tr").remove();
      }
    });
    return { close, form };
  }

  function confirmModal(html, onYes) {
    const { close, form } = openModal("Bestätigen", `<p>${html}</p>`, "Löschen");
    form.onsubmit = async (e) => {
      e.preventDefault();
      try {
        await onYes();
        close();
        toast("Gelöscht");
        router();
      } catch (err) {
        toast(err.message, "err");
      }
    };
  }

  // ---------------- Router ----------------
  const routes = {};
  async function router() {
    const name = (location.hash.replace(/^#\//, "") || "dashboard").split("?")[0];
    $$("nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === name));
    const view = routes[name] || routes.dashboard;
    const content = $("#content");
    content.innerHTML = '<div class="loading">Lade…</div>';
    try {
      await view(content);
      applyRoleRestrictions(content);
    } catch (e) {
      if (e.message !== "Nicht authentifiziert")
        content.innerHTML = `<div class="error-text">${esc(e.message)}</div>`;
    }
  }
  window.addEventListener("hashchange", router);

  function applyRoleRestrictions(root) {
    if (!state.user) return;
    if (state.user.role !== "admin") {
      $$("nav a[data-admin]").forEach((a) => (a.style.display = "none"));
    }
    if (state.user.role === "viewer") {
      $$("button", root).forEach((b) => {
        const oc = b.getAttribute("onclick") || "";
        const mutating =
          /edit|delete|Deploy|deploy|renew|toggle|Rollback|rollback|serverState|clearTable|mapEntry|keepalived/i.test(oc) ||
          b.classList.contains("danger") ||
          b.classList.contains("primary");
        if (mutating) b.style.display = "none";
      });
      $$('input[type="checkbox"][onchange]', root).forEach((i) => (i.disabled = true));
    }
  }

  function allNodes() {
    const out = [];
    (state.clusters || []).forEach((c) =>
      (c.nodes || []).forEach((n) => out.push(Object.assign({}, n, { cluster_name: c.name })))
    );
    return out;
  }

  function nodeOptions(selectedId) {
    return allNodes()
      .map(
        (n) =>
          `<option value="${n.id}" ${n.id === selectedId ? "selected" : ""}>${esc(
            n.cluster_name
          )} / ${esc(n.name)} (${esc(n.host)})</option>`
      )
      .join("");
  }

  function diffHtml(text) {
    return esc(text)
      .split("\n")
      .map((line) => {
        if (line.startsWith("+") && !line.startsWith("+++"))
          return `<span class="diff-add">${line}</span>`;
        if (line.startsWith("-") && !line.startsWith("---"))
          return `<span class="diff-del">${line}</span>`;
        if (line.startsWith("@@")) return `<span class="diff-hunk">${line}</span>`;
        return line;
      })
      .join("\n");
  }

  function clusterOptions(selectedId) {
    return state.clusters
      .map(
        (c) =>
          `<option value="${c.id}" ${c.id === selectedId ? "selected" : ""}>${esc(c.name)}</option>`
      )
      .join("");
  }

  function certOptions(selectedId) {
    return (
      '<option value="">–</option>' +
      state.certs
        .map(
          (c) =>
            `<option value="${c.id}" ${c.id === selectedId ? "selected" : ""}>${esc(c.name)} (${esc(
              (c.domains || []).join(", ")
            )})</option>`
        )
        .join("")
    );
  }

  function backendNameOptions(clusterId, selectedName) {
    return (
      '<option value="">–</option>' +
      state.backends
        .filter((b) => b.cluster_id === clusterId)
        .map(
          (b) =>
            `<option value="${esc(b.name)}" ${b.name === selectedName ? "selected" : ""}>${esc(
              b.name
            )}</option>`
        )
        .join("")
    );
  }

  // ---------------- Dashboard ----------------
  routes.dashboard = async function (el) {
    const clusters = await api("/api/overview");
    el.innerHTML =
      `<div class="page-head"><h2>Dashboard</h2>
        <button class="btn" onclick="location.reload()">Aktualisieren</button></div>` +
      (clusters.length
        ? clusters
            .map(
              (c) => `
        <div class="card">
          <div class="card-head"><h3>${esc(c.name)}</h3><span class="muted">${esc(
                c.description
              )}</span></div>
          <div class="nodes">
            ${c.nodes
              .map(
                (n) => `
              <div class="node-chip">
                <span class="dot ${n.online ? "ok" : "err"}"></span>
                <b>${esc(n.name)}</b><span class="muted">${esc(n.host)}</span>
                ${
                  n.online
                    ? `<span class="muted">HAProxy ${esc(n.info.Version || "?")} · Uptime ${esc(
                        n.info.Uptime || "?"
                      )}</span>`
                    : `<span class="error-text">${esc(n.error || "offline")}</span>`
                }
                <button class="btn sm" onclick="App.showMetrics(${n.id}, '${js(n.name)}')">Metriken</button>
              </div>`
              )
              .join("")}
          </div>
          <div id="stat-${c.id}"></div>
        </div>`
            )
            .join("")
        : '<div class="card muted">Noch keine Cluster angelegt – weiter zu <a href="#/clusters">Cluster &amp; Nodes</a>.</div>');
    for (const c of clusters) {
      const online = c.nodes.find((n) => n.online);
      if (online) loadStatTable($(`#stat-${c.id}`), online);
    }
  };

  async function loadStatTable(container, node) {
    const res = await api(`/api/stats/nodes/${node.id}/stat`);
    if (!res.ok) {
      container.innerHTML = `<div class="error-text">${esc(res.error)}</div>`;
      return;
    }
    const rows = res.rows.filter((r) =>
      ["frontend", "backend", "server", "listen"].includes((r.type || "").toLowerCase())
    );
    container.innerHTML = `
      <h4>Live-Status (Node: ${esc(node.name)})</h4>
      <table class="data">
        <thead><tr><th>Proxy</th><th>Name</th><th>Typ</th><th>Status</th><th>Check</th><th>Sessions</th><th></th></tr></thead>
        <tbody>
          ${rows
            .map(
              (r) => `
            <tr>
              <td>${esc(r.pxname)}</td><td>${esc(r.svname)}</td><td>${esc(r.type)}</td>
              <td>${statusBadge(r.status)}</td><td>${esc(r.check_status || "-")}</td>
              <td>${esc(r.scur)}</td>
              <td>${(r.type || "").toLowerCase() === "server" ? serverButtons(node.id, r) : ""}</td>
            </tr>`
            )
            .join("")}
        </tbody>
      </table>`;
  }

  function serverButtons(nodeId, r) {
    const st = String(r.status || "").toUpperCase();
    const px = js(r.pxname);
    const sv = js(r.svname);
    let out = "";
    if (st !== "UP")
      out += `<button class="btn sm ok" onclick="App.serverState(${nodeId}, '${px}', '${sv}', 'ready')">Aktivieren</button>`;
    if (st === "UP")
      out += `<button class="btn sm warn" onclick="App.serverState(${nodeId}, '${px}', '${sv}', 'drain')">Drain</button>`;
    if (st !== "MAINT")
      out += `<button class="btn sm err" onclick="App.serverState(${nodeId}, '${px}', '${sv}', 'maint')">Wartung</button>`;
    return out;
  }

  App.serverState = async function (nodeId, backend, server, stateName) {
    try {
      await api(`/api/stats/nodes/${nodeId}/server-state`, "POST", {
        backend, server, state: stateName,
      });
      toast(`Server ${server}: ${stateName}`);
      router();
    } catch (e) {
      toast(e.message, "err");
    }
  };

  // ---------------- Cluster & Nodes ----------------
  routes.clusters = async function (el) {
    state.clusters = await api("/api/clusters");
    el.innerHTML =
      `<div class="page-head"><h2>Cluster &amp; Nodes</h2>
        <button class="btn primary" onclick="App.editCluster()">+ Neuer Cluster</button></div>` +
      (state.clusters.length
        ? state.clusters
            .map(
              (c) => `
        <div class="card">
          <div class="card-head">
            <h3>${esc(c.name)}</h3>
            <div>
              <button class="btn sm" onclick="App.editCluster(${c.id})">Bearbeiten</button>
              <button class="btn sm" onclick="App.editNode(null, ${c.id})">+ Node</button>
              <button class="btn sm danger" onclick="App.deleteCluster(${c.id})">Löschen</button>
            </div>
          </div>
          <div class="muted">${esc(c.description)}</div>
          <table class="data">
            <thead><tr><th>Node</th><th>Host</th><th>Modus</th><th>Socket</th><th></th></tr></thead>
            <tbody>
              ${c.nodes
                .map(
                  (n) => `
                <tr>
                  <td>${esc(n.name)}</td>
                  <td>${esc(n.host)}${n.is_local ? "" : ":" + (n.ssh_port || 22)}</td>
                  <td>${n.is_local ? "lokal" : "SSH (" + esc(n.ssh_user) + ")"}</td>
                  <td>${esc(n.socket_type)}</td>
                  <td>
                    <button class="btn sm" onclick="App.testNode(${n.id}, this)">Test</button>
                    <button class="btn sm" onclick="App.editNode(${n.id})">Bearbeiten</button>
                    <button class="btn sm danger" onclick="App.deleteNode(${n.id})">Löschen</button>
                  </td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`
            )
            .join("")
        : '<div class="card muted">Noch keine Cluster vorhanden.</div>');
  };

  App.editCluster = function (id) {
    const c = id ? state.clusters.find((x) => x.id === id) : null;
    const { close, form } = openModal(
      c ? "Cluster bearbeiten" : "Neuer Cluster",
      `
      <label>Name<input name="name" required value="${esc(c ? c.name : "")}"></label>
      <label>Beschreibung<input name="description" value="${esc(c ? c.description : "")}"></label>
      <label>Zusätzliche global-Zeilen (optional)
        <textarea name="global_extra" rows="3" placeholder="z. B. tune.ssl.default-dh-param 2048">${esc(
          c ? c.global_extra : ""
        )}</textarea></label>
      <label>Zusätzliche defaults-Zeilen (optional)
        <textarea name="defaults_extra" rows="3" placeholder="z. B. option forwardfor">${esc(
          c ? c.defaults_extra : ""
        )}</textarea></label>`
    );
    form.onsubmit = async (e) => {
      e.preventDefault();
      const body = Object.fromEntries(new FormData(form).entries());
      try {
        if (c) await api(`/api/clusters/${c.id}`, "PUT", body);
        else await api("/api/clusters", "POST", body);
        close();
        toast("Gespeichert");
        router();
      } catch (err) {
        toast(err.message, "err");
      }
    };
  };

  App.deleteCluster = (id) =>
    confirmModal(
      "Cluster inkl. Nodes, Frontends und Backends wirklich löschen?",
      async () => api(`/api/clusters/${id}`, "DELETE")
    );

  App.deleteNode = (id) =>
    confirmModal("Node wirklich löschen?", async () => api(`/api/nodes/${id}`, "DELETE"));

  App.testNode = async function (id, btn) {
    btn.disabled = true;
    btn.textContent = "…";
    try {
      const res = await api(`/api/nodes/${id}/test`, "POST");
      if (res.ok) toast(`OK – HAProxy ${res.version}, Uptime ${res.uptime}`);
      else toast("Fehler: " + res.error, "err");
    } catch (e) {
      toast(e.message, "err");
    }
    btn.disabled = false;
    btn.textContent = "Test";
  };

  function findNode(id) {
    for (const c of state.clusters) {
      const n = c.nodes.find((x) => x.id === id);
      if (n) return n;
    }
    return null;
  }

  App.editNode = function (id, clusterId) {
    const n = id ? findNode(id) : null;
    const cid = clusterId || (n ? n.cluster_id : (state.clusters[0] || {}).id);
    const { close, form } = openModal(
      n ? "Node bearbeiten" : "Neuer Node",
      `
      <label>Cluster<select name="cluster_id">${clusterOptions(cid)}</select></label>
      <div class="row">
        <label>Name<input name="name" required value="${esc(n ? n.name : "")}"></label>
        <label>Host / IP<input name="host" required value="${esc(n ? n.host : "")}"></label>
      </div>
      <label class="check"><input type="checkbox" name="is_local" ${n && n.is_local ? "checked" : ""}>
        Läuft lokal in diesem Container</label>
      <div class="row">
        <label>SSH-Port<input name="ssh_port" type="number" value="${n ? n.ssh_port : 22}"></label>
        <label>SSH-Benutzer<input name="ssh_user" value="${esc(n ? n.ssh_user : "root")}"></label>
      </div>
      <label>SSH-Private-Key (optional${n && n.has_key ? ", vorhanden – leer lassen zum Behalten" : ""})
        <textarea name="ssh_key" rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label>
      <label>SSH-Passwort / Key-Passphrase (optional${n && n.has_password ? ", vorhanden" : ""})
        <input name="ssh_password" type="password" autocomplete="new-password"></label>
      <div class="row">
        <label>Config-Pfad<input name="config_path" value="${esc(
          n ? n.config_path : "/etc/haproxy/haproxy.cfg"
        )}"></label>
        <label>Zertifikats-Verzeichnis<input name="cert_dir" value="${esc(
          n ? n.cert_dir : "/etc/haproxy/certs"
        )}"></label>
      </div>
      <div class="row">
        <label>Runtime-Socket-Typ
          <select name="socket_type">
            <option value="ssh" ${!n || n.socket_type === "ssh" ? "selected" : ""}>via SSH (socat)</option>
            <option value="unix" ${n && n.socket_type === "unix" ? "selected" : ""}>Unix-Socket (lokal)</option>
            <option value="tcp" ${n && n.socket_type === "tcp" ? "selected" : ""}>TCP</option>
          </select></label>
        <label>Socket-Pfad<input name="socket_path" value="${esc(
          n ? n.socket_path : "/var/run/haproxy/admin.sock"
        )}"></label>
      </div>
      <div class="row">
        <label>Socket-Host (nur TCP)<input name="socket_host" value="${esc(
          n ? n.socket_host : ""
        )}"></label>
        <label>Socket-Port (nur TCP)<input name="socket_port" type="number" value="${
          n ? n.socket_port : 0
        }"></label>
      </div>
      <label>Reload-Kommando (leer = automatisch)
        <input name="reload_cmd" list="reload-presets" value="${esc(n ? n.reload_cmd : "")}">
        <datalist id="reload-presets">
          <option value="systemctl reload haproxy"></option>
          <option value="haproxy -D -f /etc/haproxy/haproxy.cfg -sf $(pidof haproxy)"></option>
          <option value="docker kill -s HUP haproxy"></option>
          <option value="sigusr2"></option>
        </datalist></label>`
    );
    form.onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const body = Object.fromEntries(fd.entries());
      body.is_local = fd.get("is_local") === "on";
      body.ssh_port = parseInt(body.ssh_port, 10) || 22;
      body.socket_port = parseInt(body.socket_port, 10) || 0;
      body.cluster_id = parseInt(body.cluster_id, 10);
      try {
        if (n) await api(`/api/nodes/${n.id}`, "PUT", body);
        else await api("/api/nodes", "POST", body);
        close();
        toast("Gespeichert");
        router();
      } catch (err) {
        toast(err.message, "err");
      }
    };
  };

  // ---------------- Frontends ----------------
  routes.frontends = async function (el) {
    [state.clusters, state.frontends, state.backends, state.certs] = await Promise.all([
      api("/api/clusters"),
      api("/api/frontends"),
      api("/api/backends"),
      api("/api/certificates"),
    ]);
    const certName = (id) => {
      const c = state.certs.find((x) => x.id === id);
      return c ? c.name : "-";
    };
    el.innerHTML =
      `<div class="page-head"><h2>Frontends</h2>
        <button class="btn primary" onclick="App.editFrontend()">+ Neues Frontend</button></div>` +
      (state.frontends.length
        ? state.clusters
            .map((c) => {
              const fes = state.frontends.filter((f) => f.cluster_id === c.id);
              if (!fes.length) return "";
              return `
        <div class="card">
          <div class="card-head"><h3>${esc(c.name)}</h3></div>
          <table class="data">
            <thead><tr><th>Name</th><th>Bind</th><th>Mode</th><th>SSL</th><th>Default-Backend</th><th></th></tr></thead>
            <tbody>
              ${fes
                .map((f) => {
                  const be = state.backends.find((b) => b.id === f.default_backend_id);
                  return `
                <tr>
                  <td>${esc(f.name)}</td>
                  <td>${esc(f.bind_ip)}:${f.port}</td>
                  <td>${esc(f.mode)}</td>
                  <td>${f.use_ssl ? esc(certName(f.cert_id)) : "-"}</td>
                  <td>${be ? esc(be.name) : "-"}</td>
                  <td>
                    <button class="btn sm" onclick="App.editFrontend(${f.id})">Bearbeiten</button>
                    <button class="btn sm danger" onclick="App.deleteFrontend(${f.id})">Löschen</button>
                  </td>
                </tr>`;
                })
                .join("")}
            </tbody>
          </table>
        </div>`;
            })
            .join("")
        : '<div class="card muted">Noch keine Frontends vorhanden.</div>');
  };

  function aclRow(a) {
    a = a || {};
    return `<tr>
      <td><input class="acl-name" placeholder="host_api" value="${esc(a.name || "")}"></td>
      <td><input class="acl-crit" placeholder="hdr(host) -i" value="${esc(a.criterion || "")}"></td>
      <td><input class="acl-value" placeholder="api.example.com" value="${esc(a.value || "")}"></td>
      <td class="c"><button type="button" class="btn sm danger del-row">✕</button></td>
    </tr>`;
  }

  function ruleRow(clusterId, rule) {
    rule = rule || {};
    return `<tr>
      <td><select class="rule-backend">${backendNameOptions(clusterId, rule.backend)}</select></td>
      <td><input class="rule-cond" placeholder="host_api" value="${esc(rule.condition || "")}"></td>
      <td class="c"><button type="button" class="btn sm danger del-row">✕</button></td>
    </tr>`;
  }

  App.editFrontend = function (id) {
    if (!state.clusters.length) {
      toast("Bitte zuerst einen Cluster anlegen", "err");
      return;
    }
    const f = id ? state.frontends.find((x) => x.id === id) : null;
    const acls = f ? JSON.parse(f.acls || "[]") : [];
    const rules = f ? JSON.parse(f.rules || "[]") : [];
    const cid0 = f ? f.cluster_id : state.clusters[0].id;
    const { close, form } = openModal(
      f ? "Frontend bearbeiten" : "Neues Frontend",
      `
      <label>Cluster<select name="cluster_id" id="fe-cluster">${clusterOptions(cid0)}</select></label>
      <div class="row">
        <label>Name<input name="name" required value="${esc(f ? f.name : "")}"></label>
        <label>Bind-IP<input name="bind_ip" value="${esc(f ? f.bind_ip : "*")}"></label>
        <label style="max-width:110px">Port<input name="port" type="number" required value="${
          f ? f.port : 443
        }"></label>
      </div>
      <div class="row">
        <label>Mode
          <select name="mode">
            <option value="http" ${!f || f.mode === "http" ? "selected" : ""}>http</option>
            <option value="tcp" ${f && f.mode === "tcp" ? "selected" : ""}>tcp</option>
          </select></label>
        <label class="check"><input type="checkbox" name="use_ssl" id="fe-ssl" ${
          f && f.use_ssl ? "checked" : ""
        }> SSL / TLS</label>
        <label class="check"><input type="checkbox" name="ssl_redirect" ${
          f && f.ssl_redirect ? "checked" : ""
        }> HTTP→HTTPS Redirect</label>
      </div>
      <label>Zertifikat<select name="cert_id">${certOptions(f ? f.cert_id : null)}</select></label>
      <label>Default-Backend<select name="default_backend_id" id="fe-backend"></select></label>
      <h4>ACLs</h4>
      <table class="data"><thead><tr><th>Name</th><th>Kriterium</th><th>Wert</th><th></th></tr></thead>
        <tbody id="acl-rows"></tbody></table>
      <button type="button" class="btn sm" id="add-acl">+ ACL</button>
      <h4>use_backend-Regeln</h4>
      <table class="data"><thead><tr><th>Backend</th><th>Bedingung (ACL)</th><th></th></tr></thead>
        <tbody id="rule-rows"></tbody></table>
      <button type="button" class="btn sm" id="add-rule">+ Regel</button>
      <h4>Zusätzliche Zeilen</h4>
      <textarea name="extra" rows="2">${esc(f ? f.extra : "")}</textarea>`
    );

    const backendSel = $("#fe-backend", form);
    const fillBackends = () => {
      const cid = parseInt($("#fe-cluster", form).value, 10);
      backendSel.innerHTML =
        '<option value="">–</option>' +
        state.backends
          .filter((b) => b.cluster_id === cid)
          .map(
            (b) =>
              `<option value="${b.id}" ${f && f.default_backend_id === b.id ? "selected" : ""}>${esc(
                b.name
              )}</option>`
          )
          .join("");
    };
    fillBackends();
    $("#fe-cluster", form).onchange = () => {
      fillBackends();
      $("#rule-rows", form).innerHTML = "";
    };

    const aclBody = $("#acl-rows", form);
    const ruleBody = $("#rule-rows", form);
    acls.forEach((a) => aclBody.insertAdjacentHTML("beforeend", aclRow(a)));
    if (!acls.length) aclBody.innerHTML = aclRow();
    rules.forEach((r) => ruleBody.insertAdjacentHTML("beforeend", ruleRow(cid0, r)));
    if (!rules.length) ruleBody.innerHTML = ruleRow(cid0);
    $("#add-acl", form).onclick = () => aclBody.insertAdjacentHTML("beforeend", aclRow());
    $("#add-rule", form).onclick = () =>
      ruleBody.insertAdjacentHTML(
        "beforeend",
        ruleRow(parseInt($("#fe-cluster", form).value, 10))
      );

    form.onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const aclList = $$("#acl-rows tr", form)
        .map((tr) => ({
          name: $(".acl-name", tr).value.trim(),
          criterion: $(".acl-crit", tr).value.trim(),
          value: $(".acl-value", tr).value.trim(),
        }))
        .filter((a) => a.name && a.criterion);
      const ruleList = $$("#rule-rows tr", form)
        .map((tr) => ({
          backend: $(".rule-backend", tr).value,
          condition: $(".rule-cond", tr).value.trim(),
        }))
        .filter((r) => r.backend && r.condition);
      const body = {
        cluster_id: parseInt(fd.get("cluster_id"), 10),
        name: fd.get("name").trim(),
        bind_ip: fd.get("bind_ip").trim() || "*",
        port: parseInt(fd.get("port"), 10),
        mode: fd.get("mode"),
        use_ssl: fd.get("use_ssl") === "on",
        cert_id: fd.get("cert_id") ? parseInt(fd.get("cert_id"), 10) : null,
        ssl_redirect: fd.get("ssl_redirect") === "on",
        default_backend_id: fd.get("default_backend_id")
          ? parseInt(fd.get("default_backend_id"), 10)
          : null,
        acls: aclList,
        rules: ruleList,
        extra: fd.get("extra") || "",
      };
      try {
        if (f) await api(`/api/frontends/${f.id}`, "PUT", body);
        else await api("/api/frontends", "POST", body);
        close();
        toast("Gespeichert");
        router();
      } catch (err) {
        toast(err.message, "err");
      }
    };
  };

  App.deleteFrontend = (id) =>
    confirmModal("Frontend wirklich löschen?", async () => api(`/api/frontends/${id}`, "DELETE"));

  // ---------------- Backends ----------------
  routes.backends = async function (el) {
    [state.clusters, state.backends] = await Promise.all([
      api("/api/clusters"),
      api("/api/backends"),
    ]);
    el.innerHTML =
      `<div class="page-head"><h2>Backends</h2>
        <button class="btn primary" onclick="App.editBackend()">+ Neues Backend</button></div>` +
      (state.backends.length
        ? state.clusters
            .map((c) => {
              const bes = state.backends.filter((b) => b.cluster_id === c.id);
              if (!bes.length) return "";
              return `
        <div class="card">
          <div class="card-head"><h3>${esc(c.name)}</h3></div>
          <table class="data">
            <thead><tr><th>Name</th><th>Mode</th><th>Balance</th><th>Health-Check</th><th>Server</th><th></th></tr></thead>
            <tbody>
              ${bes
                .map(
                  (b) => `
                <tr>
                  <td>${esc(b.name)}</td>
                  <td>${esc(b.mode)}</td>
                  <td>${esc(b.balance)}</td>
                  <td>${esc(b.check_path || "-")}</td>
                  <td>${b.servers
                    .map((s) => `${esc(s.name)} (${esc(s.host)}:${s.port})`)
                    .join(", ") || '<span class="muted">keine</span>'}</td>
                  <td>
                    <button class="btn sm" onclick="App.editBackend(${b.id})">Bearbeiten</button>
                    <button class="btn sm danger" onclick="App.deleteBackend(${b.id})">Löschen</button>
                  </td>
                </tr>`
                )
                .join("")}
            </tbody>
          </table>
        </div>`;
            })
            .join("")
        : '<div class="card muted">Noch keine Backends vorhanden.</div>');
  };

  function serverRow(s) {
    s = s || {};
    return `<tr>
      <td><input class="srv-name" placeholder="web1" value="${esc(s.name || "")}"></td>
      <td><input class="srv-host" placeholder="10.0.0.1" value="${esc(s.host || "")}"></td>
      <td style="width:90px"><input class="srv-port" type="number" placeholder="8080" value="${
        s.port || ""
      }"></td>
      <td class="c"><input class="srv-check" type="checkbox" ${!s || s.check ? "checked" : ""}></td>
      <td class="c"><input class="srv-ssl" type="checkbox" ${s && s.ssl ? "checked" : ""}></td>
      <td style="width:80px"><input class="srv-weight" type="number" value="${
        s.weight != null ? s.weight : 100
      }"></td>
      <td style="width:90px"><input class="srv-maxconn" type="number" value="${s.maxconn || 0}"></td>
      <td class="c"><input class="srv-backup" type="checkbox" ${s && s.backup ? "checked" : ""}></td>
      <td class="c"><button type="button" class="btn sm danger del-row">✕</button></td>
    </tr>`;
  }

  App.editBackend = function (id) {
    if (!state.clusters.length) {
      toast("Bitte zuerst einen Cluster anlegen", "err");
      return;
    }
    const b = id ? state.backends.find((x) => x.id === id) : null;
    const balances = [
      "roundrobin", "static-rr", "leastconn", "first", "source", "uri",
      "url_param", "hdr", "rdp-cookie", "random",
    ];
    const { close, form } = openModal(
      b ? "Backend bearbeiten" : "Neues Backend",
      `
      <label>Cluster<select name="cluster_id">${clusterOptions(b ? b.cluster_id : state.clusters[0].id)}</select></label>
      <div class="row">
        <label>Name<input name="name" required value="${esc(b ? b.name : "")}"></label>
        <label>Mode
          <select name="mode">
            <option value="http" ${!b || b.mode === "http" ? "selected" : ""}>http</option>
            <option value="tcp" ${b && b.mode === "tcp" ? "selected" : ""}>tcp</option>
          </select></label>
        <label>Balance
          <select name="balance">${balances
            .map(
              (a) =>
                `<option value="${a}" ${b && b.balance === a ? "selected" : ""}>${a}</option>`
            )
            .join("")}</select></label>
      </div>
      <div class="row">
        <label>HTTP Health-Check Pfad (optional)
          <input name="check_path" placeholder="/health" value="${esc(b ? b.check_path : "")}"></label>
        <label>Erwartetes Ergebnis (optional)
          <input name="check_expect" placeholder="status 200" value="${esc(b ? b.check_expect : "")}"></label>
      </div>
      <h4>Server</h4>
      <table class="data">
        <thead><tr><th>Name</th><th>Host</th><th>Port</th><th class="c">Check</th><th class="c">SSL</th><th>Weight</th><th>Maxconn</th><th class="c">Backup</th><th></th></tr></thead>
        <tbody id="srv-rows"></tbody>
      </table>
      <button type="button" class="btn sm" id="add-srv">+ Server</button>
      <h4>Zusätzliche Zeilen</h4>
      <textarea name="extra" rows="2" placeholder="z. B. option forwardfor">${esc(
        b ? b.extra : ""
      )}</textarea>`
    );
    const srvBody = $("#srv-rows", form);
    (b ? b.servers : []).forEach((s) => srvBody.insertAdjacentHTML("beforeend", serverRow(s)));
    if (!b || !b.servers.length) srvBody.innerHTML = serverRow();
    $("#add-srv", form).onclick = () => srvBody.insertAdjacentHTML("beforeend", serverRow());

    form.onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const servers = $$("#srv-rows tr", form)
        .map((tr) => ({
          name: $(".srv-name", tr).value.trim(),
          host: $(".srv-host", tr).value.trim(),
          port: parseInt($(".srv-port", tr).value, 10),
          check: $(".srv-check", tr).checked,
          ssl: $(".srv-ssl", tr).checked,
          weight: parseInt($(".srv-weight", tr).value, 10) || 100,
          maxconn: parseInt($(".srv-maxconn", tr).value, 10) || 0,
          backup: $(".srv-backup", tr).checked,
        }))
        .filter((s) => s.name && s.host && s.port);
      const body = {
        cluster_id: parseInt(fd.get("cluster_id"), 10),
        name: fd.get("name").trim(),
        mode: fd.get("mode"),
        balance: fd.get("balance"),
        check_path: fd.get("check_path").trim(),
        check_expect: fd.get("check_expect").trim(),
        extra: fd.get("extra") || "",
        servers,
      };
      try {
        if (b) await api(`/api/backends/${b.id}`, "PUT", body);
        else await api("/api/backends", "POST", body);
        close();
        toast("Gespeichert");
        router();
      } catch (err) {
        toast(err.message, "err");
      }
    };
  };

  App.deleteBackend = (id) =>
    confirmModal("Backend inkl. Servern wirklich löschen?", async () =>
      api(`/api/backends/${id}`, "DELETE")
    );

  // ---------------- Zertifikate ----------------
  routes.certs = async function (el) {
    [state.certs, state.providers] = await Promise.all([
      api("/api/certificates"),
      api("/api/dns-providers"),
    ]);
    el.innerHTML =
      `<div class="page-head"><h2>Zertifikate (Let's Encrypt, DNS-01)</h2>
        <button class="btn primary" onclick="App.editCert()">+ Neues Zertifikat</button></div>` +
      (state.certs.length
        ? `<div class="card"><table class="data">
        <thead><tr><th>Name</th><th>Domains</th><th>Provider</th><th>Status</th><th>Gültig bis</th><th class="c">Auto-Renew</th><th></th></tr></thead>
        <tbody>
          ${state.certs
            .map((c) => {
              let expiry = "-";
              if (c.not_after) {
                const days = Math.floor((new Date(c.not_after) - Date.now()) / 86400000);
                expiry = `${new Date(c.not_after).toLocaleDateString("de-DE")} `;
                expiry += days < 30 ? statusBadge(days + " Tage!") : `(${days} Tage)`;
              }
              return `
            <tr>
              <td>${esc(c.name)}</td>
              <td>${esc(c.domains.join(", "))}</td>
              <td>${esc((state.providers[c.dns_provider] || {}).label || c.dns_provider)}</td>
              <td>${statusBadge(c.status)}${c.message ? `<div class="error-text" style="font-size:11px">${esc(c.message.slice(0, 300))}</div>` : ""}</td>
              <td>${expiry}</td>
              <td class="c"><input type="checkbox" ${c.auto_renew ? "checked" : ""}
                onchange="App.toggleAutoRenew(${c.id}, this.checked)"></td>
              <td>
                <button class="btn sm" onclick="App.renewCert(${c.id})">Erneuern</button>
                <button class="btn sm" onclick="App.deployCert(${c.id})">Verteilen</button>
                <button class="btn sm danger" onclick="App.deleteCert(${c.id}, '${js(c.name)}')">Löschen</button>
              </td>
            </tr>`;
            })
            .join("")}
        </tbody></table></div>`
        : '<div class="card muted">Noch keine Zertifikate angelegt.</div>');
    if (state.certs.some((c) => c.status === "issuing")) {
      setTimeout(() => {
        if ((location.hash || "").includes("certs")) router();
      }, 4000);
    }
  };

  App.editCert = function () {
    const providerKeys = Object.keys(state.providers);
    const { close, form } = openModal(
      "Neues Zertifikat (DNS-01)",
      `
      <label>Name (intern)<input name="name" required placeholder="example-com"></label>
      <label>Domains (eine pro Zeile, Wildcards erlaubt)
        <textarea name="domains" rows="3" required placeholder="example.com&#10;*.example.com"></textarea></label>
      <label>E-Mail (Let's Encrypt Konto)<input name="email" type="email" placeholder="admin@example.com"></label>
      <label>DNS-Provider
        <select name="dns_provider" id="cert-provider">${providerKeys
          .map((k) => `<option value="${k}">${esc(state.providers[k].label)}</option>`)
          .join("")}</select></label>
      <div id="env-fields"></div>
      <label class="check"><input type="checkbox" name="auto_renew" checked> Automatisch erneuern</label>
      <p class="muted">Nach dem Speichern startet die Ausstellung automatisch im Hintergrund.</p>`
    );
    const envBox = $("#env-fields", form);
    const renderEnv = () => {
      const p = state.providers[$("#cert-provider", form).value];
      envBox.innerHTML = p.env
        .map(
          ([key, desc]) =>
            `<label>${esc(key)} <span class="muted">(${esc(desc)})</span>
              <input class="env-var" data-key="${esc(key)}" type="password" autocomplete="off"></label>`
        )
        .join("");
    };
    renderEnv();
    $("#cert-provider", form).onchange = renderEnv;

    form.onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const provider_config = {};
      $$(".env-var", form).forEach((i) => (provider_config[i.dataset.key] = i.value));
      const body = {
        name: fd.get("name").trim(),
        domains: fd.get("domains").split(/[\n,;]+/).map((d) => d.trim()).filter(Boolean),
        email: fd.get("email").trim(),
        dns_provider: fd.get("dns_provider"),
        provider_config,
        auto_renew: fd.get("auto_renew") === "on",
      };
      try {
        await api("/api/certificates", "POST", body);
        close();
        toast("Ausstellung gestartet – das kann 1–2 Minuten dauern");
        router();
      } catch (err) {
        toast(err.message, "err");
      }
    };
  };

  App.renewCert = async (id) => {
    try {
      await api(`/api/certificates/${id}/renew`, "POST");
      toast("Erneuerung gestartet");
      setTimeout(router, 500);
    } catch (e) {
      toast(e.message, "err");
    }
  };

  App.deployCert = async (id) => {
    try {
      const res = await api(`/api/certificates/${id}/deploy`, "POST");
      const failed = res.results.filter((r) => !r.ok);
      if (failed.length) toast("Fehler bei: " + failed.map((r) => r.node).join(", "), "err");
      else toast("Zertifikat verteilt" + (res.results.length ? ` (${res.results.length} Node-Aktionen)` : ""));
    } catch (e) {
      toast(e.message, "err");
    }
  };

  App.toggleAutoRenew = async (id, value) => {
    try {
      await api(`/api/certificates/${id}/auto-renew`, "PUT", { auto_renew: value });
      toast("Gespeichert");
    } catch (e) {
      toast(e.message, "err");
    }
  };

  App.deleteCert = (id, name) =>
    confirmModal(`Zertifikat <b>${esc(name)}</b> wirklich löschen?`, async () =>
      api(`/api/certificates/${id}`, "DELETE")
    );

  // ---------------- Config & Deploy ----------------
  routes.deploy = async function (el) {
    state.clusters = await api("/api/clusters");
    if (!state.clusters.length) {
      el.innerHTML = '<div class="card muted">Bitte zuerst einen Cluster anlegen.</div>';
      return;
    }
    el.innerHTML = `
      <h2>Config &amp; Deploy</h2>
      <div class="card">
        <div class="row">
          <label>Cluster<select id="deploy-cluster">${clusterOptions(state.clusters[0].id)}</select></label>
        </div>
        <div class="btn-row">
          <button class="btn" id="btn-preview">Konfiguration anzeigen</button>
          <button class="btn" id="btn-validate">Nur validieren</button>
          <button class="btn primary" id="btn-deploy">Validieren + Deployen + Reload</button>
        </div>
        <pre id="deploy-out" class="code-view hidden"></pre>
        <div id="deploy-results"></div>
      </div>`;
    const cid = () => parseInt($("#deploy-cluster").value, 10);
    $("#btn-preview").onclick = async () => {
      const out = $("#deploy-out");
      out.classList.remove("hidden");
      out.textContent = "Lade…";
      try {
        out.textContent = await api(`/api/clusters/${cid()}/config`);
      } catch (e) {
        out.textContent = "Fehler: " + e.message;
      }
    };
    const runDeploy = async (validateOnly) => {
      const box = $("#deploy-results");
      box.innerHTML = '<div class="loading">Arbeite… (Validierung auf den Nodes)</div>';
      try {
        const res = await api(`/api/clusters/${cid()}/deploy`, "POST", {
          validate_only: validateOnly,
        });
        box.innerHTML = res.results
          .map(
            (r) => `
          <div class="deploy-node">
            <b>${esc(r.node)}</b> ${statusBadge(r.ok ? "OK" : "FEHLER")}
            ${r.error ? `<div class="error-text">${esc(r.error)}</div>` : ""}
            <pre>${esc(r.log.join("\n"))}</pre>
          </div>`
          )
          .join("");
        toast(validateOnly ? "Validierung abgeschlossen" : "Deploy abgeschlossen");
      } catch (e) {
        box.innerHTML = `<div class="error-text">${esc(e.message)}</div>`;
      }
    };
    $("#btn-validate").onclick = () => runDeploy(true);
    $("#btn-deploy").onclick = () => runDeploy(false);
  };

  // ---------------- Metriken ----------------
  App.showMetrics = async function (nodeId, nodeName) {
    const { close, form } = openModal(`Metriken: ${nodeName}`, '<div class="loading">Lade…</div>', "Schließen");
    form.querySelector('button[type="submit"]').style.display = "none";
    try {
      const res = await api(`/api/nodes/${nodeId}/metrics`);
      const box = $(".modal-body", form);
      if (!res.ok) {
        box.innerHTML = `<div class="error-text">${esc(res.error)}</div>`;
        return;
      }
      const m = res.metrics;
      const fmt = (mb) => (mb >= 1024 ? (mb / 1024).toFixed(1) + " GB" : mb + " MB");
      box.innerHTML = `
        <div class="metric-grid">
          <div class="metric-box"><div class="value">${m.cpu_percent != null ? m.cpu_percent + "%" : "?"}</div><div class="label">CPU</div></div>
          <div class="metric-box"><div class="value">${esc(m.load || "?")}</div><div class="label">Load (1/5/15)</div></div>
          <div class="metric-box"><div class="value">${m.mem && m.mem.percent != null ? m.mem.percent + "%" : "?"}</div><div class="label">RAM ${m.mem && m.mem.total_mb ? `${fmt(m.mem.used_mb)} / ${fmt(m.mem.total_mb)}` : ""}</div></div>
          <div class="metric-box"><div class="value">${m.disk && m.disk.percent != null ? m.disk.percent + "%" : "?"}</div><div class="label">Disk / ${m.disk && m.disk.total_mb ? `${fmt(m.disk.used_mb)} / ${fmt(m.disk.total_mb)}` : ""}</div></div>
        </div>`;
    } catch (e) {
      $(".modal-body", form).innerHTML = `<div class="error-text">${esc(e.message)}</div>`;
    }
  };

  // ---------------- Versionen ----------------
  routes.versions = async function (el) {
    state.clusters = await api("/api/clusters");
    el.innerHTML = `
      <h2>Config-Versionen</h2>
      <div class="card">
        <div class="row"><label>Cluster<select id="ver-cluster">${clusterOptions(state.clusters[0] && state.clusters[0].id)}</select></label></div>
        <div id="ver-list"></div>
      </div>`;
    const load = async () => {
      const cid = $("#ver-cluster").value;
      const list = await api(`/api/clusters/${cid}/versions`);
      $("#ver-list").innerHTML = list.length
        ? `<table class="data">
            <thead><tr><th>#</th><th>Node</th><th>Zeitpunkt (UTC)</th><th>Benutzer</th><th>Notiz</th><th>Größe</th><th></th></tr></thead>
            <tbody>${list
              .map(
                (v) => `<tr>
                <td>${v.id}</td><td>${esc(v.node_name)}</td><td>${esc(v.created_at)}</td>
                <td>${esc(v.user)}</td><td>${esc(v.note)}</td><td>${v.size} B</td>
                <td>
                  <button class="btn sm" onclick="App.viewVersion(${v.id})">Anzeigen</button>
                  <button class="btn sm" onclick="App.diffVersion(${v.id})">Diff zu aktuell</button>
                  <button class="btn sm warn" onclick="App.rollbackVersion(${v.id})">Rollback</button>
                </td>
              </tr>`
              )
              .join("")}</tbody></table>`
        : '<div class="muted">Noch keine Versionen – sie entstehen bei jedem Deploy.</div>';
    };
    $("#ver-cluster").onchange = load;
    await load();
  };

  App.viewVersion = async function (vid) {
    const text = await api(`/api/versions/${vid}`);
    const { form } = openModal(`Version #${vid}`, `<pre class="code-view">${esc(text)}</pre>`, "Schließen");
    form.querySelector('button[type="submit"]').style.display = "none";
    form.onsubmit = (e) => e.preventDefault();
  };

  App.diffVersion = async function (vid) {
    const res = await api(`/api/versions/${vid}/diff`);
    const { form } = openModal(`Diff: Version #${vid} ↔ aktuell`, `<pre class="code-view">${diffHtml(res.diff)}</pre>`, "Schließen");
    form.querySelector('button[type="submit"]').style.display = "none";
    form.onsubmit = (e) => e.preventDefault();
  };

  App.rollbackVersion = function (vid) {
    confirmModal(
      `Version #${vid} auf dem zugehörigen Node wiederherstellen (mit Validierung + Reload)?`,
      async () => {
        const res = await api(`/api/versions/${vid}/rollback`, "POST");
        if (!res.ok) throw new Error(res.error || "Rollback fehlgeschlagen");
      }
    );
    // Text des Bestätigungs-Buttons anpassen
    const btn = document.querySelector('#modal-root button[type="submit"]');
    if (btn) btn.textContent = "Rollback";
  };

  // ---------------- Runtime (Stick-Tables & Maps) ----------------
  routes.runtime = async function (el) {
    state.clusters = await api("/api/clusters");
    el.innerHTML = `
      <h2>Runtime – Stick-Tables &amp; Maps</h2>
      <div class="card">
        <div class="row"><label>Node<select id="rt-node">${nodeOptions()}</select></label></div>
        <div class="btn-row"><button class="btn" id="rt-load">Laden</button></div>
        <h4>Stick-Tables</h4>
        <div id="rt-tables" class="muted">–</div>
        <h4>Maps / ACL-Dateien</h4>
        <div id="rt-maps" class="muted">–</div>
        <div id="rt-map-detail"></div>
      </div>`;
    const nid = () => $("#rt-node").value;
    $("#rt-load").onclick = async () => {
      const tBox = $("#rt-tables");
      const mBox = $("#rt-maps");
      tBox.innerHTML = mBox.innerHTML = '<div class="loading">Lade…</div>';
      const [t, m] = await Promise.all([
        api(`/api/stats/nodes/${nid()}/tables`),
        api(`/api/stats/nodes/${nid()}/maps`),
      ]);
      tBox.innerHTML = t.ok
        ? t.tables.length
          ? `<table class="data"><thead><tr><th>Table</th><th>Typ</th><th>Belegt</th><th>Größe</th><th></th></tr></thead>
             <tbody>${t.tables
               .map(
                 (tb) => `<tr><td>${esc(tb.name)}</td><td>${esc(tb.type || "-")}</td>
               <td>${esc(tb.used || "-")}</td><td>${esc(tb.size || "-")}</td>
               <td><button class="btn sm danger" onclick="App.clearTable(${nid()}, '${js(tb.name)}')">Leeren</button></td></tr>`
               )
               .join("")}</tbody></table>`
          : '<div class="muted">Keine Stick-Tables definiert.</div>'
        : `<div class="error-text">${esc(t.error)}</div>`;
      mBox.innerHTML = m.ok
        ? m.maps.length
          ? `<table class="data"><thead><tr><th>ID</th><th>Map</th><th></th></tr></thead>
             <tbody>${m.maps
               .map(
                 (mp) => `<tr><td>${esc(mp.id)}</td><td>${esc(mp.info)}</td>
               <td><button class="btn sm" onclick="App.showMapEntries(${nid()}, '${js(mp.id)}')">Einträge</button></td></tr>`
               )
               .join("")}</tbody></table>`
          : '<div class="muted">Keine Maps definiert.</div>'
        : `<div class="error-text">${esc(m.error)}</div>`;
    };
  };

  App.clearTable = async function (nid, table) {
    try {
      await api(`/api/stats/nodes/${nid}/tables/clear`, "POST", { table });
      toast(`Table ${table} geleert`);
    } catch (e) {
      toast(e.message, "err");
    }
  };

  App.showMapEntries = async function (nid, mapId) {
    const box = $("#rt-map-detail");
    box.innerHTML = '<div class="loading">Lade…</div>';
    const res = await api(`/api/stats/nodes/${nid}/maps/${mapId}/entries`);
    box.innerHTML = `
      <h4>Map #${esc(mapId)}</h4>
      <div class="row">
        <label>Schlüssel<input id="map-key"></label>
        <label>Wert<input id="map-value"></label>
        <label style="align-self:end"><button class="btn sm" id="map-add">Hinzufügen</button></label>
      </div>
      ${
        res.ok
          ? res.entries.length
            ? `<table class="data"><thead><tr><th>Schlüssel</th><th>Wert</th><th></th></tr></thead>
               <tbody>${res.entries
                 .map(
                   (e) => `<tr><td>${esc(e.key)}</td><td>${esc(e.value)}</td>
                   <td><button class="btn sm danger" onclick="App.delMapEntry(${nid}, '${js(mapId)}', '${js(e.key)}')">✕</button></td></tr>`
                 )
                 .join("")}</tbody></table>`
            : '<div class="muted">Map ist leer.</div>'
          : `<div class="error-text">${esc(res.error)}</div>`
      }`;
    $("#map-add").onclick = async () => {
      try {
        await api(`/api/stats/nodes/${nid}/maps/entry`, "POST", {
          map_id: mapId,
          key: $("#map-key").value.trim(),
          value: $("#map-value").value.trim(),
          action: "add",
        });
        toast("Eintrag hinzugefügt");
        App.showMapEntries(nid, mapId);
      } catch (e) {
        toast(e.message, "err");
      }
    };
  };

  App.delMapEntry = async function (nid, mapId, key) {
    try {
      await api(`/api/stats/nodes/${nid}/maps/entry`, "POST", {
        map_id: mapId, key, action: "del",
      });
      toast("Eintrag entfernt");
      App.showMapEntries(nid, mapId);
    } catch (e) {
      toast(e.message, "err");
    }
  };

  // ---------------- Logs ----------------
  routes.logs = async function (el) {
    state.clusters = await api("/api/clusters");
    el.innerHTML = `
      <h2>HAProxy-Logs</h2>
      <div class="card">
        <div class="row">
          <label>Node<select id="log-node">${nodeOptions()}</select></label>
          <label style="max-width:130px">Zeilen<input id="log-lines" type="number" value="300"></label>
        </div>
        <div class="btn-row">
          <button class="btn" id="log-load">Laden</button>
          <label class="check" style="margin:0"><input type="checkbox" id="log-auto"> Auto-Refresh (5s)</label>
        </div>
        <pre id="log-out" class="log-view">–</pre>
      </div>`;
    let timer = null;
    const load = async () => {
      const out = $("#log-out");
      try {
        out.textContent = await api(
          `/api/logs/nodes/${$("#log-node").value}?lines=${$("#log-lines").value || 300}`
        );
        out.scrollTop = out.scrollHeight;
      } catch (e) {
        out.textContent = "Fehler: " + e.message;
      }
    };
    $("#log-load").onclick = load;
    $("#log-auto").onchange = (e) => {
      if (timer) clearInterval(timer);
      timer = e.target.checked ? setInterval(load, 5000) : null;
    };
    await load();
  };

  // ---------------- Keepalived ----------------
  routes.keepalived = async function (el) {
    state.clusters = await api("/api/clusters");
    el.innerHTML = `
      <h2>Keepalived (VRRP / Hochverfügbarkeit)</h2>
      <div class="card">
        <div class="row"><label>Cluster<select id="ka-cluster">${clusterOptions(state.clusters[0] && state.clusters[0].id)}</select></label></div>
        <div id="ka-body"></div>
      </div>`;
    const load = async () => {
      const cid = $("#ka-cluster").value;
      const data = await api(`/api/clusters/${cid}/keepalived`);
      const cfg = data.config;
      $("#ka-body").innerHTML = `
        <div class="row">
          <label>Virtuelle IP (VIP, mit CIDR)<input id="ka-vip" placeholder="192.168.1.10/24" value="${esc(cfg.vip)}"></label>
          <label>Interface<input id="ka-iface" value="${esc(cfg.iface || "eth0")}"></label>
        </div>
        <div class="row">
          <label style="max-width:160px">Virtual Router ID<input id="ka-vrid" type="number" value="${cfg.vr_id || 51}"></label>
          <label style="max-width:220px">Auth-Passwort (max. 8 Zeichen)<input id="ka-pass" value="${esc(cfg.auth_pass)}"></label>
        </div>
        <h4>Nodes</h4>
        <table class="data"><thead><tr><th>Node</th><th>Rolle</th><th>Priorität</th></tr></thead>
        <tbody>${data.nodes
          .map(
            (n) => `<tr data-node="${n.id}">
            <td>${esc(n.name)} ${n.is_local ? '<span class="muted">(lokal – wird übersprungen)</span>' : ""}</td>
            <td><select class="ka-state">
              <option value="MASTER" ${n.state === "MASTER" ? "selected" : ""}>MASTER</option>
              <option value="BACKUP" ${n.state !== "MASTER" ? "selected" : ""}>BACKUP</option>
            </select></td>
            <td><input class="ka-prio" type="number" value="${n.priority}" style="width:90px"></td>
          </tr>`
          )
          .join("")}</tbody></table>
        <div class="btn-row">
          <button class="btn" id="ka-save">Speichern</button>
          <button class="btn" id="ka-preview">Vorschau</button>
          <button class="btn primary" id="ka-deploy">Deploy auf Remote-Nodes</button>
          <button class="btn" id="ka-status">Dienst-Status</button>
        </div>
        <div id="ka-out"></div>`;
      const collect = () => ({
        vip: $("#ka-vip").value.trim(),
        iface: $("#ka-iface").value.trim() || "eth0",
        vr_id: parseInt($("#ka-vrid").value, 10) || 51,
        auth_pass: $("#ka-pass").value.trim(),
        nodes: $$("#ka-body tr[data-node]").map((tr) => ({
          node_id: parseInt(tr.dataset.node, 10),
          state: $(".ka-state", tr).value,
          priority: parseInt($(".ka-prio", tr).value, 10) || 100,
        })),
      });
      $("#ka-save").onclick = async () => {
        try {
          await api(`/api/clusters/${cid}/keepalived`, "PUT", collect());
          toast("Gespeichert");
        } catch (e) {
          toast(e.message, "err");
        }
      };
      $("#ka-preview").onclick = async () => {
        try {
          await api(`/api/clusters/${cid}/keepalived`, "PUT", collect());
          const first = data.nodes.find((n) => !n.is_local) || data.nodes[0];
          const res = await api(`/api/clusters/${cid}/keepalived/preview?nid=${first.id}`);
          $("#ka-out").innerHTML = `<pre class="code-view">${esc(res.config)}</pre>`;
        } catch (e) {
          $("#ka-out").innerHTML = `<div class="error-text">${esc(e.message)}</div>`;
        }
      };
      $("#ka-deploy").onclick = async () => {
        try {
          await api(`/api/clusters/${cid}/keepalived`, "PUT", collect());
          const res = await api(`/api/clusters/${cid}/keepalived/deploy`, "POST");
          $("#ka-out").innerHTML = res.results
            .map(
              (r) => `<div class="deploy-node"><b>${esc(r.node)}</b> ${statusBadge(
                r.ok ? "OK" : "FEHLER"
              )}${r.error ? `<div class="error-text">${esc(r.error)}</div>` : ""}
              <pre>${esc((r.log || []).join("\n"))}</pre></div>`
            )
            .join("");
        } catch (e) {
          $("#ka-out").innerHTML = `<div class="error-text">${esc(e.message)}</div>`;
        }
      };
      $("#ka-status").onclick = async () => {
        try {
          const res = await api(`/api/clusters/${cid}/keepalived/status`);
          $("#ka-out").innerHTML = `<table class="data"><thead><tr><th>Node</th><th>Status</th></tr></thead>
            <tbody>${res
              .map((r) => `<tr><td>${esc(r.node)}</td><td>${statusBadge(r.status)}</td></tr>`)
              .join("")}</tbody></table>`;
        } catch (e) {
          $("#ka-out").innerHTML = `<div class="error-text">${esc(e.message)}</div>`;
        }
      };
    };
    $("#ka-cluster").onchange = load;
    await load();
  };

  // ---------------- Tools (Portscan, Config-Vergleich) ----------------
  routes.tools = async function (el) {
    state.clusters = await api("/api/clusters");
    el.innerHTML = `
      <h2>Tools</h2>
      <div class="card">
        <h3>Port-Scanner</h3>
        <div class="row">
          <label>Host<input id="ps-host" placeholder="10.0.0.1"></label>
          <label>Ports (Komma-getrennt, leer = Standard)<input id="ps-ports" placeholder="80,443,3306"></label>
        </div>
        <div class="btn-row"><button class="btn" id="ps-run">Scannen</button></div>
        <div id="ps-out"></div>
      </div>
      <div class="card">
        <h3>Config-Vergleich zwischen Nodes</h3>
        <div class="row">
          <label>Cluster<select id="cmp-cluster">${clusterOptions(state.clusters[0] && state.clusters[0].id)}</select></label>
          <label>Node A<select id="cmp-a"></select></label>
          <label>Node B<select id="cmp-b"></select></label>
        </div>
        <div class="btn-row"><button class="btn" id="cmp-run">Vergleichen</button></div>
        <pre id="cmp-out" class="code-view hidden"></pre>
      </div>`;
    $("#ps-run").onclick = async () => {
      const out = $("#ps-out");
      out.innerHTML = '<div class="loading">Scanne…</div>';
      try {
        const ports = $("#ps-ports").value
          .split(",")
          .map((p) => parseInt(p.trim(), 10))
          .filter((p) => p > 0);
        const res = await api("/api/tools/portscan", "POST", {
          host: $("#ps-host").value.trim(),
          ports,
        });
        const open = res.results.filter((r) => r.open);
        out.innerHTML = open.length
          ? `<p><b>${open.length}</b> offene Ports auf ${esc(res.host)}:</p>
             ${open.map((r) => `<span class="badge ok" style="margin:2px">${r.port}</span>`).join("")}`
          : `<div class="muted">Keine offenen Ports gefunden.</div>`;
      } catch (e) {
        out.innerHTML = `<div class="error-text">${esc(e.message)}</div>`;
      }
    };
    const fillNodes = () => {
      const cid = parseInt($("#cmp-cluster").value, 10);
      const cluster = state.clusters.find((c) => c.id === cid);
      const opts = (cluster ? cluster.nodes : [])
        .map((n) => `<option value="${n.id}">${esc(n.name)}</option>`)
        .join("");
      $("#cmp-a").innerHTML = opts;
      $("#cmp-b").innerHTML = opts;
      if (cluster && cluster.nodes[1]) $("#cmp-b").value = cluster.nodes[1].id;
    };
    fillNodes();
    $("#cmp-cluster").onchange = fillNodes;
    $("#cmp-run").onclick = async () => {
      const out = $("#cmp-out");
      out.classList.remove("hidden");
      out.textContent = "Vergleiche…";
      try {
        const res = await api(
          `/api/tools/compare?cluster_id=${$("#cmp-cluster").value}&node_a=${$(
            "#cmp-a"
          ).value}&node_b=${$("#cmp-b").value}`
        );
        out.innerHTML = diffHtml(res.diff);
      } catch (e) {
        out.textContent = "Fehler: " + e.message;
      }
    };
  };

  // ---------------- Alerts (Admin) ----------------
  routes.alerts = async function (el) {
    const st = await api("/api/alerts/settings");
    el.innerHTML = `
      <h2>Alerts &amp; Benachrichtigungen</h2>
      <form id="alert-form" class="card">
        <label class="check"><input type="checkbox" name="enabled" ${st.enabled ? "checked" : ""}> Alerts aktiviert</label>
        <h4>Webhook (Slack / Discord / Mattermost-kompatibel)</h4>
        <label>Webhook-URL<input name="webhook_url" value="${esc(st.webhook_url)}" placeholder="https://hooks.slack.com/…"></label>
        <h4>E-Mail (SMTP)</h4>
        <div class="row">
          <label>SMTP-Host<input name="smtp_host" value="${esc(st.smtp_host)}"></label>
          <label style="max-width:120px">Port<input name="smtp_port" type="number" value="${st.smtp_port || 587}"></label>
        </div>
        <div class="row">
          <label>Benutzer<input name="smtp_user" value="${esc(st.smtp_user)}"></label>
          <label>Passwort<input name="smtp_pass" type="password" value="${esc(st.smtp_pass)}" autocomplete="new-password"></label>
        </div>
        <div class="row">
          <label>Absender<input name="smtp_from" value="${esc(st.smtp_from)}"></label>
          <label>Empfänger<input name="smtp_to" value="${esc(st.smtp_to)}"></label>
        </div>
        <h4>Ereignisse</h4>
        <label class="check"><input type="checkbox" name="alert_node_down" ${st.alert_node_down ? "checked" : ""}> Node offline/online</label>
        <label class="check"><input type="checkbox" name="alert_cert_expiry" ${st.alert_cert_expiry ? "checked" : ""}> Zertifikat läuft ab (&lt; 14 Tage)</label>
        <label class="check"><input type="checkbox" name="alert_deploy_fail" ${st.alert_deploy_fail ? "checked" : ""}> Deploy fehlgeschlagen</label>
        <div class="btn-row">
          <button type="submit" class="btn primary">Speichern</button>
          <button type="button" class="btn" id="alert-test">Test-Alarm senden</button>
        </div>
        <div id="alert-msg"></div>
      </form>`;
    $("#alert-form").onsubmit = async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const body = Object.fromEntries(fd.entries());
      ["enabled", "alert_node_down", "alert_cert_expiry", "alert_deploy_fail"].forEach(
        (k) => (body[k] = fd.get(k) === "on")
      );
      body.smtp_port = parseInt(body.smtp_port, 10) || 587;
      try {
        await api("/api/alerts/settings", "PUT", body);
        toast("Gespeichert");
      } catch (err) {
        toast(err.message, "err");
      }
    };
    $("#alert-test").onclick = async () => {
      const msg = $("#alert-msg");
      msg.textContent = "Sende…";
      try {
        const res = await api("/api/alerts/test", "POST");
        msg.innerHTML = res.ok
          ? '<span class="badge ok">Gesendet</span>'
          : `<span class="error-text">${esc(res.errors.join("; "))}</span>`;
      } catch (err) {
        msg.innerHTML = `<span class="error-text">${esc(err.message)}</span>`;
      }
    };
  };

  // ---------------- Benutzer, Tokens & Audit (Admin) ----------------
  routes.users = async function (el) {
    const [users, tokens, auditLog] = await Promise.all([
      api("/api/users"),
      api("/api/tokens"),
      api("/api/audit?limit=100"),
    ]);
    el.innerHTML = `
      <div class="page-head"><h2>Benutzer &amp; API</h2>
        <div>
          <button class="btn" onclick="App.editToken()">+ API-Token</button>
          <button class="btn primary" onclick="App.editUser()">+ Benutzer</button>
        </div></div>
      <div class="card">
        <h3>Benutzer</h3>
        <table class="data">
          <thead><tr><th>Name</th><th>Rolle</th><th>Erstellt</th><th></th></tr></thead>
          <tbody>${users
            .map(
              (u) => `<tr>
              <td>${esc(u.username)}</td><td>${statusBadge(u.role)}</td><td>${esc(u.created_at)}</td>
              <td>
                <button class="btn sm" onclick="App.editUser(${u.id}, '${js(u.username)}', '${js(u.role)}')">Bearbeiten</button>
                <button class="btn sm danger" onclick="App.deleteUser(${u.id}, '${js(u.username)}')">Löschen</button>
              </td>
            </tr>`
            )
            .join("")}</tbody>
        </table>
      </div>
      <div class="card">
        <h3>API-Tokens</h3>
        <p class="muted">Nutzung: <code>Authorization: Bearer hg_…</code> (z. B. für CI/CD-Deploys)</p>
        <table class="data">
          <thead><tr><th>Name</th><th>Rolle</th><th>Erstellt</th><th>Zuletzt genutzt</th><th></th></tr></thead>
          <tbody>${tokens
            .map(
              (t) => `<tr>
              <td>${esc(t.name)}</td><td>${statusBadge(t.role)}</td><td>${esc(t.created_at)}</td>
              <td>${esc(t.last_used || "nie")}</td>
              <td><button class="btn sm danger" onclick="App.deleteToken(${t.id})">Löschen</button></td>
            </tr>`
            )
            .join("")}</tbody>
        </table>
      </div>
      <div class="card">
        <h3>LDAP / Active Directory</h3>
        <p class="muted">LDAP-Benutzer melden sich direkt am Login an – die Rolle wird über Gruppen-Mapping bestimmt.</p>
        <button class="btn" onclick="App.ldapSettings()">LDAP konfigurieren</button>
      </div>
      <div class="card">
        <h3>Aktionsverlauf (Audit-Log)</h3>
        <table class="data">
          <thead><tr><th>Zeitpunkt (UTC)</th><th>Benutzer</th><th>Aktion</th><th>Details</th></tr></thead>
          <tbody>${auditLog
            .map(
              (a) => `<tr><td>${esc(a.ts)}</td><td>${esc(a.user)}</td>
              <td>${esc(a.action)}</td><td>${esc(a.detail)}</td></tr>`
            )
            .join("")}</tbody>
        </table>
      </div>`;
  };

  App.editUser = function (id, username, role) {
    const { close, form } = openModal(
      id ? "Benutzer bearbeiten" : "Neuer Benutzer",
      `
      <label>Benutzername<input name="username" required value="${esc(username || "")}"></label>
      <label>Passwort ${id ? "(leer = unverändert)" : ""}
        <input name="password" type="password" ${id ? "" : "required"} autocomplete="new-password"></label>
      <label>Rolle
        <select name="role">
          <option value="viewer" ${role === "viewer" ? "selected" : ""}>viewer (nur lesen)</option>
          <option value="operator" ${role === "operator" ? "selected" : ""}>operator (verwalten)</option>
          <option value="admin" ${role === "admin" ? "selected" : ""}>admin (alles)</option>
        </select></label>`
    );
    form.onsubmit = async (e) => {
      e.preventDefault();
      const body = Object.fromEntries(new FormData(form).entries());
      try {
        if (id) await api(`/api/users/${id}`, "PUT", body);
        else await api("/api/users", "POST", body);
        close();
        toast("Gespeichert");
        router();
      } catch (err) {
        toast(err.message, "err");
      }
    };
  };

  App.deleteUser = (id, username) =>
    confirmModal(`Benutzer <b>${esc(username)}</b> wirklich löschen?`, async () =>
      api(`/api/users/${id}`, "DELETE")
    );

  App.editToken = function () {
    const { close, form } = openModal(
      "Neuer API-Token",
      `
      <label>Name<input name="name" required placeholder="ci-pipeline"></label>
      <label>Rolle
        <select name="role">
          <option value="viewer">viewer</option>
          <option value="operator" selected>operator</option>
          <option value="admin">admin</option>
        </select></label>`
    );
    form.onsubmit = async (e) => {
      e.preventDefault();
      const body = Object.fromEntries(new FormData(form).entries());
      try {
        const res = await api("/api/tokens", "POST", body);
        $(".modal-body", form).innerHTML = `
          <p>Token (wird nur einmal angezeigt – jetzt kopieren!):</p>
          <div class="token-display">${esc(res.token)}</div>`;
        form.querySelector('button[type="submit"]').style.display = "none";
        toast("Token erstellt");
      } catch (err) {
        toast(err.message, "err");
      }
    };
  };

  App.deleteToken = (id) =>
    confirmModal("API-Token wirklich löschen?", async () => api(`/api/tokens/${id}`, "DELETE"));

  App.ldapSettings = async function () {
    let st;
    try {
      st = await api("/api/ldap/settings");
    } catch (e) {
      toast(e.message, "err");
      return;
    }
    const { close, form } = openModal(
      "LDAP / Active Directory",
      `
      <label class="check"><input type="checkbox" name="enabled" ${st.enabled ? "checked" : ""}> LDAP-Login aktiviert</label>
      <div class="row">
        <label>Server-URI<input name="server_uri" value="${esc(st.server_uri)}" placeholder="ldaps://dc01.firma.local:636"></label>
        <label class="check" style="align-self:end"><input type="checkbox" name="use_tls" ${st.use_tls ? "checked" : ""}> Zertifikat prüfen (TLS)</label>
      </div>
      <label>Base-DN<input name="base_dn" value="${esc(st.base_dn)}" placeholder="dc=firma,dc=local"></label>
      <label>User-Filter (<code>{username}</code> wird ersetzt)
        <input name="user_filter" value="${esc(st.user_filter)}"></label>
      <p class="muted">Active Directory: <code>(&(objectClass=user)(sAMAccountName={username}))</code></p>
      <div class="row">
        <label>Service-Bind-DN (Suche)<input name="bind_dn" value="${esc(st.bind_dn)}" placeholder="cn=svc,ou=service,dc=firma,dc=local"></label>
        <label>Bind-Passwort ${st.bind_password === "***" ? "(gesetzt)" : ""}<input name="bind_password" type="password" autocomplete="new-password"></label>
      </div>
      <div class="row">
        <label>Gruppe → admin (DN)<input name="group_admin" value="${esc(st.group_admin)}" placeholder="cn=haproxy-admins,ou=groups,dc=firma,dc=local"></label>
        <label>Gruppe → operator (DN)<input name="group_operator" value="${esc(st.group_operator)}" placeholder="cn=haproxy-ops,ou=groups,dc=firma,dc=local"></label>
      </div>
      <label>Standard-Rolle (wenn keine Gruppen konfiguriert)
        <select name="default_role">
          <option value="viewer" ${st.default_role === "viewer" ? "selected" : ""}>viewer</option>
          <option value="operator" ${st.default_role === "operator" ? "selected" : ""}>operator</option>
          <option value="admin" ${st.default_role === "admin" ? "selected" : ""}>admin</option>
        </select></label>
      <p class="muted">Hinweis: Wenn Gruppen-DNs konfiguriert sind, können sich nur Benutzer dieser Gruppen anmelden.</p>
      <div class="btn-row"><button type="button" class="btn" id="ldap-test">Verbindung testen</button></div>
      <div id="ldap-msg"></div>`
    );
    const collect = () => {
      const fd = new FormData(form);
      const body = Object.fromEntries(fd.entries());
      body.enabled = fd.get("enabled") === "on";
      body.use_tls = fd.get("use_tls") === "on";
      return body;
    };
    $("#ldap-test", form).onclick = async () => {
      const msg = $("#ldap-msg", form);
      msg.textContent = "Teste…";
      try {
        await api("/api/ldap/settings", "PUT", collect());
        const res = await api("/api/ldap/test", "POST");
        msg.innerHTML = res.ok
          ? `<span class="badge ok">${esc(res.message)}</span>`
          : `<span class="error-text">${esc(res.message)}</span>`;
      } catch (e) {
        msg.innerHTML = `<span class="error-text">${esc(e.message)}</span>`;
      }
    };
    form.onsubmit = async (e) => {
      e.preventDefault();
      try {
        await api("/api/ldap/settings", "PUT", collect());
        close();
        toast("LDAP-Einstellungen gespeichert");
      } catch (err) {
        toast(err.message, "err");
      }
    };
  };

  // ---------------- Login & Init ----------------
  function applyUser(user) {
    state.user = user;
    $("#user-info").textContent = user ? `${user.username} (${user.role})` : "";
    $$("nav a[data-admin]").forEach(
      (a) => (a.style.display = user && user.role === "admin" ? "" : "none")
    );
  }

  async function init() {
    $("#login-form").onsubmit = async (e) => {
      e.preventDefault();
      $("#login-error").textContent = "";
      try {
        const res = await api("/api/auth/login", "POST", {
          username: $("#login-user").value,
          password: $("#login-pass").value,
        });
        localStorage.setItem("hg_token", res.token);
        applyUser({ username: res.username, role: res.role });
        showApp();
        router();
      } catch (err) {
        $("#login-error").textContent = err.message;
      }
    };
    $("#logout-btn").onclick = async () => {
      try {
        await api("/api/auth/logout", "POST");
      } catch (e) {}
      localStorage.removeItem("hg_token");
      applyUser(null);
      showLogin();
    };
    try {
      const me = await api("/api/auth/me");
      applyUser(me);
      showApp();
      router();
    } catch (e) {
      showLogin();
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
