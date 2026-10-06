/* =========================================================
   密码管理器 — script.js
   1. 常量与配置      2. DOM 引用       3. 存储与加密
   4. UI 基元         5. 2FA (TOTP)     6. 主页逻辑
   7. 安全设置页      8. 事件与初始化
   兼容 index.html / security.html，localStorage 数据格式保持不变。
   ========================================================= */

(function () {
  "use strict";

  /* ---------- 1. 常量与配置 ---------- */
  const STORAGE_KEY = "pm_secure_v1"; // 加密库
  const PLAIN_KEY = "pm_plain_v1";    // 明文库（关闭主密码时）
  const MODE_KEY = "pm_mode_v1";      // secure | plain

  const SESSION_PWD_KEY = "pm_session_pwd_v1"; // 仅在用户选择“保持解锁”时写入
  const AUTO_LOCK_KEY = "pm_autolock_v1";

  const SALT_LEN = 16;
  const IV_LEN = 12;
  const PBKDF2_ITERATIONS = 200000;
  const MIN_MASTER_LENGTH = 8;

  const TOTP_STEP = 30;
  const TOTP_DIGITS = 6;
  const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  const AUTO_LOCK_OPTIONS = [
    { value: "0", label: "自动锁定：关闭" },
    { value: "1", label: "自动锁定：1 分钟" },
    { value: "5", label: "自动锁定：5 分钟" },
    { value: "15", label: "自动锁定：15 分钟" },
  ];

  /* ---------- 2. DOM 引用 ---------- */
  const $ = (id) => document.getElementById(id);

  // 解锁页
  const authCard = $("authCard");
  const authForm = $("authForm");
  const authTitle = $("authTitle");
  const authTip = $("authTip");
  const masterPasswordInput = $("masterPassword");
  const masterPasswordConfirmInput = $("masterPasswordConfirm");
  const confirmRow = $("confirmRow");
  const masterHint = $("masterHint");
  const authError = $("authError");
  const authBtn = $("authBtn");
  const rememberSessionInput = $("rememberSession");

  // 应用区
  const appArea = $("appArea");
  const vaultStatus = $("vaultStatus");
  const lockBtn = $("lockBtn");

  // 表单
  const form = $("passwordForm");
  const formTitle = $("formTitle");
  const editIdInput = $("editId");
  const nameInput = $("name");
  const accountInput = $("account");
  const passwordInput = $("password");
  const noteInput = $("note");
  const totpSecretInput = $("totpSecret");
  const genPasswordBtn = $("genPasswordBtn");
  const cancelEditBtn = $("cancelEditBtn");
  const autoLockSelect = $("autoLockSelect");

  // 列表
  const searchInput = $("searchInput");
  const searchClearBtn = $("searchClearBtn");
  const listContainer = $("listContainer");
  const listCount = $("listCount");

  // 安全设置页
  const toggleMasterBtn = $("toggleMasterBtn");
  const changeMasterSection = $("changeMasterSection");
  const oldMasterPasswordInput = $("oldMasterPassword");
  const newMasterPasswordInput = $("newMasterPassword");
  const newMasterPasswordConfirmInput = $("newMasterPasswordConfirm");
  const changeMasterBtn = $("changeMasterBtn");
  const clearAllBtn = $("clearAllBtn");

  const isIndexPage = () => Boolean(authCard || appArea || form);
  const isSecurityPage = () => Boolean(toggleMasterBtn || changeMasterBtn);

  /* ---------- 3. 存储与加密 ---------- */
  let items = [];
  let cryptoKey = null;
  let vaultSaltBase64 = null;
  let listSignature = "";
  let editingId = "";
  const revealed = new Set();

  let mode = localStorage.getItem(MODE_KEY) || "secure";
  let autoLockMinutes = Number(localStorage.getItem(AUTO_LOCK_KEY) || 0);

  const toBase64 = (bytes) => btoa(String.fromCharCode(...bytes));
  const fromBase64 = (base64) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  const textEncode = (str) => new TextEncoder().encode(str);
  const textDecode = (buf) => new TextDecoder().decode(buf);

  function randomBytes(len) {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return arr;
  }

  function setMode(next) {
    mode = next;
    localStorage.setItem(MODE_KEY, next);
  }

  function getVaultRaw() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY));
    } catch {
      return null;
    }
  }

  const hasVault = () => Boolean(getVaultRaw());

  function loadPlain() {
    try {
      const raw = JSON.parse(localStorage.getItem(PLAIN_KEY) || "[]");
      return Array.isArray(raw) ? raw : [];
    } catch {
      return [];
    }
  }

  const savePlain = () => localStorage.setItem(PLAIN_KEY, JSON.stringify(items));

  async function deriveKey(masterPassword, saltBytes) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      textEncode(masterPassword),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptJson(obj, key) {
    const iv = randomBytes(IV_LEN);
    const cipher = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      textEncode(JSON.stringify(obj))
    );
    return { iv: toBase64(iv), data: toBase64(new Uint8Array(cipher)) };
  }

  async function decryptJson(payload, key) {
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(payload.iv) },
      key,
      fromBase64(payload.data)
    );
    return JSON.parse(textDecode(plainBuf));
  }

  async function createVault(masterPassword, initItems = []) {
    const salt = randomBytes(SALT_LEN);
    const key = await deriveKey(masterPassword, salt);
    const encrypted = await encryptJson(initItems, key);

    const payload = {
      salt: toBase64(salt),
      iv: encrypted.iv,
      data: encrypted.data,
      updatedAt: Date.now(),
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));

    cryptoKey = key;
    vaultSaltBase64 = payload.salt;
    items = initItems;
  }

  async function unlockVault(masterPassword) {
    const raw = getVaultRaw();
    if (!raw) throw new Error("密码库不存在");

    const key = await deriveKey(masterPassword, fromBase64(raw.salt));
    const list = await decryptJson({ iv: raw.iv, data: raw.data }, key);
    if (!Array.isArray(list)) throw new Error("数据格式错误");

    cryptoKey = key;
    vaultSaltBase64 = raw.salt;
    items = list;
  }

  async function persistVault() {
    if (mode === "plain") {
      savePlain();
      return;
    }
    if (!cryptoKey || !vaultSaltBase64) throw new Error("未解锁");
    const encrypted = await encryptJson(items, cryptoKey);
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        salt: vaultSaltBase64,
        iv: encrypted.iv,
        data: encrypted.data,
        updatedAt: Date.now(),
      })
    );
  }

  // 会话内保持解锁（仅当前标签页，关闭即失效）
  function saveSessionPassword(password) {
    try {
      sessionStorage.setItem(SESSION_PWD_KEY, password);
    } catch {
      /* 隐私模式下可能不可用 */
    }
  }

  function getSessionPassword() {
    try {
      return sessionStorage.getItem(SESSION_PWD_KEY) || "";
    } catch {
      return "";
    }
  }

  function clearSessionPassword() {
    try {
      sessionStorage.removeItem(SESSION_PWD_KEY);
    } catch {
      /* ignore */
    }
  }

  /* ---------- 4. UI 基元（Toast / 弹窗 / 剪贴板） ---------- */
  const hasDialog = () => Boolean(document.querySelector("dialog[open]"));

  const ui = (function createUI() {
    let toastWrap = null;

    function toastHost() {
      if (!toastWrap) {
        toastWrap = document.createElement("div");
        toastWrap.className = "toast-wrap";
        toastWrap.setAttribute("aria-live", "polite");
        document.body.appendChild(toastWrap);
      }
      return toastWrap;
    }

    function toast(message, type = "info", duration = 2000) {
      if (!message) return;
      const host = toastHost();
      const node = document.createElement("div");
      node.className = `toast toast-${type}`;
      node.textContent = message;
      host.appendChild(node);

      const remove = () => {
        node.classList.add("is-out");
        setTimeout(() => node.remove(), 220);
      };
      const timer = setTimeout(remove, duration);
      node.addEventListener("click", () => {
        clearTimeout(timer);
        remove();
      });
    }

    function buildControls(rows) {
      const wrap = document.createElement("div");
      const refs = [];
      rows.forEach((row) => {
        const box = document.createElement("div");
        box.className = "form-row";

        if (row.label) {
          const label = document.createElement("label");
          label.className = "field-label";
          label.textContent = row.label;
          box.appendChild(label);
        }

        const field = document.createElement("input");
        field.type = row.type || "text";
        field.id = row.id;
        field.placeholder = row.placeholder || "";
        field.autocomplete = row.autocomplete || "off";
        if (row.inputmode) field.inputMode = row.inputmode;
        box.appendChild(field);

        if (row.hint) {
          const hint = document.createElement("p");
          hint.className = "hint";
          hint.textContent = row.hint;
          box.appendChild(hint);
        }

        wrap.appendChild(box);
        refs.push(field);
      });
      return { wrap, refs };
    }

    function open(opts) {
      const options = opts || {};
      return new Promise((resolve) => {
        const rows = options.fields || [];
        const { wrap: fieldsWrap, refs } = buildControls(rows);

        const dialog = document.createElement("div");
        dialog.className = "modal";
        dialog.innerHTML = `
          <div class="modal-dialog" role="dialog" aria-modal="true">
            <h3></h3>
            <p class="modal-desc"></p>
            <p class="modal-error hidden"></p>
            <div class="modal-body"></div>
            <div class="modal-actions"></div>
          </div>`;

        const box = dialog.querySelector(".modal-dialog");
        const titleEl = box.querySelector("h3");
        const descEl = box.querySelector(".modal-desc");
        const errorEl = box.querySelector(".modal-error");
        const bodyEl = box.querySelector(".modal-body");
        const actionsEl = box.querySelector(".modal-actions");

        titleEl.textContent = options.title || "请确认";
        if (options.desc) descEl.textContent = options.desc;
        else descEl.remove();
        if (options.tone === "danger") titleEl.style.color = "var(--danger)";

        if (fieldsWrap.children.length) bodyEl.appendChild(fieldsWrap);
        bodyEl.insertAdjacentHTML(
          "beforeend",
          `<div class="form-actions" data-actions></div>`
        );
        const buttonRow = bodyEl.querySelector("[data-actions]");

        const cancelBtn = document.createElement("button");
        cancelBtn.type = "button";
        cancelBtn.className = "secondary";
        cancelBtn.textContent = options.cancelText || "取消";

        const okBtn = document.createElement("button");
        okBtn.type = "button";
        okBtn.textContent = options.okText || "确定";
        if (options.tone === "danger") okBtn.className = "danger";

        buttonRow.append(cancelBtn, okBtn);

        if (options.descActions) {
          const extra = document.createElement("button");
          extra.type = "button";
          extra.className = "secondary";
          extra.textContent = options.descActions;
          extra.addEventListener("click", () =>
            window.open("./security.html", "_self")
          );
          actionsEl.appendChild(extra);
        }

        const showError = (message) => {
          errorEl.textContent = message;
          errorEl.classList.remove("hidden");
        };

        const finish = (value) => {
          document.removeEventListener("keydown", onKey);
          dialog.remove();
          document.body.style.overflow = "";
          resolve(value);
        };

        okBtn.addEventListener("click", () => {
          const values = refs.map((input) => input.value);
          if (options.validate) {
            const error = options.validate(values);
            if (error) {
              showError(error);
              const first = refs[0];
              if (first) first.focus();
              return;
            }
          }
          finish({ ok: true, values, fields: refs });
        });

        cancelBtn.addEventListener("click", () => finish({ ok: false, values: [], fields: refs }));
        dialog.addEventListener("click", (event) => {
          if (event.target === dialog) finish({ ok: false, values: [], fields: refs });
        });

        function onKey(event) {
          if (event.key === "Escape") {
            event.preventDefault();
            finish({ ok: false, values: [], fields: refs });
          } else if (event.key === "Enter" && event.target.tagName === "INPUT") {
            event.preventDefault();
            okBtn.click();
          }
        }

        document.addEventListener("keydown", onKey);
        document.body.appendChild(dialog);
        document.body.style.overflow = "hidden";
        const firstField = refs[0];
        if (firstField) setTimeout(() => firstField.focus(), 0);
        else okBtn.focus();
      });
    }

    const confirm = (options) =>
      open({ okText: "确定", ...options, fields: options.fields || [] });

    function promptPassword(options) {
      const opts = options || {};
      return open({
        title: opts.title,
        desc: opts.desc,
        okText: opts.okText || "确定",
        cancelText: "取消",
        fields: [
          {
            id: "uiPromptPassword",
            label: opts.label || "主密码",
            type: "password",
            placeholder: opts.placeholder || "请输入主密码",
            autocomplete: "current-password",
            hint: opts.hint || "",
          },
        ],
      });
    }

    async function copy(text, successMessage = "已复制") {
      const value = String(text ?? "");
      if (!value) {
        toast("没有可复制的内容", "warn");
        return false;
      }
      try {
        await navigator.clipboard.writeText(value);
        toast(successMessage, "ok");
        return true;
      } catch {
        try {
          const ta = document.createElement("textarea");
          ta.value = value;
          ta.setAttribute("readonly", "");
          ta.style.position = "fixed";
          ta.style.opacity = "0";
          document.body.appendChild(ta);
          ta.select();
          const ok = document.execCommand("copy");
          document.body.removeChild(ta);
          if (ok) {
            toast(successMessage, "ok");
            return true;
          }
        } catch {
          /* fallthrough */
        }
        toast("复制失败，请手动选择复制", "error");
        return false;
      }
    }

    return { toast, open, confirm, promptPassword, copy };
  })();

  /* ---------- 5. 2FA (TOTP) ---------- */
  const normalizeBase32Secret = (raw) =>
    String(raw || "").replace(/[\s-]/g, "").toUpperCase();

  function base32ToBytes(secret) {
    const s = normalizeBase32Secret(secret);
    if (!s) return new Uint8Array();

    let bits = 0;
    let buffer = 0;
    const out = [];

    for (const ch of s) {
      const v = BASE32_ALPHABET.indexOf(ch);
      if (v === -1) throw new Error(`无效 Base32 字符：${ch}`);
      buffer = (buffer << 5) | v;
      bits += 5;
      while (bits >= 8) {
        out.push((buffer >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  async function generateTotp(secretBase32, timestamp = Date.now()) {
    const secret = base32ToBytes(secretBase32);
    if (!secret.length) throw new Error("缺少 2FA 密钥");

    const counter = Math.floor(timestamp / 1000 / TOTP_STEP);
    const key = await crypto.subtle.importKey(
      "raw",
      secret,
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"]
    );

    const msg = new Uint8Array(8);
    let c = counter;
    for (let i = 7; i >= 0; i--) {
      msg[i] = c & 0xff;
      c = Math.floor(c / 256);
    }

    const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      (hmac[offset + 1] << 16) |
      (hmac[offset + 2] << 8) |
      hmac[offset + 3];

    return ((binary >>> 0) % 10 ** TOTP_DIGITS).toString().padStart(TOTP_DIGITS, "0");
  }

  const totpRemain = () => TOTP_STEP - (Math.floor(Date.now() / 1000) % TOTP_STEP);

  /* ---------- 6. 主页逻辑 ---------- */
  function uid() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }

  function escapeHtml(str = "") {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function generateStrongPassword(length = 16) {
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const digits = "0123456789";
    const symbols = "!@#$%^&*()_+[]{}<>?/|";
    const all = upper + lower + digits + symbols;

    const pwd = [
      upper[Math.floor(Math.random() * upper.length)],
      lower[Math.floor(Math.random() * lower.length)],
      digits[Math.floor(Math.random() * digits.length)],
      symbols[Math.floor(Math.random() * symbols.length)],
    ];

    for (let i = pwd.length; i < length; i++) {
      pwd.push(all[Math.floor(Math.random() * all.length)]);
    }
    for (let i = pwd.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [pwd[i], pwd[j]] = [pwd[j], pwd[i]];
    }
    return pwd.join("");
  }

  const formatDate = (ts) =>
    ts
      ? new Date(ts).toLocaleString("zh-CN", {
          year: "numeric",
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
        })
      : "-";

  function copyButton(label, field, id) {
    return `<button type="button" class="icon-btn" data-act="copy" data-id="${escapeHtml(id)}"
              data-field="${field}" title="${label}" aria-label="${label}">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <rect x="9" y="9" width="11" height="11" rx="2" />
          <path d="M15 5.5A2.5 2.5 0 0 0 12.5 3H6a2 6 0 0 0-2 2v7a2.5 2.5 0 0 0 2.5 2.5" />
        </svg>
      </button>`;
  }

  function renderItem(item) {
    const pwdLen = (item.password || "").length;
    const hasTotp = Boolean(item.totpSecret);
    const isRevealed = revealed.has(item.id);
    const editCls = item.id === editingId ? " editing" : "";

    const pwdValue = !item.password
      ? `<span class="value">-</span>`
      : isRevealed
        ? `<span class="value mono">${escapeHtml(item.password)}</span>`
        : `<span class="value mono">${"•".repeat(Math.min(Math.max(pwdLen, 8), 24))}</span>
           <span class="hint" style="margin:0">${pwdLen} 位</span>`;

    return `
      <article class="item${editCls}" data-id="${escapeHtml(item.id)}">
        <div class="item-head">
          <span class="item-title" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>
          <span class="meta">更新于 ${formatDate(item.updatedAt)}</span>
        </div>

        <dl>
          <dt>账号</dt>
          <dd>
            <span class="value">${item.account ? escapeHtml(item.account) : "-"}</span>
            ${item.account ? copyButton("复制账号", "account", item.id) : ""}
          </dd>

          <dt>密码</dt>
          <dd>
            ${pwdValue}
            ${
              item.password
                ? `${copyButton("复制密码", "password", item.id)}
                   <button type="button" class="icon-btn" data-act="reveal" data-id="${escapeHtml(item.id)}"
                     title="${isRevealed ? "隐藏密码" : "显示密码"}"
                     aria-label="${isRevealed ? "隐藏密码" : "显示密码"}">
                     <svg viewBox="0 0 24 24" aria-hidden="true">${
                       isRevealed
                         ? `<path d="M4 4l16 16" /><circle cx="12" cy="12" r="3" />`
                         : `<path d="M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12Z" /><circle cx="12" cy="12" r="3" />`
                     }</svg>
                   </button>`
                : ""
            }
          </dd>

          ${
            hasTotp
              ? `<dt>2FA</dt>
                 <dd>
                   <span class="totp-code" data-totp-id="${escapeHtml(item.id)}">------</span>
                   <span class="totp-remain" data-totp-remain>(${totpRemain()}s)</span>
                   <button type="button" class="icon-btn" data-act="copy-totp" data-id="${escapeHtml(item.id)}"
                     title="复制动态验证码" aria-label="复制动态验证码">
                     <svg viewBox="0 0 24 24" aria-hidden="true">
                       <rect x="9" y="9" width="11" height="11" rx="2" />
                       <path d="M15 5.5A2.5 2.5 0 0 0 12.5 3H6a2 2 0 0 0-2 2v7a2.5 2.5 0 0 0 2.5 2.5" />
                     </svg>
                   </button>
                 </dd>`
              : ""
          }

          ${
            item.note
              ? `<dt>备注</dt><dd><span class="value">${escapeHtml(item.note)}</span></dd>`
              : ""
          }
        </dl>

        <div class="actions">
          <button type="button" class="secondary btn-sm" data-act="edit" data-id="${escapeHtml(item.id)}">修改</button>
          <button type="button" class="danger-soft btn-sm" data-act="delete" data-id="${escapeHtml(item.id)}">删除</button>
        </div>
      </article>`;
  }

  function filteredItems() {
    const keyword = (searchInput?.value || "").trim().toLowerCase();
    if (!keyword) return items;
    return items.filter(
      (x) =>
        (x.name || "").toLowerCase().includes(keyword) ||
        (x.account || "").toLowerCase().includes(keyword) ||
        (x.note || "").toLowerCase().includes(keyword) ||
        (x.totpSecret || "").toLowerCase().includes(keyword)
    );
  }

  function updateCount(filtered) {
    if (!listCount) return;
    const searching = Boolean((searchInput?.value || "").trim());
    if (!items.length) listCount.textContent = "";
    else if (searching) listCount.textContent = `匹配 ${filtered.length} / ${items.length} 条`;
    else listCount.textContent = `共 ${items.length} 条`;
  }

  function updateEditingClass() {
    if (!listContainer) return;
    listContainer.querySelectorAll(".item").forEach((node) => {
      node.classList.toggle("editing", node.dataset.id === editingId);
    });
  }

  function render() {
    if (!listContainer) return;

    const filtered = filteredItems();
    const searching = Boolean((searchInput?.value || "").trim());
    updateCount(filtered);

    if (searchClearBtn) searchClearBtn.classList.toggle("hidden", !searching);

    if (!filtered.length) {
      listContainer.innerHTML = items.length
        ? `<div class="empty">
             <span class="empty-icon" aria-hidden="true">🔍</span>
             <strong>没有匹配的条目</strong>
             换个关键词试试，或清空搜索框。
           </div>`
        : `<div class="empty">
             <span class="empty-icon" aria-hidden="true">🗂️</span>
             <strong>密码库还是空的</strong>
             在左侧填写名称与账号密码，保存后会显示在这里。
           </div>`;
      listSignature = "";
      return;
    }

    // 列表采用整体重绘，重绘后立即补回编辑高亮与 2FA 验证码
    listContainer.innerHTML = filtered.map(renderItem).join("");
    listSignature = filtered.map((x) => x.id).join("|");

    updateEditingClass();
    void refreshTotpCodes(true);
  }

  function resetForm() {
    if (!form) return;
    form.reset();
    if (editIdInput) editIdInput.value = "";
    if (totpSecretInput) totpSecretInput.value = "";
    setEditMode(false);
    if (autoLockSelect) autoLockSelect.value = String(autoLockMinutes);
  }

  function setEditMode(on, item) {
    editingId = on && item ? item.id : "";
    if (formTitle) formTitle.textContent = on ? "编辑密码" : "添加密码";
    if (cancelEditBtn) cancelEditBtn.classList.toggle("hidden", !on);
    updateEditingClass();
  }

  function startEdit(id) {
    const item = items.find((x) => x.id === id);
    if (!item || !form) return;

    editIdInput.value = item.id;
    nameInput.value = item.name || "";
    accountInput.value = item.account || "";
    passwordInput.value = item.password || "";
    noteInput.value = item.note || "";
    if (totpSecretInput) totpSecretInput.value = item.totpSecret || "";

    setEditMode(true, item);

    if (window.matchMedia("(max-width: 900px)").matches) {
      form.scrollIntoView({ behavior: "smooth", block: "start" });
    } else {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
    nameInput.focus();
    nameInput.select();
  }

  async function removeItem(id) {
    const item = items.find((x) => x.id === id);
    if (!item) return;

    const answer = await ui.confirm({
      title: "删除这条记录？",
      desc: `「${item.name}」将从密码库中移除，此操作无法撤销。`,
      okText: "删除",
      tone: "danger",
    });
    if (!answer.ok) return;

    items = items.filter((x) => x.id !== id);
    revealed.delete(id);
    if (editingId === id && form) resetForm();
    await persistVault();
    render();
    ui.toast("已删除", "ok");
  }

  async function toggleReveal(id) {
    if (revealed.has(id)) revealed.delete(id);
    else revealed.add(id);
    render();
  }

  async function copyField(id, field) {
    const item = items.find((x) => x.id === id);
    if (!item) return;
    const labels = { account: "账号已复制", password: "密码已复制" };
    await ui.copy(item[field] || "", labels[field] || "已复制");
  }

  async function copyTotp(id) {
    const item = items.find((x) => x.id === id);
    if (!item || !item.totpSecret) {
      ui.toast("该条记录未设置 2FA 密钥", "warn");
      return;
    }
    try {
      const code = await generateTotp(item.totpSecret);
      await ui.copy(code, "动态验证码已复制");
    } catch (error) {
      console.error(error);
      ui.toast("2FA 生成失败，请检查密钥", "error");
    }
  }

  // ---- 2FA 实时刷新 ----
  let totpTimer = null;
  let lastTotpStep = -1;

  function totpNodes() {
    return listContainer ? [...listContainer.querySelectorAll("[data-totp-id]")] : [];
  }

  async function refreshTotpCodes(force = false) {
    const nodes = totpNodes();
    if (!nodes.length) return;

    const now = Date.now();
    const step = Math.floor(now / 1000 / TOTP_STEP);
    const remain = totpRemain();

    nodes.forEach((node) => {
      const remainNode = node.parentElement?.querySelector("[data-totp-remain]");
      if (remainNode) remainNode.textContent = `(${remain}s)`;
    });

    if (!force && step === lastTotpStep) return;
    lastTotpStep = step;

    for (const node of nodes) {
      const item = items.find((x) => x.id === node.dataset.totpId);
      if (!item || !item.totpSecret) continue;
      try {
        node.textContent = await generateTotp(item.totpSecret, now);
      } catch {
        node.textContent = "ERR";
      }
    }
  }

  function startTotpTicker() {
    if (!listContainer) return;
    if (totpTimer) clearInterval(totpTimer);
    lastTotpStep = -1;
    void refreshTotpCodes(true);
    totpTimer = setInterval(() => void refreshTotpCodes(), 1000);
  }

  function stopTotpTicker() {
    if (totpTimer) clearInterval(totpTimer);
    totpTimer = null;
  }

  // ---- 自动锁定 ----
  let lastActivity = Date.now();

  function noteActivity() {
    lastActivity = Date.now();
  }

  function lockVault(fromIdle = false) {
    cryptoKey = null;
    vaultSaltBase64 = null;
    items = [];
    revealed.clear();
    editingId = "";
    listSignature = "";
    stopTotpTicker();
    clearSessionPassword();
    resetForm();
    showAuth();
    if (vaultStatus) vaultStatus.classList.add("hidden");
    if (lockBtn) lockBtn.classList.add("hidden");
    if (isIndexPage()) initAuthUI();
    if (fromIdle) ui.toast("已自动锁定", "warn");
  }

  function startAutoLockWatcher() {
    if (!isIndexPage() || !autoLockMinutes) return;
    ["pointerdown", "keydown", "wheel", "touchstart"].forEach((evt) =>
      window.addEventListener(evt, noteActivity, { passive: true })
    );
    setInterval(() => {
      if (!appArea || appArea.classList.contains("hidden")) return;
      if (mode === "plain") return;
      if (Date.now() - lastActivity >= autoLockMinutes * 60000) lockVault(true);
    }, 15000);
  }

  // ---- 主页视图切换 ----
  function showAuth() {
    if (authCard) authCard.classList.remove("hidden");
    if (appArea) appArea.classList.add("hidden");
    masterPasswordInput?.focus();
  }

  function showApp() {
    if (authCard) authCard.classList.add("hidden");
    if (appArea) appArea.classList.remove("hidden");
    if (vaultStatus) vaultStatus.classList.remove("hidden");
    if (lockBtn) lockBtn.classList.toggle("hidden", mode === "plain");
  }

  function applyModeUI() {
    if (vaultStatus) {
      vaultStatus.textContent = mode === "secure" ? "加密存储" : "明文存储";
      vaultStatus.className = `badge ${mode === "secure" ? "badge-ok" : "badge-warn"}`;
    }
    if (toggleMasterBtn) {
      toggleMasterBtn.textContent = mode === "secure" ? "关闭主密码" : "开启主密码";
      toggleMasterBtn.className = mode === "secure" ? "danger-soft" : "";
    }
    if (changeMasterSection) {
      changeMasterSection.classList.toggle("hidden", mode !== "secure");
    }
  }

  function clearAuthError() {
    if (!authError) return;
    authError.textContent = "";
    authError.classList.add("hidden");
  }

  function showAuthError(message) {
    if (!authError) return;
    authError.textContent = message;
    authError.classList.remove("hidden");
  }

  function initAuthUI() {
    if (!isIndexPage()) return;
    clearAuthError();

    if (mode === "plain") {
      items = loadPlain();
      enterApp();
      return;
    }

    if (hasVault()) {
      if (authTitle) authTitle.textContent = "解锁密码库";
      if (authTip) authTip.textContent = "请输入主密码解锁。";
      if (confirmRow) confirmRow.classList.add("hidden");
      if (masterHint) masterHint.classList.add("hidden");
      if (authBtn) authBtn.textContent = "解锁";
    } else {
      if (authTitle) authTitle.textContent = "首次设置主密码";
      if (authTip) authTip.textContent = "设置一个主密码来加密你的密码库。";
      if (confirmRow) confirmRow.classList.remove("hidden");
      if (masterHint) masterHint.classList.remove("hidden");
      if (authBtn) authBtn.textContent = "创建密码库";
    }
  }

  async function enterApp() {
    showApp();
    applyModeUI();
    render();
    startTotpTicker();
  }

  async function handleAuthSubmit() {
    if (mode !== "secure") return;

    const master = masterPasswordInput?.value || "";
    const confirmPwd = masterPasswordConfirmInput?.value || "";
    const creating = !hasVault();

    clearAuthError();

    if (!master) return showAuthError("请输入主密码");
    if (master.length < MIN_MASTER_LENGTH) {
      return showAuthError(`主密码至少 ${MIN_MASTER_LENGTH} 位`);
    }
    if (creating && master !== confirmPwd) return showAuthError("两次输入的主密码不一致");

    authBtn.disabled = true;
    try {
      if (creating) await createVault(master, []);
      else await unlockVault(master);

      if (rememberSessionInput?.checked) saveSessionPassword(master);
      else clearSessionPassword();

      if (masterPasswordInput) masterPasswordInput.value = "";
      if (masterPasswordConfirmInput) masterPasswordConfirmInput.value = "";
      noteActivity();
      await enterApp();
      if (creating) ui.toast("密码库已创建", "ok");
    } catch (error) {
      console.error(error);
      showAuthError(creating ? "创建失败，请重试" : "解锁失败：主密码错误或数据损坏");
      masterPasswordInput?.select();
    } finally {
      authBtn.disabled = false;
    }
  }

  async function trySessionUnlock() {
    if (mode !== "secure") return false;
    if (!hasVault()) return false;
    const saved = getSessionPassword();
    if (!saved) return false;
    try {
      await unlockVault(saved);
      await enterApp();
      return true;
    } catch {
      clearSessionPassword();
      return false;
    }
  }

  /* ---------- 7. 安全设置页 ---------- */
  async function currentMasterPassword() {
    const saved = getSessionPassword();
    if (saved) return saved;

    const answer = await ui.promptPassword({
      title: "验证主密码",
      desc: "此操作需要验证当前主密码。",
      okText: "验证",
      placeholder: "请输入当前主密码",
    });
    if (!answer.ok) return "";
    const password = answer.values[0] || "";
    if (password.length < MIN_MASTER_LENGTH) {
      ui.toast(`主密码至少 ${MIN_MASTER_LENGTH} 位`, "error");
      return "";
    }
    return password;
  }

  async function ensureUnlockedItems(password) {
    if (items.length) return true;
    await unlockVault(password);
    return true;
  }

  async function disableMasterPassword() {
    if (mode !== "secure") {
      ui.toast("主密码已处于关闭状态", "warn");
      return;
    }

    const answer = await ui.confirm({
      title: "关闭主密码？",
      desc: "关闭后，密码库将以明文保存在本机浏览器中，任何能打开此页面的人都能看到。",
      okText: "确认关闭",
      tone: "danger",
    });
    if (!answer.ok) return;

    const password = await currentMasterPassword();
    if (!password) return;

    try {
      await ensureUnlockedItems(password);
    } catch (error) {
      console.error(error);
      ui.toast("主密码错误，操作已取消", "error");
      return;
    }

    savePlain();
    localStorage.removeItem(STORAGE_KEY);
    cryptoKey = null;
    vaultSaltBase64 = null;
    setMode("plain");
    clearSessionPassword();
    applyModeUI();
    ui.toast("已关闭主密码，改为明文存储", "warn");
  }

  async function enableMasterPassword() {
    if (mode !== "secure") {
      const answer = await ui.confirm({
        title: "开启主密码？",
        desc: "重新设置主密码后，密码库将使用 AES-GCM 加密存储。",
        okText: "继续",
      });
      if (!answer.ok) return;
    }

    const plainItems = loadPlain();
    const result = await ui.open({
      title: "设置新主密码",
      desc: "主密码不会保存，请务必牢记；忘记将无法解密数据。",
      okText: "开启并加密",
      fields: [
        {
          id: "uiNewMaster",
          label: "新主密码",
          type: "password",
          placeholder: `至少 ${MIN_MASTER_LENGTH} 位`,
          autocomplete: "new-password",
        },
        {
          id: "uiNewMasterConfirm",
          label: "确认新主密码",
          type: "password",
          placeholder: "请再次输入",
          autocomplete: "new-password",
        },
      ],
      validate(values) {
        const [pwd, confirmPwd] = values;
        if (!pwd || pwd.length < MIN_MASTER_LENGTH) {
          return `主密码至少 ${MIN_MASTER_LENGTH} 位`;
        }
        if (pwd !== confirmPwd) return "两次输入的主密码不一致";
        return "";
      },
    });
    if (!result.ok) return;

    const [newMaster] = result.values;
    try {
      await createVault(newMaster, plainItems);
      localStorage.removeItem(PLAIN_KEY);
      setMode("secure");
      saveSessionPassword(newMaster);
      applyModeUI();
      ui.toast("已开启主密码并完成加密", "ok");
    } catch (error) {
      console.error(error);
      ui.toast("操作失败，请重试", "error");
    }
  }

  async function changeMasterPassword() {
    if (mode !== "secure") {
      ui.toast("请先开启主密码", "warn");
      return;
    }

    const oldPwd = oldMasterPasswordInput?.value || "";
    const newPwd = newMasterPasswordInput?.value || "";
    const confirmPwd = newMasterPasswordConfirmInput?.value || "";

    if (!oldPwd || !newPwd || !confirmPwd) {
      ui.toast("请完整填写修改主密码信息", "warn");
      return;
    }
    if (newPwd.length < MIN_MASTER_LENGTH) {
      ui.toast(`新主密码至少 ${MIN_MASTER_LENGTH} 位`, "warn");
      return;
    }
    if (newPwd !== confirmPwd) {
      ui.toast("两次新主密码不一致", "warn");
      return;
    }

    changeMasterBtn.disabled = true;
    try {
      await unlockVault(oldPwd);
      await createVault(newPwd, items);
      saveSessionPassword(newPwd);

      if (oldMasterPasswordInput) oldMasterPasswordInput.value = "";
      if (newMasterPasswordInput) newMasterPasswordInput.value = "";
      if (newMasterPasswordConfirmInput) newMasterPasswordConfirmInput.value = "";
      ui.toast("主密码修改成功", "ok");
    } catch (error) {
      console.error(error);
      ui.toast("旧主密码错误，修改失败", "error");
    } finally {
      changeMasterBtn.disabled = false;
    }
  }

  async function clearAllData() {
    const answer = await ui.confirm({
      title: "清空全部数据？",
      desc: "将删除本机保存的密码库（加密与明文），且无法恢复。",
      okText: "全部清空",
      tone: "danger",
    });
    if (!answer.ok) return;

    const second = await ui.confirm({
      title: "最后确认",
      desc: "此操作不可撤销，确定要继续吗？",
      okText: "确定清空",
      tone: "danger",
    });
    if (!second.ok) return;

    [STORAGE_KEY, PLAIN_KEY, MODE_KEY, AUTO_LOCK_KEY].forEach((key) =>
      localStorage.removeItem(key)
    );
    clearSessionPassword();
    cryptoKey = null;
    vaultSaltBase64 = null;
    items = [];
    mode = "secure";
    applyModeUI();
    ui.toast("已清空本机数据", "ok");
  }

  function initSecurityPage() {
    if (!isSecurityPage()) return;
    applyModeUI();
    if (vaultStatus) vaultStatus.classList.remove("hidden");
  }

  /* ---------- 8. 事件与初始化 ---------- */
  function bindCommonEvents() {
    // 密码显隐（表单内的眼睛按钮）
    document.addEventListener("click", (event) => {
      const trigger = event.target.closest("[data-toggle-password]");
      if (!trigger) return;
      const input = $(trigger.dataset.togglePassword);
      if (!input) return;
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      trigger.setAttribute("aria-label", show ? "隐藏密码" : "显示密码");
      trigger.setAttribute("title", show ? "隐藏密码" : "显示密码");
      input.focus();
    });

    // 跨标签页同步模式
    window.addEventListener("storage", (event) => {
      if (event.key !== MODE_KEY) return;
      mode = event.newValue || "secure";
      applyModeUI();
    });
  }

  function bindIndexEvents() {
    if (!isIndexPage()) return;

    authForm?.addEventListener("submit", (event) => {
      event.preventDefault();
      void handleAuthSubmit();
    });

    masterPasswordConfirmInput?.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      void handleAuthSubmit();
    });

    [masterPasswordInput, masterPasswordConfirmInput].forEach((input) =>
      input?.addEventListener("input", clearAuthError)
    );

    // 侧栏表单
    form?.addEventListener("submit", (event) => {
      event.preventDefault();
      void saveItemFromForm();
    });

    form?.addEventListener("reset", () => {
      // 原生 reset 之后再同步编辑态
      setTimeout(() => {
        if (editIdInput) editIdInput.value = "";
        setEditMode(false);
        if (autoLockSelect) autoLockSelect.value = String(autoLockMinutes);
      }, 0);
    });

    genPasswordBtn?.addEventListener("click", () => {
      if (!passwordInput) return;
      passwordInput.value = generateStrongPassword(16);
      passwordInput.type = "text";
      passwordInput.focus();
      ui.toast("已生成 16 位随机密码", "ok");
    });

    cancelEditBtn?.addEventListener("click", () => {
      resetForm();
      ui.toast("已取消编辑");
    });

    searchInput?.addEventListener("input", render);

    searchClearBtn?.addEventListener("click", () => {
      if (searchInput) searchInput.value = "";
      render();
      searchInput?.focus();
    });

    listContainer?.addEventListener("click", (event) => {
      const trigger = event.target.closest("[data-act]");
      if (!trigger) return;
      const id = trigger.dataset.id;
      switch (trigger.dataset.act) {
        case "copy":
          void copyField(id, trigger.dataset.field);
          break;
        case "copy-totp":
          void copyTotp(id);
          break;
        case "reveal":
          void toggleReveal(id);
          break;
        case "edit":
          startEdit(id);
          break;
        case "delete":
          void removeItem(id);
          break;
        default:
          break;
      }
    });

    lockBtn?.addEventListener("click", () => {
      lockVault();
      ui.toast("已锁定密码库", "ok");
    });

    autoLockSelect?.addEventListener("change", () => {
      autoLockMinutes = Number(autoLockSelect.value) || 0;
      localStorage.setItem(AUTO_LOCK_KEY, String(autoLockMinutes));
      ui.toast(
        autoLockMinutes ? `已设置 ${autoLockMinutes} 分钟自动锁定` : "已关闭自动锁定",
        "ok"
      );
    });

    // 快捷键
    document.addEventListener("keydown", (event) => {
      if (hasDialog()) return;

      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        if (appArea && !appArea.classList.contains("hidden")) searchInput?.focus();
        return;
      }

      if (event.key === "Escape" && editingId) {
        const active = document.activeElement;
        const typing = active && ["INPUT", "TEXTAREA"].includes(active.tagName);
        if (typing && (nameInput?.value || "")) return;
        resetForm();
      }
    });

    rememberSessionInput?.addEventListener("change", () => {
      if (!rememberSessionInput.checked) clearSessionPassword();
    });
  }

  async function saveItemFromForm() {
    const id = editIdInput?.value.trim() || "";
    const payload = {
      name: nameInput?.value.trim() || "",
      account: accountInput?.value.trim() || "",
      password: passwordInput?.value.trim() || "",
      note: noteInput?.value.trim() || "",
      totpSecret: normalizeBase32Secret(totpSecretInput?.value || ""),
    };

    if (!payload.name) {
      ui.toast("请填写必填项：名称", "warn");
      nameInput?.focus();
      return;
    }
    if (
      (payload.account && !payload.password) ||
      (payload.password && !payload.account)
    ) {
      ui.toast("账号与密码需成对填写", "warn");
      return;
    }
    if (!payload.account && !payload.totpSecret) {
      ui.toast("请填写「账号 + 密码」或「2FA 密钥」", "warn");
      return;
    }
    if (payload.totpSecret) {
      try {
        base32ToBytes(payload.totpSecret);
      } catch {
        ui.toast("2FA 密钥含无效 Base32 字符", "warn");
        totpSecretInput?.focus();
        return;
      }
    }

    const saveBtn = $("saveBtn");
    if (saveBtn) saveBtn.disabled = true;
    try {
      if (id) {
        const idx = items.findIndex((x) => x.id === id);
        if (idx !== -1) items[idx] = { ...items[idx], ...payload, updatedAt: Date.now() };
      } else {
        items.unshift({
          id: uid(),
          ...payload,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        });
      }
      await persistVault();
      resetForm();
      render();
      void refreshTotpCodes(true);
      ui.toast(id ? "已保存修改" : "已添加到密码库", "ok");
    } catch (error) {
      console.error(error);
      ui.toast("保存失败，请重试", "error");
    } finally {
      if (saveBtn) saveBtn.disabled = false;
    }
  }

  function bindSecurityEvents() {
    if (!isSecurityPage()) return;

    toggleMasterBtn?.addEventListener("click", () => {
      if (mode === "secure") void disableMasterPassword();
      else void enableMasterPassword();
    });

    changeMasterBtn?.addEventListener("click", () => void changeMasterPassword());

    $("changeMasterForm")?.addEventListener("submit", (event) => {
      event.preventDefault();
      void changeMasterPassword();
    });

    clearAllBtn?.addEventListener("click", () => void clearAllData());
  }

  function initAutoLockSelect() {
    if (!autoLockSelect) return;
    if (!AUTO_LOCK_OPTIONS.some((opt) => Number(opt.value) === autoLockMinutes)) {
      autoLockMinutes = 0;
    }
    autoLockSelect.innerHTML = AUTO_LOCK_OPTIONS.map(
      (opt) => `<option value="${opt.value}">${opt.label}</option>`
    ).join("");
    autoLockSelect.value = String(autoLockMinutes);
  }

  async function init() {
    bindCommonEvents();
    initAutoLockSelect();

    if (isIndexPage()) {
      bindIndexEvents();
      if (mode === "secure" && (await trySessionUnlock())) {
        startAutoLockWatcher();
        return;
      }
      initAuthUI();
      startAutoLockWatcher();
      return;
    }

    if (isSecurityPage()) {
      bindSecurityEvents();
      initSecurityPage();
    }
  }

  void init();

  window.addEventListener("beforeunload", stopTotpTicker);
})();
