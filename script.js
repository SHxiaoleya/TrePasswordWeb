// =========================
// 密码管理器（双页面兼容版 + 2FA 实时计算）
// 兼容：index.html / security.html
// =========================

const STORAGE_KEY = "pm_secure_v1"; // 加密库
const PLAIN_KEY = "pm_plain_v1";    // 明文库（关闭主密码时）
const MODE_KEY = "pm_mode_v1";      // secure | plain

const SALT_LEN = 16;
const IV_LEN = 12;

// 2FA 配置
const TOTP_STEP = 30;   // 30秒一刷新
const TOTP_DIGITS = 6;  // 6位验证码
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// ---------- DOM（按页面可能不存在，全部做兼容） ----------
// auth (index)
const authCard = document.getElementById("authCard");
const authTitle = document.getElementById("authTitle");
const authTip = document.getElementById("authTip");
const masterPasswordInput = document.getElementById("masterPassword");
const masterPasswordConfirmInput = document.getElementById("masterPasswordConfirm");
const confirmRow = document.getElementById("confirmRow");
const authBtn = document.getElementById("authBtn");

// app (index)
const appArea = document.getElementById("appArea");
const vaultStatus = document.getElementById("vaultStatus");

// security (security.html)
const toggleMasterBtn = document.getElementById("toggleMasterBtn");
const changeMasterSection = document.getElementById("changeMasterSection");
const oldMasterPasswordInput = document.getElementById("oldMasterPassword");
const newMasterPasswordInput = document.getElementById("newMasterPassword");
const newMasterPasswordConfirmInput = document.getElementById("newMasterPasswordConfirm");
const changeMasterBtn = document.getElementById("changeMasterBtn");

// form/list (index)
const form = document.getElementById("passwordForm");
const formTitle = document.getElementById("formTitle");
const editIdInput = document.getElementById("editId");
const nameInput = document.getElementById("name");
const accountInput = document.getElementById("account");
const passwordInput = document.getElementById("password");
const noteInput = document.getElementById("note");
const totpSecretInput = document.getElementById("totpSecret"); // 新增
const searchInput = document.getElementById("searchInput");
const listContainer = document.getElementById("listContainer");
const genPasswordBtn = document.getElementById("genPasswordBtn");
const cancelEditBtn = document.getElementById("cancelEditBtn");

// ---------- 状态 ----------
let items = [];
let cryptoKey = null;
let vaultSaltBase64 = null;
let mode = localStorage.getItem(MODE_KEY) || "secure"; // 默认开启主密码

let totpTimer = null;
let lastTotpStep = -1;

// ---------- 工具 ----------
function toBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
function fromBase64(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}
function textEncode(str) {
  return new TextEncoder().encode(str);
}
function textDecode(buf) {
  return new TextDecoder().decode(buf);
}
function randomBytes(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return arr;
}

function isIndexPage() {
  return !!authCard || !!appArea || !!form;
}
function isSecurityPage() {
  return !!toggleMasterBtn || !!changeMasterBtn;
}

function setMode(nextMode) {
  mode = nextMode;
  localStorage.setItem(MODE_KEY, nextMode);
}

async function deriveKey(masterPassword, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    textEncode(masterPassword),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: 200000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptJson(obj, key) {
  const iv = randomBytes(IV_LEN);
  const plaintext = textEncode(JSON.stringify(obj));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { iv: toBase64(iv), data: toBase64(new Uint8Array(cipher)) };
}

async function decryptJson(payload, key) {
  const iv = fromBase64(payload.iv);
  const data = fromBase64(payload.data);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(textDecode(plainBuf));
}

function getVaultRaw() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY));
  } catch {
    return null;
  }
}
function hasVault() {
  return !!getVaultRaw();
}

function loadPlain() {
  try {
    const raw = JSON.parse(localStorage.getItem(PLAIN_KEY) || "[]");
    return Array.isArray(raw) ? raw : [];
  } catch {
    return [];
  }
}
function savePlain() {
  localStorage.setItem(PLAIN_KEY, JSON.stringify(items));
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

  const salt = fromBase64(raw.salt);
  const key = await deriveKey(masterPassword, salt);
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
  const payload = {
    salt: vaultSaltBase64,
    iv: encrypted.iv,
    data: encrypted.data,
    updatedAt: Date.now(),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}

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

  let pwd = [
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

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    alert("复制成功");
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("复制成功");
  }
}

// ---------- 2FA（TOTP） ----------
function normalizeBase32Secret(raw) {
  return String(raw || "").replace(/[\s-]/g, "").toUpperCase();
}

function base32ToBytes(secret) {
  const s = normalizeBase32Secret(secret);
  if (!s) return new Uint8Array();

  const rev = {};
  for (let i = 0; i < BASE32_ALPHABET.length; i++) {
    rev[BASE32_ALPHABET[i]] = i;
  }

  let bits = 0;
  let buffer = 0;
  const out = [];

  for (const ch of s) {
    const v = rev[ch];
    if (v === undefined) throw new Error(`无效Base32字符：${ch}`);
    buffer = (buffer << 5) | v;
    bits += 5;
    while (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

async function generateTotp(secretBase32, timestamp = Date.now(), step = TOTP_STEP, digits = TOTP_DIGITS) {
  const secret = base32ToBytes(secretBase32);
  if (!secret.length) throw new Error("缺少2FA密钥");
  const counter = Math.floor(timestamp / 1000 / step);

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
    (hmac[offset + 3]);
  const code = ((binary >>> 0) % Math.pow(10, digits)).toString().padStart(digits, "0");

  return code;
}

async function updateTotpDisplays() {
  if (!isIndexPage() || !listContainer) return;

  const now = Date.now();
  const nowSec = Math.floor(now / 1000);
  const remain = TOTP_STEP - (nowSec % TOTP_STEP);
  const stepNow = Math.floor(nowSec / TOTP_STEP);

  const codeNodes = [...listContainer.querySelectorAll("[data-totp-id]")];
  if (!codeNodes.length) return;

  // 只在30秒边界重算一次，避免无谓计算
  if (stepNow !== lastTotpStep) {
    lastTotpStep = stepNow;
    for (const node of codeNodes) {
      const id = node.dataset.totpId;
      const item = items.find((x) => x.id === id);
      if (!item || !item.totpSecret) continue;

      try {
        const code = await generateTotp(item.totpSecret, now, TOTP_STEP, TOTP_DIGITS);
        node.textContent = code;
      } catch {
        node.textContent = "ERR";
      }
    }
  }

  for (const node of codeNodes) {
    const id = node.dataset.totpId;
    const remainNode = document.getElementById(`totpRemain-${id}`);
    if (remainNode) remainNode.textContent = `(${remain}s)`;
  }
}

function startTotpTicker() {
  if (!isIndexPage() || !listContainer) return;
  if (totpTimer) clearInterval(totpTimer);
  lastTotpStep = -1;
  updateTotpDisplays();
  totpTimer = setInterval(updateTotpDisplays, 1000);
}

// ---------- index：表单 / 列表 ----------
function resetForm() {
  if (!form) return;
  form.reset();
  if (editIdInput) editIdInput.value = "";
  if (totpSecretInput) totpSecretInput.value = "";
  if (formTitle) formTitle.textContent = "添加密码";
  if (cancelEditBtn) cancelEditBtn.classList.add("hidden");
}

function startEdit(id) {
  if (!form) return;
  const item = items.find((x) => x.id === id);
  if (!item) return;

  editIdInput.value = item.id;
  nameInput.value = item.name;
  accountInput.value = item.account;
  passwordInput.value = item.password;
  noteInput.value = item.note || "";
  if (totpSecretInput) totpSecretInput.value = item.totpSecret || "";

  if (formTitle) formTitle.textContent = "编辑密码";
  if (cancelEditBtn) cancelEditBtn.classList.remove("hidden");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function removeItem(id) {
  if (!confirm("确定删除这条记录吗？")) return;
  items = items.filter((x) => x.id !== id);
  await persistVault();
  render();
}

function render() {
  if (!listContainer) return;

  const keyword = (searchInput?.value || "").trim().toLowerCase();
  const filtered = items.filter(
    (x) =>
      x.name.toLowerCase().includes(keyword) ||
      x.account.toLowerCase().includes(keyword) ||
      (x.note || "").toLowerCase().includes(keyword) ||
      (x.totpSecret || "").toLowerCase().includes(keyword)
  );

  if (!filtered.length) {
    listContainer.innerHTML = `<div class="empty">暂无数据</div>`;
    return;
  }

  listContainer.innerHTML = filtered
    .map((item) => {
      const maskedPwd = "•".repeat(Math.max(item.password.length, 8));
      const hasTotp = !!item.totpSecret;
      return `
      <div class="item">
        <div class="item-head">
          <div class="item-title">${escapeHtml(item.name)}</div>
          <small class="meta">更新：${new Date(item.updatedAt).toLocaleString()}</small>
        </div>
        <div class="meta"><strong>账号：</strong>${escapeHtml(item.account)}</div>
        <div class="meta"><strong>密码：</strong>${escapeHtml(maskedPwd)}</div>
        ${hasTotp
          ? `<div class="meta">
               <strong>2FA验证码：</strong>
               <span id="totpCode-${item.id}" data-totp-id="${item.id}" class="totp-code">------</span>
               <span id="totpRemain-${item.id}" class="totp-remain">(30s)</span>
             </div>`
          : ""
        }
        <div class="meta"><strong>备注：</strong>${escapeHtml(item.note || "-")}</div>
        <div class="actions">
          <button onclick="copyField('${item.id}','account')">复制账号</button>
          <button onclick="copyField('${item.id}','password')">复制密码</button>
          ${hasTotp ? `<button class="secondary" onclick="copyTotp('${item.id}')">复制2FA</button>` : ""}
          <button class="secondary" onclick="startEdit('${item.id}')">修改</button>
          <button class="danger" onclick="removeItem('${item.id}')">删除</button>
        </div>
      </div>
    `;
    })
    .join("");

  // 列表重绘后立即刷新一次显示
  void updateTotpDisplays();
}

window.copyField = function (id, field) {
  const item = items.find((x) => x.id === id);
  if (!item) return;
  copyText(item[field] || "");
};

window.startEdit = startEdit;
window.removeItem = removeItem;

window.copyTotp = async function (id) {
  const item = items.find((x) => x.id === id);
  if (!item || !item.totpSecret) {
    alert("该条记录未设置2FA密钥");
    return;
  }
  try {
    const code = await generateTotp(item.totpSecret, Date.now(), TOTP_STEP, TOTP_DIGITS);
    copyText(code);
  } catch (e) {
    console.error(e);
    alert("2FA生成失败，请检查密钥是否正确");
  }
};

// ---------- UI 刷新 ----------
function refreshSecurityUI() {
  if (vaultStatus) {
    vaultStatus.textContent =
      mode === "secure" ? "已解锁（主密码开启）" : "已解锁（主密码关闭）";
  }

  if (toggleMasterBtn) {
    toggleMasterBtn.textContent = mode === "secure" ? "关闭主密码" : "开启主密码";
  }

  if (changeMasterSection) {
    if (mode === "secure") changeMasterSection.classList.remove("hidden");
    else changeMasterSection.classList.add("hidden");
  }
}

// index: 进入主应用
function enterApp() {
  if (authCard) authCard.classList.add("hidden");
  if (appArea) appArea.classList.remove("hidden");

  if (masterPasswordInput) masterPasswordInput.value = "";
  if (masterPasswordConfirmInput) masterPasswordConfirmInput.value = "";

  refreshSecurityUI();
  render();
  startTotpTicker();
}

// index: 初始化解锁卡
function initAuthUI() {
  if (!isIndexPage()) return;

  if (mode === "plain") {
    // 主密码关闭：直接进入
    items = loadPlain();
    enterApp();
    return;
  }

  // secure 模式
  if (hasVault()) {
    if (authTitle) authTitle.textContent = "解锁密码库";
    if (authTip) authTip.textContent = "请输入主密码解锁。";
    if (confirmRow) confirmRow.classList.add("hidden");
    if (authBtn) authBtn.textContent = "解锁";
  } else {
    if (authTitle) authTitle.textContent = "首次设置主密码";
    if (authTip) authTip.textContent = "主密码不会保存，请牢记；忘记将无法解密数据。";
    if (confirmRow) confirmRow.classList.remove("hidden");
    if (authBtn) authBtn.textContent = "创建密码库";
  }
}

// security.html: 初始化显示状态
function initSecurityPage() {
  if (!isSecurityPage()) return;
  refreshSecurityUI();
}

// ---------- 事件绑定 ----------

// index: 解锁/创建
if (authBtn) {
  authBtn.addEventListener("click", async () => {
    if (mode !== "secure") return;

    const master = masterPasswordInput?.value || "";
    const confirmPwd = masterPasswordConfirmInput?.value || "";

    if (!master || master.length < 8) {
      alert("主密码至少 8 位");
      return;
    }

    try {
      if (!hasVault()) {
        if (master !== confirmPwd) {
          alert("两次输入的主密码不一致");
          return;
        }
        await createVault(master, []);
      } else {
        await unlockVault(master);
      }

      enterApp();
    } catch (err) {
      console.error(err);
      alert("解锁失败：主密码错误或数据损坏");
    }
  });
}

// index: 添加/编辑
if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const id = editIdInput?.value.trim() || "";
    const payload = {
      name: nameInput?.value.trim() || "",
      account: accountInput?.value.trim() || "",
      password: passwordInput?.value.trim() || "",
      note: noteInput?.value.trim() || "",
      totpSecret: normalizeBase32Secret(totpSecretInput?.value || ""),
    };
    const hasAccountPassword = payload.account && payload.password; // 账号+密码这一组
    const hasTotp = !!payload.totpSecret;                         // 2FA这一组
    if (!payload.name) {
      alert("请填写必填项：名称");
      return;
    }
    // 新判定：账号+密码 二选一 或 2FA
    if (!hasAccountPassword && !hasTotp) {
      alert("请至少填写“账号+密码”或“2FA密钥”（可二选一，也可都填）");
      return;
    }
    // 若使用账号密码，账号和密码必须成对出现
    if ((payload.account && !payload.password) || (payload.password && !payload.account)) {
      alert("若选择“账号密码”方式，请同时填写账号和密码");
      return;
    }
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
  });
}

if (genPasswordBtn) {
  genPasswordBtn.addEventListener("click", () => {
    if (passwordInput) passwordInput.value = generateStrongPassword(16);
  });
}
if (cancelEditBtn) cancelEditBtn.addEventListener("click", resetForm);
if (searchInput) searchInput.addEventListener("input", render);

// security: 开关主密码
if (toggleMasterBtn) {
  toggleMasterBtn.addEventListener("click", async () => {
    try {
      if (mode === "secure") {
        // secure -> plain
        const ok = confirm("关闭主密码后，将改为本地明文存储。确定继续吗？");
        if (!ok) return;

        // 当前未解锁时，先用主密码解锁再转换
        if (!items.length && hasVault() && !cryptoKey) {
          const pwd = prompt("请输入当前主密码以完成关闭操作");
          if (!pwd) return;
          await unlockVault(pwd);
        }

        savePlain();
        localStorage.removeItem(STORAGE_KEY);
        cryptoKey = null;
        vaultSaltBase64 = null;
        setMode("plain");
        refreshSecurityUI();
        alert("已关闭主密码");
      } else {
        // plain -> secure
        const newMaster = prompt("请输入新主密码（至少8位）");
        if (!newMaster || newMaster.length < 8) {
          alert("主密码至少 8 位");
          return;
        }
        const confirmMaster = prompt("请再次输入新主密码");
        if (newMaster !== confirmMaster) {
          alert("两次输入不一致");
          return;
        }

        const plainItems = loadPlain();
        await createVault(newMaster, plainItems);
        localStorage.removeItem(PLAIN_KEY);
        setMode("secure");
        refreshSecurityUI();
        alert("已开启主密码并完成加密");
      }
    } catch (e) {
      console.error(e);
      alert("操作失败，请重试");
    }
  });
}

// security: 修改主密码（仅 secure）
if (changeMasterBtn) {
  changeMasterBtn.addEventListener("click", async () => {
    if (mode !== "secure") return;

    const oldPwd = oldMasterPasswordInput?.value || "";
    const newPwd = newMasterPasswordInput?.value || "";
    const confirmPwd = newMasterPasswordConfirmInput?.value || "";

    if (!oldPwd || !newPwd || !confirmPwd) {
      alert("请完整填写修改主密码信息");
      return;
    }
    if (newPwd.length < 8) {
      alert("新主密码至少 8 位");
      return;
    }
    if (newPwd !== confirmPwd) {
      alert("两次新主密码不一致");
      return;
    }

    try {
      // 校验旧密码并解密
      await unlockVault(oldPwd);

      // 用新密码重加密
      const currentItems = [...items];
      await createVault(newPwd, currentItems);

      oldMasterPasswordInput.value = "";
      newMasterPasswordInput.value = "";
      newMasterPasswordConfirmInput.value = "";
      alert("主密码修改成功");
    } catch (e) {
      console.error(e);
      alert("旧主密码错误，修改失败");
    }
  });
}

// ---------- 初始化 ----------
(function init() {
  if (isIndexPage()) {
    initAuthUI();
  }

  if (isSecurityPage()) {
    // security 页面只展示状态，不需要自动解锁
    initSecurityPage();
  }
})();

// 页面离开时清理计时器（可选）
window.addEventListener("beforeunload", () => {
  if (totpTimer) clearInterval(totpTimer);
});
