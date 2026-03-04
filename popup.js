const API_BASE = 'http://127.0.0.1:8877';
const SESSION_KEY = 'hwvault_session_token';
const SESSION_SIGN_KEY = 'hwvault_session_sign_key';
const RELAXED_AUTOFILL_KEY = 'hwvault_relaxed_autofill_policy';
const LAST_ACTIVE_TAB_ID_KEY = 'hwvault_last_active_tab_id';

let allEntries = [];
let entryDataCache = {};
let currentEntry = null;
let currentOtpSecret = null;
let otpInterval = null;
let sessionToken = null;
let sessionSignKey = null;
let passkeyRegistered = false;
let linuxBiometricAvailable = false;
let pendingAutofillMatches = [];
let pendingAutofillTabId = null;
let editMode = null;
let editingEntryId = null;

const PAYLOAD_TEMPLATES = {
  password: {},
  ssh_key: { ssh_key: { private_pem: '', public: '', fingerprint: '' } },
  gpg_key: { gpg_key: { armored_private: '', armored_public: '', key_id: '' } },
  mtls_cert: { mtls_cert: { cert_pem: '', key_pem: '', chain_pem: '' } },
  api_token: { api_token: { token: '', scope: '' } },
  note: { note: { text: '' } },
  binary_blob: { binary_blob: { mime: '', base64: '' } },
};

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str || '';
  return div.innerHTML;
}

function normalizeEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const entryId = raw.entry_id || raw.id || '';
  const name = raw.name || '';
  if (!entryId || !name) return null;

  const tagsRaw = raw.tags;
  const tags = Array.isArray(tagsRaw)
    ? tagsRaw.filter(Boolean).map((v) => String(v))
    : (typeof tagsRaw === 'string' && tagsRaw.trim()
      ? tagsRaw.split(',').map((t) => t.trim()).filter(Boolean)
      : []);

  const payload = (raw.payload && typeof raw.payload === 'object') ? raw.payload : {};

  return {
    entry_id: entryId,
    credential_type: raw.credential_type || raw.type || 'password',
    created_at: Number(raw.created_at || raw.created || 0) || 0,
    updated_at: Number(raw.updated_at || raw.updated || 0) || 0,
    name,
    url: raw.url || '',
    user: raw.username || raw.user || '',
    pass: raw.password || raw.pass || '',
    note: raw.note || '',
    otp: raw.otp || '',
    tags,
    folder: raw.folder || '',
    payload,
    last_used_at: Number(raw.last_used_at || 0) || 0,
    origin: raw.origin || '',
  };
}

function loadSessionToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get([SESSION_KEY, SESSION_SIGN_KEY], (obj) => {
      sessionToken = obj[SESSION_KEY] || null;
      sessionSignKey = obj[SESSION_SIGN_KEY] || null;
      resolve(hasSession());
    });
  });
}

function hasSession() {
  return Boolean(sessionToken && sessionSignKey);
}

function persistSessionToken() {
  return new Promise((resolve) => {
    if (!hasSession()) {
      sessionToken = null;
      sessionSignKey = null;
      chrome.storage.local.remove([SESSION_KEY, SESSION_SIGN_KEY], () => resolve());
      return;
    }
    chrome.storage.local.set({ [SESSION_KEY]: sessionToken, [SESSION_SIGN_KEY]: sessionSignKey || '' }, () => resolve());
  });
}

function bytesToB64url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sha256B64url(inputText) {
  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(inputText));
  return bytesToB64url(new Uint8Array(digest));
}

async function hmacSha256B64url(keyText, messageText) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(keyText),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(messageText));
  return bytesToB64url(new Uint8Array(sig));
}

function randomNonceB64url() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToB64url(bytes);
}

function loadRelaxedPolicyMap() {
  return new Promise((resolve) => {
    chrome.storage.local.get([RELAXED_AUTOFILL_KEY], (obj) => {
      resolve(obj[RELAXED_AUTOFILL_KEY] || {});
    });
  });
}

function persistRelaxedPolicyMap(map) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ [RELAXED_AUTOFILL_KEY]: map || {} }, () => resolve());
  });
}

async function isRelaxedAllowed(host) {
  const map = await loadRelaxedPolicyMap();
  return !!map[host];
}

async function allowRelaxedForHost(host) {
  const map = await loadRelaxedPolicyMap();
  map[host] = true;
  await persistRelaxedPolicyMap(map);
}

function showToast(msg) {
  const toast = $('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2000);
}

function showError(msg) {
  const el = $('error');
  el.textContent = msg;
  el.style.display = 'block';
  setTimeout(() => {
    el.style.display = 'none';
  }, 5000);
}

function hideError() {
  $('error').style.display = 'none';
}

function b64urlToBuffer(v) {
  const pad = '='.repeat((4 - (v.length % 4)) % 4);
  const base64 = (v + pad).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out.buffer;
}

function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function toPublicKeyOptions(serverPublicKey) {
  const options = structuredClone(serverPublicKey);
  options.challenge = b64urlToBuffer(options.challenge);
  if (options.user && options.user.id) {
    options.user.id = b64urlToBuffer(options.user.id);
  }
  if (Array.isArray(options.allowCredentials)) {
    options.allowCredentials = options.allowCredentials.map((c) => ({
      ...c,
      id: b64urlToBuffer(c.id),
    }));
  }
  return options;
}

function serializeCredential(cred) {
  const out = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
    },
  };

  if (cred.response.attestationObject) {
    out.response.attestationObject = bufferToB64url(cred.response.attestationObject);
  }
  if (cred.response.authenticatorData) {
    out.response.authenticatorData = bufferToB64url(cred.response.authenticatorData);
  }
  if (cred.response.signature) {
    out.response.signature = bufferToB64url(cred.response.signature);
  }
  if (cred.response.userHandle) {
    out.response.userHandle = bufferToB64url(cred.response.userHandle);
  }
  if (typeof cred.response.getPublicKey === 'function') {
    const pk = cred.response.getPublicKey();
    if (pk) out.response.publicKey = bufferToB64url(pk);
  }
  if (typeof cred.response.getAuthenticatorData === 'function') {
    const ad = cred.response.getAuthenticatorData();
    if (ad) out.response.authenticatorData = bufferToB64url(ad);
  }

  return out;
}

async function api(path, opts = {}) {
  try {
    const method = (opts.method || 'GET').toUpperCase();
    const bodyText = opts.body ? JSON.stringify(opts.body) : '';
    const headers = {
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    };
    if (sessionToken && sessionSignKey) {
      const ts = Math.floor(Date.now() / 1000).toString();
      const nonce = randomNonceB64url();
      const bodyHash = await sha256B64url(bodyText);
      const canonical = `${method}|${path}|${ts}|${nonce}|${bodyHash}`;
      const sig = await hmacSha256B64url(sessionSignKey, canonical);
      headers.Authorization = `Bearer ${sessionToken}`;
      headers['X-HWV-TS'] = ts;
      headers['X-HWV-Nonce'] = nonce;
      headers['X-HWV-Sig'] = sig;
    }

    const resp = await fetch(API_BASE + path, {
      method,
      headers,
      body: bodyText || undefined,
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      if (resp.status === 401 || resp.status === 403) {
        sessionToken = null;
        sessionSignKey = null;
        await persistSessionToken();
      }
      return { error: data.error || `HTTP ${resp.status}` };
    }
    return data;
  } catch (_) {
    showError('Cannot connect to native vault server. Start the built-in server binary first.');
    return null;
  }
}

async function getPasskeyStatus() {
  const data = await api('/webauthn/status', { method: 'POST', body: {} });
  if (data && !data.error) {
    passkeyRegistered = !!data.registered;
  }
}

async function getLinuxStatus() {
  const data = await api('/linux/status', { method: 'POST', body: {} });
  if (data && !data.error) {
    linuxBiometricAvailable = !!data.fingerprint_available;
  }
}

async function registerPasskey() {
  const optionsResp = await api('/webauthn/register/options', { method: 'POST', body: {} });
  if (!optionsResp || optionsResp.error) {
    throw new Error(optionsResp?.error || 'Failed to create registration challenge');
  }

  const credential = await navigator.credentials.create({
    publicKey: toPublicKeyOptions(optionsResp.publicKey),
  });
  if (!credential) {
    throw new Error('Passkey registration cancelled');
  }

  const verifyResp = await api('/webauthn/register/verify', {
    method: 'POST',
    body: {
      challenge_id: optionsResp.challenge_id,
      credential: serializeCredential(credential),
    },
  });

  if (!verifyResp || verifyResp.error || !verifyResp.success) {
    throw new Error(verifyResp?.error || 'Registration verify failed');
  }

  passkeyRegistered = true;
}

async function authenticatePasskey() {
  const optionsResp = await api('/webauthn/auth/options', { method: 'POST', body: {} });
  if (!optionsResp || optionsResp.error) {
    throw new Error(optionsResp?.error || 'Failed to create auth challenge');
  }

  const assertion = await navigator.credentials.get({
    publicKey: toPublicKeyOptions(optionsResp.publicKey),
  });
  if (!assertion) {
    throw new Error('Passkey authentication cancelled');
  }

  const verifyResp = await api('/webauthn/auth/verify', {
    method: 'POST',
    body: {
      challenge_id: optionsResp.challenge_id,
      credential: serializeCredential(assertion),
    },
  });

  if (!verifyResp || verifyResp.error || !verifyResp.success || !verifyResp.token || !verifyResp.session_key) {
    throw new Error(verifyResp?.error || 'Authentication verify failed');
  }

  sessionToken = verifyResp.token;
  sessionSignKey = verifyResp.session_key || null;
  await persistSessionToken();
}

async function authenticateLinuxFingerprint() {
  const response = await new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'hwvault-unlock-fingerprint' }, (res) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }
      resolve(res || { ok: false, error: 'No response from background service' });
    });
  });
  if (!response.ok) {
    throw new Error(response.error || 'Linux fingerprint authentication failed');
  }
  await loadSessionToken();
  if (!hasSession()) {
    throw new Error('Linux fingerprint authentication failed');
  }
}

function updateStatus(unlocked) {
  const status = $('status');
  const unlockBtn = $('unlockBtn');
  const lockBtn = $('lockBtn');
  const fingerprintBtn = $('fingerprintBtn');
  const fingerprintSection = $('fingerprintSection');
  const newBtn = $('newBtn');

  fingerprintSection.style.display = 'block';
  if (newBtn) newBtn.disabled = !unlocked;

  if (unlocked) {
    status.textContent = 'Unlocked';
    status.className = 'status unlocked';
    unlockBtn.style.display = 'none';
    lockBtn.style.display = 'block';
    fingerprintBtn.innerHTML = '<span>👆</span> Re-authenticate';
  } else {
    status.textContent = 'Locked';
    status.className = 'status locked';
    unlockBtn.style.display = 'block';
    lockBtn.style.display = 'none';

    if (passkeyRegistered) {
      unlockBtn.innerHTML = '<span>🔓</span> Unlock with Passkey';
      fingerprintBtn.innerHTML = '<span>👆</span> Use Passkey';
    } else if (linuxBiometricAvailable) {
      unlockBtn.innerHTML = '<span>👆</span> Unlock with Fingerprint';
      fingerprintBtn.innerHTML = '<span>👆</span> Use Fingerprint';
    } else {
      unlockBtn.innerHTML = '<span>🔑</span> Register Passkey';
      fingerprintBtn.innerHTML = '<span>👆</span> Register Passkey';
    }
  }
}

function setEditPanelVisible(visible) {
  const panel = $('editPanel');
  if (!panel) return;
  panel.classList.toggle('show', !!visible);
}

function setEditError(msg) {
  const el = $('editError');
  if (!el) return;
  if (!msg) {
    el.style.display = 'none';
    el.textContent = '';
    return;
  }
  el.textContent = msg;
  el.style.display = 'block';
}

function clearEditForm() {
  $('editType').value = 'password';
  $('editName').value = '';
  $('editUrl').value = '';
  $('editUser').value = '';
  $('editPass').value = '';
  $('editOtp').value = '';
  $('editTags').value = '';
  $('editFolder').value = '';
  $('editNote').value = '';
  $('editPayload').value = '';
  setEditError('');
}

function openCreateForm() {
  if (!hasSession()) {
    showError('Unlock vault first');
    return;
  }
  editMode = 'create';
  editingEntryId = null;
  clearEditForm();
  applyPayloadTemplate(true);
  setEditPanelVisible(true);
}

function openEditForm() {
  if (!hasSession()) {
    showError('Unlock vault first');
    return;
  }
  if (!currentEntry || !currentEntry.entry_id) {
    showError('No entry selected');
    return;
  }
  editMode = 'edit';
  editingEntryId = currentEntry.entry_id;

  $('editType').value = currentEntry.credential_type || 'password';
  $('editName').value = currentEntry.name || '';
  $('editUrl').value = currentEntry.url || '';
  $('editUser').value = currentEntry.user || '';
  $('editPass').value = currentEntry.pass || '';
  $('editOtp').value = currentEntry.otp || '';
  $('editTags').value = (currentEntry.tags || []).join(', ');
  $('editFolder').value = currentEntry.folder || '';
  $('editNote').value = currentEntry.note || '';
  $('editPayload').value = Object.keys(currentEntry.payload || {}).length ? JSON.stringify(currentEntry.payload, null, 2) : '';

  setEditPanelVisible(true);
}

function cancelEditForm() {
  editMode = null;
  editingEntryId = null;
  setEditError('');
  setEditPanelVisible(false);
}

function payloadTemplateForType(type) {
  return PAYLOAD_TEMPLATES[type] || {};
}

function applyPayloadTemplate(force = false) {
  const type = $('editType').value.trim() || 'password';
  const el = $('editPayload');
  if (!el) return;
  if (!force && el.value.trim()) return;
  const tpl = payloadTemplateForType(type);
  el.value = Object.keys(tpl).length ? JSON.stringify(tpl, null, 2) : '';
}

function validateTypedPayload(credentialType, payload) {
  if (!payload || typeof payload !== 'object') return 'Payload must be a JSON object';
  if (credentialType === 'password') return '';
  if (credentialType === 'ssh_key') {
    const p = payload.ssh_key;
    if (!p || typeof p !== 'object') return 'ssh_key payload object is required';
    if (!('private_pem' in p) || !('public' in p)) return 'ssh_key payload must include private_pem and public';
    return '';
  }
  if (credentialType === 'gpg_key') {
    const p = payload.gpg_key;
    if (!p || typeof p !== 'object') return 'gpg_key payload object is required';
    if (!('armored_private' in p) || !('armored_public' in p)) return 'gpg_key payload must include armored_private and armored_public';
    return '';
  }
  if (credentialType === 'mtls_cert') {
    const p = payload.mtls_cert;
    if (!p || typeof p !== 'object') return 'mtls_cert payload object is required';
    if (!('cert_pem' in p) || !('key_pem' in p)) return 'mtls_cert payload must include cert_pem and key_pem';
    return '';
  }
  if (credentialType === 'api_token') {
    const p = payload.api_token;
    if (!p || typeof p !== 'object') return 'api_token payload object is required';
    if (!('token' in p)) return 'api_token payload must include token';
    return '';
  }
  if (credentialType === 'note') {
    const p = payload.note;
    if (!p || typeof p !== 'object') return 'note payload object is required';
    return '';
  }
  if (credentialType === 'binary_blob') {
    const p = payload.binary_blob;
    if (!p || typeof p !== 'object') return 'binary_blob payload object is required';
    if (!('mime' in p) || !('base64' in p)) return 'binary_blob payload must include mime and base64';
    return '';
  }
  return '';
}

function buildTypedPayloadFromForm() {
  const credential_type = $('editType').value.trim();
  const name = $('editName').value.trim();
  const payloadRaw = $('editPayload').value.trim();
  let payload = {};
  if (payloadRaw) {
    try {
      payload = JSON.parse(payloadRaw);
    } catch (_) {
      throw new Error('Payload JSON is invalid');
    }
  }
  const payloadErr = validateTypedPayload(credential_type, payload);
  if (payloadErr) {
    throw new Error(payloadErr);
  }

  const tags = $('editTags').value
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);

  return {
    credential_type,
    name,
    username: $('editUser').value || '',
    password: $('editPass').value || '',
    url: $('editUrl').value || '',
    note: $('editNote').value || '',
    otp: $('editOtp').value || '',
    tags,
    folder: $('editFolder').value || '',
    payload,
  };
}

async function saveEditForm() {
  if (!hasSession()) {
    showError('Unlock vault first');
    return;
  }

  let payload;
  try {
    payload = buildTypedPayloadFromForm();
    setEditError('');
  } catch (e) {
    setEditError(e.message || 'Invalid form');
    return;
  }

  if (!payload.credential_type || !payload.name) {
    setEditError('Credential type and name are required');
    return;
  }

  let resp;
  if (editMode === 'edit' && editingEntryId) {
    resp = await api('/entry/update-typed', {
      method: 'POST',
      body: { entry_id: editingEntryId, ...payload },
    });
  } else {
    resp = await api('/entry/store-typed', {
      method: 'POST',
      body: payload,
    });
  }

  if (!resp || resp.error || !resp.success) {
    setEditError(resp?.error || 'Failed to save credential');
    return;
  }

  showToast(editMode === 'edit' ? 'Entry updated' : 'Entry created');
  cancelEditForm();
  await loadEntries();
}

async function fetchEntryData(entryId) {
  if (!entryId) return null;
  if (entryDataCache[entryId]) return entryDataCache[entryId];

  const data = await api('/entry/get/' + encodeURIComponent(entryId));
  if (!data || data.error) return data;

  const normalized = normalizeEntry(data);
  if (!normalized) return { error: 'Invalid entry payload' };

  entryDataCache[entryId] = normalized;
  return normalized;
}

function queryActiveTab() {
  const isUsable = (tab) => !!(tab && tab.id && tab.url && /^https?:\/\//i.test(tab.url));
  return new Promise((resolve, reject) => {
    chrome.storage.local.get([LAST_ACTIVE_TAB_ID_KEY], (obj) => {
      const rememberedId = Number(obj[LAST_ACTIVE_TAB_ID_KEY] || 0);
      if (rememberedId > 0) {
        chrome.tabs.get(rememberedId, (tab) => {
          if (!chrome.runtime.lastError && isUsable(tab)) {
            resolve(tab);
            return;
          }
          chrome.tabs.query({ lastFocusedWindow: true }, (tabs) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
              return;
            }
            const usable = (tabs || [])
              .filter(isUsable)
              .sort((a, b) => {
                const activeDelta = Number(Boolean(b.active)) - Number(Boolean(a.active));
                if (activeDelta !== 0) return activeDelta;
                return Number(b.lastAccessed || 0) - Number(a.lastAccessed || 0);
              })[0];
            resolve(usable || null);
          });
        });
        return;
      }

      chrome.tabs.query({ lastFocusedWindow: true }, (tabs) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        const usable = (tabs || [])
          .filter(isUsable)
          .sort((a, b) => {
            const activeDelta = Number(Boolean(b.active)) - Number(Boolean(a.active));
            if (activeDelta !== 0) return activeDelta;
            return Number(b.lastAccessed || 0) - Number(a.lastAccessed || 0);
          })[0];
        resolve(usable || null);
      });
    });
  });
}

function executeAutofill(tabId, username, password, entryMeta = {}) {
  return new Promise((resolve, reject) => {
    chrome.scripting.executeScript(
      {
        target: { tabId },
        func: (u, p, meta) => {
          const isEditable = (el) =>
            el && !el.disabled && !el.readOnly && el.offsetParent !== null && el.type !== 'hidden';

          const setValue = (el, value) => {
            if (!el || value == null) return;
            const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
            const desc = Object.getOwnPropertyDescriptor(proto, 'value');
            if (desc && desc.set) desc.set.call(el, value);
            else el.value = value;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
          };

          const inputs = Array.from(document.querySelectorAll('input,textarea'));
          const passwordField = inputs.find((el) => el.tagName === 'INPUT' && el.type === 'password' && isEditable(el));
          if (!passwordField) {
            return { ok: false, reason: 'No password field detected on this page' };
          }

          const userCandidates = inputs.filter((el) => {
            if (!isEditable(el)) return false;
            if (el === passwordField) return false;
            const tag = el.tagName.toLowerCase();
            const type = (el.type || '').toLowerCase();
            if (tag === 'textarea') return true;
            return ['text', 'email', 'tel', 'search', 'url'].includes(type);
          });

          const rank = (el) => {
            const s = `${el.name || ''} ${el.id || ''} ${el.autocomplete || ''} ${el.placeholder || ''}`.toLowerCase();
            if (s.includes('username') || s.includes('email') || s.includes('login') || s.includes('user')) return 100;
            if (el.type === 'email') return 90;
            return 10;
          };

          userCandidates.sort((a, b) => rank(b) - rank(a));
          const userField = userCandidates[0] || null;

          if (userField && u) setValue(userField, u);
          setValue(passwordField, p || '');

          const form = passwordField.form || (userField ? userField.form : null);
          if (form && !form.__hwvaultHooked) {
            form.__hwvaultHooked = true;
            form.addEventListener('submit', () => {
              try {
                const newPass = passwordField.value || '';
                const newUser = userField ? (userField.value || '') : '';
                if (!newPass || newPass === (meta.password || '')) return;
                if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
                  chrome.runtime.sendMessage({
                    type: 'hwvault-password-change-detected',
                    payload: {
                      entry_id: meta.entry_id || '',
                      name: meta.name || document.title || location.hostname,
                      username: newUser || meta.username || '',
                      password: newPass,
                      url: location.origin,
                      note: meta.note || '',
                      otp: meta.otp || '',
                    },
                  });
                }
              } catch (_) {}
            }, { capture: true });
          }

          return {
            ok: true,
            filledUser: Boolean(userField && u),
            filledPass: true,
          };
        },
        args: [username || '', password || '', entryMeta || {}],
      },
      (results) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(results && results[0] ? results[0].result : null);
      }
    );
  });
}

async function touchEntryUsage(entryId, origin) {
  if (!entryId || !hasSession()) return;
  try {
    await api('/entry/touch', {
      method: 'POST',
      body: {
        entry_id: entryId,
        origin: origin || 'autofill',
      },
    });
  } catch (_) {}
}

function generateSecurePassword(length = 24) {
  if (typeof HWPasswordUtils !== 'undefined' && HWPasswordUtils.generateSecurePassword) {
    return HWPasswordUtils.generateSecurePassword(length);
  }
  throw new Error('password generator unavailable');
}

async function saveEntryPassword(entry, newPassword) {
  if (entry?.credential_type && entry.credential_type !== 'password') {
    throw new Error('Password generation is only available for password credentials');
  }
  if (!entry?.entry_id) {
    throw new Error('No selected entry');
  }

  const payload = {
    entry_id: entry.entry_id,
    credential_type: 'password',
    name: entry.name || '',
    username: entry.user || '',
    password: newPassword,
    url: entry.url || '',
    note: entry.note || '',
    otp: entry.otp || '',
    tags: entry.tags || [],
    folder: entry.folder || '',
    payload: entry.payload || {},
  };

  const resp = await api('/entry/update-typed', { method: 'POST', body: payload });
  if (!resp || resp.error || !resp.success) {
    throw new Error(resp?.error || 'Failed to update password');
  }
}

async function generatePasswordForCurrentEntry() {
  const generated = generateSecurePassword(24);
  if (!currentEntry || !currentEntry.name) {
    copyToClipboard(generated);
    showToast('Generated and copied');
    return;
  }
  if (!hasSession()) {
    showError('Unlock vault first');
    return;
  }

  try {
    await saveEntryPassword(currentEntry, generated);
    currentEntry.pass = generated;
    $('detailPass').textContent = generated;
    $('detailPassBox').classList.add('revealed');
    copyToClipboard(generated);
    showToast('Generated, saved, and copied');
  } catch (e) {
    showError(e.message || 'Password generation failed');
  }
}

async function autofillCurrentSite() {
  hideError();
  if (!hasSession()) {
    showError('Unlock vault first');
    return;
  }

  const tab = await queryActiveTab();
  if (!tab || !tab.id || !tab.url) {
    showError('No active tab detected');
    return;
  }
  if (!/^https?:\/\//i.test(tab.url)) {
    showError('Autofill only works on http/https pages');
    return;
  }

  const targetHost = HWAutofillMatcher.normalizeHost(tab.url);
  if (!targetHost) {
    showError('Could not determine site hostname');
    return;
  }

  if (!allEntries.length) {
    const listData = await api('/entry/list');
    if (!listData || listData.error) {
      showError(listData?.error || 'Failed to load entries');
      return;
    }
    allEntries = (listData.entries || []).map(normalizeEntry).filter(Boolean);
  }

  const candidates = allEntries.filter((entry) => entry.credential_type === 'password' && (entry.pass || entry.user));
  const matches = HWAutofillMatcher.rankMatches(targetHost, candidates);
  if (!matches.length) {
    showError(`No password entry matched ${targetHost}`);
    return;
  }

  const exactMatches = HWAutofillMatcher.preferExactMatches(matches);
  let effectiveMatches = exactMatches;
  if (effectiveMatches.length === matches.length && matches[0] && matches[0].score < 100) {
    const allowed = await isRelaxedAllowed(targetHost);
    if (!allowed) {
      const ok = confirm(`No exact hostname match for ${targetHost}. Allow relaxed autofill for this site?`);
      if (!ok) {
        showError('Autofill cancelled (exact match required)');
        return;
      }
      await allowRelaxedForHost(targetHost);
    }
    effectiveMatches = matches;
  }

  if (effectiveMatches.length === 1) {
    try {
      const picked = effectiveMatches[0];
      const result = await executeAutofill(tab.id, picked.user || '', picked.pass || '', {
        entry_id: picked.entry_id || '',
        name: picked.name || '',
        username: picked.user || '',
        password: picked.pass || '',
        note: picked.note || '',
        otp: picked.otp || '',
      });
      if (!result || !result.ok) {
        showError(result?.reason || 'Could not fill fields on this page');
        return;
      }
      await touchEntryUsage(picked.entry_id, 'autofill');
      chrome.runtime.sendMessage({
        type: 'hwvault-canonical-pick',
        entry_id: picked.entry_id || '',
        url: tab.url || '',
      });
      showToast(`Autofilled for ${targetHost}`);
    } catch (e) {
      showError(e.message || 'Autofill failed');
    }
    return;
  }

  pendingAutofillMatches = effectiveMatches;
  pendingAutofillTabId = tab.id;
  const select = $('autofillSelect');
  select.innerHTML = '';

  effectiveMatches.forEach((m, idx) => {
    const opt = document.createElement('option');
    const userPart = m.user ? ` (${m.user})` : '';
    const hostPart = m.url ? ` - ${HWAutofillMatcher.normalizeHost(m.url)}` : '';
    opt.value = String(idx);
    opt.textContent = `${m.name}${userPart}${hostPart}`;
    select.appendChild(opt);
  });

  $('autofillPicker').style.display = 'block';
}

async function fillSelectedMatch() {
  const picker = $('autofillPicker');
  if (!pendingAutofillMatches.length || !pendingAutofillTabId) {
    picker.style.display = 'none';
    return;
  }

  const idx = Number($('autofillSelect').value || '0');
  const picked = pendingAutofillMatches[idx];
  if (!picked) {
    showError('Invalid credential selection');
    return;
  }

  try {
    const result = await executeAutofill(pendingAutofillTabId, picked.user || '', picked.pass || '', {
      entry_id: picked.entry_id || '',
      name: picked.name || '',
      username: picked.user || '',
      password: picked.pass || '',
      note: picked.note || '',
      otp: picked.otp || '',
    });
    if (!result || !result.ok) {
      showError(result?.reason || 'Could not fill fields on this page');
      return;
    }
    await touchEntryUsage(picked.entry_id, 'autofill');
    const tabForUrl = await chrome.tabs.get(pendingAutofillTabId).catch(() => null);
    chrome.runtime.sendMessage({
      type: 'hwvault-canonical-pick',
      entry_id: picked.entry_id || '',
      url: tabForUrl?.url || '',
    });
    showToast(`Autofilled: ${picked.name}`);
    picker.style.display = 'none';
    pendingAutofillMatches = [];
    pendingAutofillTabId = null;
  } catch (e) {
    showError(e.message || 'Autofill failed');
  }
}

function cancelAutofillSelection() {
  $('autofillPicker').style.display = 'none';
  pendingAutofillMatches = [];
  pendingAutofillTabId = null;
}

function renderEntries(entries) {
  const container = $('entries');
  const stats = $('stats');
  const entryCount = $('entryCount');

  container.innerHTML = '';

  if (entries.length === 0) {
    container.innerHTML = '<div class="empty"><div class="empty-icon">🔐</div><div class="empty-text">No entries found</div></div>';
    stats.style.display = 'none';
    return;
  }

  entryCount.textContent = entries.length;
  stats.style.display = 'block';

  entries.forEach((entry) => {
    const entryId = entry.entry_id || '';
    const name = entry.name || '';
    const url = entry.url || '';
    const hasOtp = !!entry.otp;
    const type = entry.credential_type || 'password';
    if (!entryId || !name) return;

    entryDataCache[entryId] = entry;

    const div = document.createElement('div');
    div.className = 'entry';
    div.innerHTML = `
      <div class="entry-info" data-entry-id="${escapeHtml(entryId).replace(/"/g, '&quot;')}">
        <div class="entry-name">
          ${escapeHtml(name)}
          <span class="icon">[${escapeHtml(type)}]</span>
          ${hasOtp ? '<span class="icon">🔐</span>' : ''}
        </div>
        <div class="entry-url">${url ? escapeHtml(url) : 'Click to view'}</div>
      </div>
      <div class="entry-actions">
        <button class="entry-btn" title="Copy Password" data-action="pass" data-entry-id="${escapeHtml(entryId).replace(/"/g, '&quot;')}">🔑</button>
        <button class="entry-btn" title="Copy OTP" data-action="otp" data-entry-id="${escapeHtml(entryId).replace(/"/g, '&quot;')}" ${!hasOtp ? 'style="display:none"' : ''}>🔐</button>
        <button class="entry-btn" title="Copy Username" data-action="user" data-entry-id="${escapeHtml(entryId).replace(/"/g, '&quot;')}">👤</button>
      </div>
    `;
    container.appendChild(div);
  });

  container.querySelectorAll('.entry-info').forEach((info) => {
    info.addEventListener('click', () => showDetails(info.dataset.entryId));
  });

  container.querySelectorAll('.entry-btn').forEach((btn) => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const entryId = btn.dataset.entryId;
      const action = btn.dataset.action;

      const data = await fetchEntryData(entryId);
      if (!data || data.error) {
        showError('Failed to load entry');
        return;
      }

      if (action === 'pass') copyToClipboard(data.pass || '', btn);
      if (action === 'user') copyToClipboard(data.user || '', btn);
      if (action === 'otp' && data.otp) {
        generateTOTP(data.otp).then((code) => copyToClipboard(code, btn));
      }
    });
  });
}

async function showDetails(entryId) {
  $('entries').innerHTML = '<div class="empty"><div class="empty-icon">⏳</div><div class="empty-text">Loading...</div></div>';

  const data = await fetchEntryData(entryId);
  if (!data || data.error) {
    showError('Entry not found');
    renderEntries(allEntries);
    return;
  }

  currentEntry = data;
  $('detailTitle').textContent = `${data.name || ''} [${data.credential_type || 'password'}]`;

  const urlEl = $('detailUrl');
  if (data.url) {
    urlEl.textContent = data.url;
    urlEl.href = data.url;
    urlEl.style.pointerEvents = 'auto';
    urlEl.style.color = '#e94560';
  } else {
    urlEl.textContent = 'No URL';
    urlEl.href = 'javascript:void(0)';
    urlEl.style.pointerEvents = 'none';
    urlEl.style.color = 'rgba(255,255,255,0.3)';
  }

  $('detailUser').textContent = data.user || '';
  $('detailPass').textContent = data.pass ? '••••••••' : '';
  $('detailPass').classList.remove('revealed');
  $('genPassBtn').disabled = (data.credential_type || 'password') !== 'password';

  const otpSection = $('otpSection');
  if (data.otp) {
    currentOtpSecret = data.otp;
    otpSection.style.display = 'block';
    startOtpTimer();
  } else {
    currentOtpSecret = null;
    otpSection.style.display = 'none';
    stopOtpTimer();
  }

  $('entries').style.display = 'none';
  $('details').classList.add('show');
}

function showList() {
  $('details').classList.remove('show');
  $('entries').style.display = 'block';
  stopOtpTimer();
  $('genPassBtn').disabled = false;
}

function base32ToBytes(base32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of base32.toUpperCase().replace(/[^A-Z2-7]/g, '')) {
    bits += chars.indexOf(ch).toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

function generateTOTP(secret, timeStep = 30) {
  const key = base32ToBytes(secret);
  let time = Math.floor(Date.now() / 1000 / timeStep);
  const timeBytes = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    timeBytes[i] = time & 0xff;
    time >>>= 8;
  }

  return crypto.subtle
    .importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'])
    .then((k) => crypto.subtle.sign('HMAC', k, timeBytes))
    .then((sig) => {
      const h = new Uint8Array(sig);
      const o = h[h.length - 1] & 0xf;
      const code = ((h[o] & 0x7f) << 24) | ((h[o + 1] & 0xff) << 16) | ((h[o + 2] & 0xff) << 8) | (h[o + 3] & 0xff);
      return (code % 1000000).toString().padStart(6, '0');
    })
    .catch(() => '------');
}

function startOtpTimer() {
  stopOtpTimer();
  updateOtp();
  otpInterval = setInterval(updateOtp, 1000);
}

function stopOtpTimer() {
  if (otpInterval) {
    clearInterval(otpInterval);
    otpInterval = null;
  }
}

function updateOtp() {
  if (!currentOtpSecret) return;
  const timeStep = 30;
  const remaining = timeStep - (Math.floor(Date.now() / 1000) % timeStep);

  const timerEl = $('otpTimer');
  timerEl.textContent = 'Regenerates in ' + remaining + 's';
  timerEl.className = 'otp-timer' + (remaining <= 5 ? ' warning' : '');

  if (remaining === timeStep || remaining === timeStep - 1) {
    generateTOTP(currentOtpSecret).then((code) => {
      $('otpCode').textContent = code.slice(0, 3) + ' ' + code.slice(3);
    });
  }
}

async function checkStatus() {
  await loadSessionToken();
  await getPasskeyStatus();
  await getLinuxStatus();
  const data = await api('/health');
  const unlocked = !!(data && data.authenticated);
  if (!unlocked && (sessionToken || sessionSignKey)) {
    sessionToken = null;
    sessionSignKey = null;
    await persistSessionToken();
  }
  updateStatus(unlocked);

  if (unlocked) {
    await loadEntries();
    hideError();
  } else {
    $('entries').innerHTML = '<div class="empty"><div class="empty-icon">🔐</div><div class="empty-text">Vault is locked</div></div>';
    $('stats').style.display = 'none';
  }
}

async function loadEntries() {
  const data = await api('/entry/list');
  if (!data) return;
  if (data.error) {
    if (data.error.includes('unauthorized')) {
      sessionToken = null;
      sessionSignKey = null;
      await persistSessionToken();
      updateStatus(false);
    }
    showError(data.error);
    return;
  }

  allEntries = (data.entries || []).map(normalizeEntry).filter(Boolean);
  entryDataCache = {};
  renderEntries(allEntries);
}

async function deleteCurrentEntry() {
  if (!hasSession()) {
    showError('Unlock vault first');
    return;
  }
  if (!currentEntry || !currentEntry.entry_id) {
    showError('No entry selected');
    return;
  }

  const ok = confirm(`Delete credential "${currentEntry.name}"?`);
  if (!ok) return;

  const resp = await api('/entry/delete', {
    method: 'POST',
    body: { entry_id: currentEntry.entry_id },
  });

  if (!resp || resp.error || !resp.success) {
    showError(resp?.error || 'Failed to delete entry');
    return;
  }

  showToast('Entry deleted');
  currentEntry = null;
  showList();
  await loadEntries();
}

async function unlockWithPasskey() {
  hideError();

  const btn = $('fingerprintBtn');
  btn.disabled = true;

  try {
    if (linuxBiometricAvailable) {
      btn.textContent = 'Scanning fingerprint...';
      await authenticateLinuxFingerprint();
      await checkStatus();
      if (!hasSession()) throw new Error('Fingerprint unlock failed');
      await loadEntries();
      showToast('Unlocked');
    } else {
      if (!window.PublicKeyCredential) {
        throw new Error('Passkeys are not supported in this browser context');
      }
      let platformAvailable = true;
      if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
        try {
          platformAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        } catch (_) {}
      }
      if (!platformAvailable) {
        throw new Error('No platform authenticator available. Use Linux fingerprint or security key.');
      }
      if (!passkeyRegistered) {
        btn.textContent = 'Registering passkey...';
        await registerPasskey();
        showToast('Passkey registered. Tap again to unlock.');
        updateStatus(false);
        return;
      }
      btn.textContent = 'Authenticating...';
      await authenticatePasskey();
      await checkStatus();
      if (!hasSession()) throw new Error('Passkey unlock failed');
      await loadEntries();
      showToast('Unlocked');
    }
  } catch (e) {
    showError(e.message || 'Passkey operation failed');
  } finally {
    btn.disabled = false;
    updateStatus(hasSession());
  }
}

async function lockVault() {
  await api('/lock', { method: 'POST', body: {} });
  sessionToken = null;
  sessionSignKey = null;
  await persistSessionToken();
  allEntries = [];
  entryDataCache = {};
  currentEntry = null;
  cancelEditForm();
  updateStatus(false);
  $('entries').innerHTML = '<div class="empty"><div class="empty-icon">🔐</div><div class="empty-text">Vault is locked</div></div>';
  $('stats').style.display = 'none';
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text || '').then(() => {
    if (!btn) {
      showToast('Copied');
      return;
    }

    const original = btn.textContent;
    btn.textContent = '✓';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = original;
      btn.classList.remove('copied');
    }, 1200);
  });
}

function init() {
  if (window.__hwvaultInit) return;
  window.__hwvaultInit = true;

  $('unlockBtn').addEventListener('click', unlockWithPasskey);
  $('fingerprintBtn').addEventListener('click', unlockWithPasskey);
  $('autofillBtn').addEventListener('click', autofillCurrentSite);
  $('genPassBtn').addEventListener('click', generatePasswordForCurrentEntry);
  $('fillSelectedBtn').addEventListener('click', fillSelectedMatch);
  $('cancelFillBtn').addEventListener('click', cancelAutofillSelection);
  $('lockBtn').addEventListener('click', lockVault);
  $('refreshBtn').addEventListener('click', loadEntries);
  $('newBtn').addEventListener('click', openCreateForm);
  $('backBtn').addEventListener('click', showList);
  $('editBtn').addEventListener('click', openEditForm);
  $('saveEditBtn').addEventListener('click', saveEditForm);
  $('cancelEditBtn').addEventListener('click', cancelEditForm);
  $('payloadTemplateBtn').addEventListener('click', () => applyPayloadTemplate(true));
  $('editType').addEventListener('change', () => {
    setEditError('');
    applyPayloadTemplate(false);
  });

  const deleteBtn = $('deleteBtn');
  if (deleteBtn) deleteBtn.addEventListener('click', deleteCurrentEntry);

  $('search').addEventListener('input', (e) => {
    const q = e.target.value.toLowerCase().trim();
    if (!q) {
      renderEntries(allEntries);
      return;
    }

    const filtered = allEntries.filter((entry) => {
      const name = (entry.name || '').toLowerCase();
      const user = (entry.user || '').toLowerCase();
      const url = (entry.url || '').toLowerCase();
      const type = (entry.credential_type || '').toLowerCase();
      const folder = (entry.folder || '').toLowerCase();
      const tags = (entry.tags || []).join(' ').toLowerCase();
      return name.includes(q) || user.includes(q) || url.includes(q) || type.includes(q) || folder.includes(q) || tags.includes(q);
    });
    renderEntries(filtered);
  });

  $('detailPassBox').addEventListener('click', function onPassClick(e) {
    if (e.target.tagName === 'BUTTON') return;
    if (!currentEntry || !currentEntry.pass) return;

    const passEl = $('detailPass');
    if (passEl.textContent.includes('•')) {
      passEl.textContent = currentEntry.pass;
      this.classList.add('revealed');
    } else {
      passEl.textContent = '••••••••';
      this.classList.remove('revealed');
    }
  });

  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const field = btn.dataset.field;
      if (field === 'detailUser') copyToClipboard($('detailUser').textContent, btn);
      if (field === 'detailPass') copyToClipboard(currentEntry?.pass || '', btn);
      if (field === 'detailUrl') copyToClipboard($('detailUrl').href, btn);
    });
  });

  const copyOtp = $('copyOtp');
  if (copyOtp) {
    copyOtp.addEventListener('click', () => {
      const code = $('otpCode').textContent.replace(' ', '');
      copyToClipboard(code, copyOtp);
    });
  }

  const copyAll = $('copyAll');
  if (copyAll) {
    copyAll.addEventListener('click', () => {
      if (!currentEntry) return;
      const text = [
        `Type: ${currentEntry.credential_type || ''}`,
        `Name: ${currentEntry.name || ''}`,
        `URL: ${currentEntry.url || ''}`,
        `User: ${currentEntry.user || ''}`,
        `Pass: ${currentEntry.pass || ''}`,
        `Tags: ${(currentEntry.tags || []).join(', ')}`,
        `Folder: ${currentEntry.folder || ''}`,
      ].join('\n');
      copyToClipboard(text, copyAll);
    });
  }

  checkStatus();
}

document.addEventListener('DOMContentLoaded', init);
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  init();
}
