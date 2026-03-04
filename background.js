const API_BASE = 'http://127.0.0.1:8877';
const SESSION_KEY = 'hwvault_session_token';
const SESSION_SIGN_KEY = 'hwvault_session_sign_key';
const CHANGE_DEBOUNCE_MS = 700;
const RETRY_DELAYS_MS = [200, 500, 1000];
const RECENT_WINDOW_MS = 15000;

const AUTO_POLICY_KEY = 'hwvault_auto_policy';
const LAST_ACTIVE_TAB_ID_KEY = 'hwvault_last_active_tab_id';
const DEFAULT_AUTO_POLICY = {
  enabled: true,
  autoSubmit: true,
  exactOnly: true,
};
const CANONICAL_BY_HOST_KEY = 'hwvault_canonical_entry_by_host';

const pendingByKey = new Map();
const recentSavedByKey = new Map();
const recentAutofillByTabHost = new Map();

let entriesCache = [];
let entriesCacheTs = 0;
const ENTRIES_CACHE_TTL_MS = 30000;

function rememberLastActiveTab(tabId, url) {
  if (!tabId || !/^https?:\/\//i.test(url || '')) return;
  chrome.storage.local.set({ [LAST_ACTIVE_TAB_ID_KEY]: tabId }, () => {});
}

function getCanonicalMap() {
  return new Promise((resolve) => {
    chrome.storage.local.get([CANONICAL_BY_HOST_KEY], (obj) => {
      resolve(obj[CANONICAL_BY_HOST_KEY] || {});
    });
  });
}

function setCanonicalForHost(host, entryId) {
  if (!host || !entryId) return Promise.resolve();
  return new Promise((resolve) => {
    chrome.storage.local.get([CANONICAL_BY_HOST_KEY], (obj) => {
      const next = { ...(obj[CANONICAL_BY_HOST_KEY] || {}) };
      next[host] = entryId;
      chrome.storage.local.set({ [CANONICAL_BY_HOST_KEY]: next }, () => resolve());
    });
  });
}

function getSessionToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get([SESSION_KEY, SESSION_SIGN_KEY], (obj) => {
      resolve({
        token: obj[SESSION_KEY] || null,
        sessionKey: obj[SESSION_SIGN_KEY] || null,
      });
    });
  });
}

function getAutoPolicy() {
  return new Promise((resolve) => {
    chrome.storage.local.get([AUTO_POLICY_KEY], (obj) => {
      resolve({ ...DEFAULT_AUTO_POLICY, ...(obj[AUTO_POLICY_KEY] || {}) });
    });
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

function persistSession(token, sessionKey) {
  return new Promise((resolve) => {
    if (!token || !sessionKey) {
      chrome.storage.local.remove([SESSION_KEY, SESSION_SIGN_KEY], () => resolve());
      return;
    }
    chrome.storage.local.set(
      { [SESSION_KEY]: token, [SESSION_SIGN_KEY]: sessionKey },
      () => resolve()
    );
  });
}

async function api(path, opts = {}) {
  const { token, sessionKey } = await getSessionToken();
  const method = (opts.method || 'GET').toUpperCase();
  const bodyText = opts.body ? JSON.stringify(opts.body) : '';
  const headers = {
    'Content-Type': 'application/json',
    ...(opts.headers || {}),
  };
  if (token && sessionKey) {
    const ts = Math.floor(Date.now() / 1000).toString();
    const nonce = randomNonceB64url();
    const bodyHash = await sha256B64url(bodyText);
    const canonical = `${method}|${path}|${ts}|${nonce}|${bodyHash}`;
    const sig = await hmacSha256B64url(sessionKey, canonical);
    headers.Authorization = `Bearer ${token}`;
    headers['X-HWV-TS'] = ts;
    headers['X-HWV-Nonce'] = nonce;
    headers['X-HWV-Sig'] = sig;
  }

  const resp = await fetch(API_BASE + path, {
    method,
    headers,
    body: bodyText || undefined,
  });

  let data = {};
  try {
    data = await resp.json();
  } catch (_) {}

  if (!resp.ok) {
    if (resp.status === 401 || resp.status === 403) {
      await new Promise((resolve) => {
        chrome.storage.local.remove([SESSION_KEY, SESSION_SIGN_KEY], () => resolve());
      });
    }
    throw new Error(data.error || `HTTP ${resp.status}`);
  }
  return data;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function keyForPayload(payload) {
  if (payload.entry_id) return `id:${payload.entry_id}`;
  return `name:${payload.name || ''}`;
}

async function postWithRetry(path, body) {
  let lastErr = null;
  for (let i = 0; i < RETRY_DELAYS_MS.length + 1; i++) {
    try {
      return await api(path, { method: 'POST', body });
    } catch (e) {
      lastErr = e;
      if (i < RETRY_DELAYS_MS.length) {
        await sleep(RETRY_DELAYS_MS[i]);
      }
    }
  }
  throw lastErr || new Error('request failed');
}

async function fetchCurrentPassword(payload) {
  if (payload.entry_id) {
    try {
      const res = await api('/entry/get/' + encodeURIComponent(payload.entry_id));
      return res.password || res.pass || '';
    } catch (_) {
      return null;
    }
  }
  if (payload.name) {
    try {
      const res = await api('/get/' + encodeURIComponent(payload.name));
      return res.password || res.pass || '';
    } catch (_) {
      return null;
    }
  }
  return null;
}

function rememberRecentSaved(key, password) {
  recentSavedByKey.set(key, { password, ts: Date.now() });
}

function isRecentlySaved(key, password) {
  const recent = recentSavedByKey.get(key);
  if (!recent) return false;
  if (Date.now() - recent.ts > RECENT_WINDOW_MS) {
    recentSavedByKey.delete(key);
    return false;
  }
  return recent.password === password;
}

async function processPasswordChange(payload) {
  if (!payload.password) throw new Error('invalid password change payload');

  const key = keyForPayload(payload);
  if (isRecentlySaved(key, payload.password)) return { skipped: true, reason: 'duplicate_recent' };

  const currentPassword = await fetchCurrentPassword(payload);
  if (currentPassword !== null && currentPassword === payload.password) {
    rememberRecentSaved(key, payload.password);
    return { skipped: true, reason: 'unchanged' };
  }

  if (payload.entry_id) {
    if (!payload.name) throw new Error('invalid payload: missing name for entry update');
    await postWithRetry('/entry/update', {
      entry_id: payload.entry_id,
      name: payload.name,
      username: payload.username || '',
      password: payload.password,
      url: payload.url || '',
      note: payload.note || '',
      otp: payload.otp || '',
      origin: 'detected-change',
    });
    rememberRecentSaved(key, payload.password);
    return { updated: true };
  }

  if (!payload.name) throw new Error('invalid payload: missing name');

  await postWithRetry('/store', {
    name: payload.name,
    username: payload.username || '',
    password: payload.password,
    url: payload.url || '',
    note: payload.note || '',
    otp: payload.otp || '',
  });
  rememberRecentSaved(key, payload.password);
  return { stored: true };
}

function queuePasswordChange(payload) {
  const key = keyForPayload(payload);
  const pending = pendingByKey.get(key);
  if (pending) {
    pending.payload = payload;
    return pending.promise;
  }

  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });

  const state = { payload, timer: null, promise };
  state.timer = setTimeout(async () => {
    pendingByKey.delete(key);
    try {
      const result = await processPasswordChange(state.payload);
      resolvePromise(result);
    } catch (e) {
      rejectPromise(e);
    }
  }, CHANGE_DEBOUNCE_MS);

  pendingByKey.set(key, state);
  return promise;
}

function normalizeHost(input) {
  if (!input) return '';
  try {
    const url = input.includes('://') ? new URL(input) : new URL(`https://${input}`);
    return (url.hostname || '').toLowerCase().replace(/^www\./, '');
  } catch (_) {
    return '';
  }
}

function scoreEntryForHost(entryName, entryUrl, targetHost) {
  const host = normalizeHost(entryUrl);
  if (!host || !targetHost) return 0;
  if (host === targetHost) return 100;
  if (targetHost.endsWith(`.${host}`) || host.endsWith(`.${targetHost}`)) return 80;
  if ((entryUrl || '').toLowerCase().includes(targetHost)) return 60;
  if ((entryName || '').toLowerCase().includes(targetHost)) return 40;
  return 0;
}

function rankMatches(targetHost, candidates) {
  const scored = [];
  for (const c of candidates || []) {
    const score = scoreEntryForHost(c.name || '', c.url || '', targetHost);
    if (score > 0) scored.push({ ...c, score });
  }
  scored.sort((a, b) => (b.score - a.score) || (a.name || '').localeCompare(b.name || ''));
  return scored;
}

async function fetchEntriesCached() {
  if (Date.now() - entriesCacheTs < ENTRIES_CACHE_TTL_MS && entriesCache.length) return entriesCache;
  const listData = await api('/entry/list');
  const entries = (listData.entries || []).filter((e) => e.credential_type === 'password' && (e.pass || e.user));
  entriesCache = entries;
  entriesCacheTs = Date.now();
  return entries;
}

function shouldSkipRecentAutofill(tabId, host) {
  const key = `${tabId}:${host}`;
  const ts = recentAutofillByTabHost.get(key) || 0;
  if (Date.now() - ts < 12000) return true;
  recentAutofillByTabHost.set(key, Date.now());
  return false;
}

async function tryAutofillTab(tabId, pageUrl) {
  try {
    if (!/^https?:\/\//i.test(pageUrl || '')) return;
    await installCaptureHook(tabId);

    const { token, sessionKey } = await getSessionToken();
    if (!token || !sessionKey) return;

    const policy = await getAutoPolicy();
    if (!policy.enabled) return;

    const host = normalizeHost(pageUrl);
    if (!host || shouldSkipRecentAutofill(tabId, host)) return;

    const entries = await fetchEntriesCached();
    const matches = rankMatches(host, entries);
    if (!matches.length) return;

    const canonicalMap = await getCanonicalMap();
    const canonicalEntryId = canonicalMap[host] || '';
    let picked = null;
    if (canonicalEntryId) {
      picked = matches.find((m) => (m.entry_id || '') === canonicalEntryId) || null;
    }
    if (!picked) {
      picked = policy.exactOnly ? matches.find((m) => (m.score || 0) >= 100) : matches[0];
    }
    if (!picked) return;

    const resultArr = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: (u, p, meta, opts) => {
        const isEditable = (el) => !!el && !el.disabled && !el.readOnly;
        const allInputs = Array.from(document.querySelectorAll('input'));
        const inputs = allInputs.filter(isEditable);
        const passwordField = inputs.find((el) => el.type === 'password' && isEditable(el));
        if (!passwordField) return { ok: false, reason: 'no-password-field' };

        const userField = inputs.find((el) => {
          if (el === passwordField) return false;
          const t = (el.type || '').toLowerCase();
          return ['text', 'email', 'username', 'tel'].includes(t) || el.autocomplete === 'username';
        });

        const setValue = (el, v) => {
          if (!el) return;
          const prev = el.value || '';
          if (prev && prev.length && prev !== v) return;
          el.focus();
          el.value = v;
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        };

        setValue(passwordField, p || '');
        if (userField) setValue(userField, u || '');

        const form = passwordField.form || (userField ? userField.form : null);
        if (form && !form.__hwvPasswordHooked) {
          form.__hwvPasswordHooked = true;
          form.addEventListener('submit', () => {
            try {
              const newPass = passwordField.value || '';
              if (!newPass || newPass === (meta.password || '')) return;
              if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
                chrome.runtime.sendMessage({
                  type: 'hwvault-password-change-detected',
                  payload: {
                    entry_id: meta.entry_id || '',
                    name: meta.name || '',
                    username: userField ? (userField.value || meta.username || '') : (meta.username || ''),
                    password: newPass,
                    url: location.href || '',
                    note: meta.note || '',
                    otp: meta.otp || '',
                  },
                });
              }
            } catch (_) {}
          }, { capture: true });
        }

        if (form && opts && opts.autoSubmit) {
          const submitBtn = form.querySelector('button[type="submit"],input[type="submit"]');
          if (submitBtn) submitBtn.click();
          else form.requestSubmit ? form.requestSubmit() : form.submit();
        }

        return { ok: true, filledUser: Boolean(userField && u), filledPass: true };
      },
      args: [picked.user || '', picked.pass || '', {
        entry_id: picked.entry_id || '',
        name: picked.name || '',
        username: picked.user || '',
        password: picked.pass || '',
        note: picked.note || '',
        otp: picked.otp || '',
      }, { autoSubmit: !!policy.autoSubmit }],
    });

    const result = Array.isArray(resultArr)
      ? (resultArr.find((r) => r && r.result && r.result.ok)?.result || null)
      : null;
    if (result && result.ok && picked.entry_id) {
      await postWithRetry('/entry/touch', { entry_id: picked.entry_id, origin: 'autofill-auto' });
      await setCanonicalForHost(host, picked.entry_id);
    }
  } catch (_) {
    // silent by design to keep browsing seamless
  }
}

async function installCaptureHook(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      func: () => {
        if (window.__hwvCaptureInstalled) return;
        window.__hwvCaptureInstalled = true;

        const isEditable = (el) => !!el && !el.disabled && !el.readOnly;
        const maybeFindFields = (form) => {
          const scope = form || document;
          const inputs = Array.from(scope.querySelectorAll('input')).filter(isEditable);
          const pass = inputs.find((el) => (el.type || '').toLowerCase() === 'password');
          if (!pass) return null;
          const user = inputs.find((el) => {
            if (el === pass) return false;
            const t = (el.type || '').toLowerCase();
            return ['text', 'email', 'username', 'tel'].includes(t) || el.autocomplete === 'username';
          });
          return { user, pass };
        };

        const hookForm = (form) => {
          if (!form || form.__hwvCaptureHooked) return;
          form.__hwvCaptureHooked = true;
          form.addEventListener('submit', () => {
            try {
              const fields = maybeFindFields(form);
              if (!fields || !fields.pass) return;
              const password = fields.pass.value || '';
              if (!password) return;
              const username = fields.user ? (fields.user.value || '') : '';
              const host = (location.hostname || '').replace(/^www\./, '');
              const name = host || 'login';
              if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
                chrome.runtime.sendMessage({
                  type: 'hwvault-login-captured',
                  payload: {
                    name,
                    username,
                    password,
                    url: location.href || '',
                    note: 'captured-from-login-submit',
                  },
                });
              }
            } catch (_) {}
          }, { capture: true });
        };

        document.querySelectorAll('form').forEach(hookForm);
        const mo = new MutationObserver(() => {
          document.querySelectorAll('form').forEach(hookForm);
        });
        mo.observe(document.documentElement || document.body, { childList: true, subtree: true });
      },
    });
  } catch (_) {
    // best effort only
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (tab && tab.url) rememberLastActiveTab(tabId, tab.url);
  if (changeInfo.status === 'complete' && tab && tab.url) {
    tryAutofillTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab && tab.url) {
      rememberLastActiveTab(tabId, tab.url);
      tryAutofillTab(tabId, tab.url);
    }
  } catch (_) {}
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details && details.tabId >= 0 && details.url) {
    tryAutofillTab(details.tabId, details.url);
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === 'hwvault-login-captured') {
    (async () => {
      try {
        const p = msg.payload || {};
        const result = await queuePasswordChange({
          name: p.name || '',
          username: p.username || '',
          password: p.password || '',
          url: p.url || '',
          note: p.note || '',
          otp: '',
        });
        sendResponse({ ok: true, ...result });
      } catch (e) {
        sendResponse({ ok: false, error: e.message || 'capture failed' });
      }
    })();
    return true;
  }

  if (msg && msg.type === 'hwvault-canonical-pick') {
    (async () => {
      try {
        const host = normalizeHost(msg.url || '');
        if (host && msg.entry_id) await setCanonicalForHost(host, msg.entry_id);
        sendResponse({ ok: true });
      } catch (e) {
        sendResponse({ ok: false, error: e.message || 'failed' });
      }
    })();
    return true;
  }

  if (msg && msg.type === 'hwvault-unlock-fingerprint') {
    (async () => {
      try {
        const resp = await fetch(API_BASE + '/linux/fingerprint-unlock', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Origin: chrome.runtime.getURL('').replace(/\/$/, ''),
          },
          body: '{}',
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok || !data.success || !data.token || !data.session_key) {
          throw new Error(data.error || `HTTP ${resp.status}`);
        }
        await persistSession(data.token, data.session_key);
        sendResponse({ ok: true });
      } catch (e) {
        await persistSession(null, null);
        sendResponse({ ok: false, error: e.message || 'fingerprint unlock failed' });
      }
    })();
    return true;
  }

  if (!msg || msg.type !== 'hwvault-password-change-detected') return false;

  (async () => {
    try {
      const payload = msg.payload || {};
      const result = await queuePasswordChange(payload);
      sendResponse({ ok: true, ...result });
    } catch (e) {
      sendResponse({ ok: false, error: e.message || 'store failed' });
    }
  })();

  return true;
});
