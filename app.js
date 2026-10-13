'use strict';

const BUILTIN_HOSTS = [
  { url: 'https://bedbrick.fxtun.ru',            label: 'prod' },
  { url: 'http://localhost:25572',            label: 'local' },
];

const STORAGE_KEY        = 'bb_selected_host';
const STORAGE_CUSTOM_KEY = 'bb_custom_hosts';

let AUTH_ENDPOINT = loadSelectedHost();

const $ = (id) => document.getElementById(id);
const $$ = (sel) => document.querySelectorAll(sel);

function toast(msg, type = '', ms = 2500) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast' + (type ? ' ' + type : '');
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { t.hidden = true; }, ms);
}

function getDeviceId() {
  let id = localStorage.getItem('bb_device_id');
  if (!id) {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    id = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem('bb_device_id', id);
  }
  return id;
}

async function hashPassword(password, email) {
  const enc = new TextEncoder();
  const salt = enc.encode(
    `bedbrick::${email.toLowerCase().trim()}`
  );
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
    baseKey, 256
  );
  return btoa(String.fromCharCode(...new Uint8Array(derived)));
}

async function fetchWithTimeout(url, opts = {}, ms = 15000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

function setLoading(btn, on, labelIdle) {
  btn.disabled = on;
  btn.querySelector('.btn-label').textContent = on ? 'Подождите…' : labelIdle;
  btn.querySelector('.spinner').hidden = !on;
}




const ALL_PANELS = ['tab-login', 'tab-register', 'step-verify', 'step-setup', 'step-code'];

function showPanel(panelId) {
  ALL_PANELS.forEach(id => { $(id).hidden = (id !== panelId); });

  const tabsVisible = (panelId === 'tab-login' || panelId === 'tab-register');
  $$('.tabs').forEach(t => t.hidden = !tabsVisible);

  if (tabsVisible) {
    $$('.tab').forEach(t => {
      const active = ('tab-' + t.dataset.tab) === panelId;
      t.classList.toggle('active', active);
      t.setAttribute('aria-selected', active ? 'true' : 'false');
    });
  }

  $('login-form').classList.remove('validated');
  $('register-form').classList.remove('validated');
  $('setup-form').classList.remove('validated');
}


$$('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    showPanel('tab-' + tab.dataset.tab);
  });
});


$$('.eye').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = $(btn.dataset.for);
    const nowVisible = btn.getAttribute('aria-pressed') !== 'true';
    const start = input.selectionStart;
    const end   = input.selectionEnd;

    input.type = nowVisible ? 'text' : 'password';
    btn.setAttribute('aria-pressed', nowVisible ? 'true' : 'false');
    btn.setAttribute('aria-label', nowVisible ? 'Скрыть пароль' : 'Показать пароль');
    btn.setAttribute('title',    nowVisible ? 'Скрыть пароль' : 'Показать пароль');

    input.focus({ preventScroll: true });
    try { input.setSelectionRange(start, end); } catch {}
  });
});


function handleSecretCopy(input, { cut = false } = {}) {
  const selStart = input.selectionStart ?? 0;
  const selEnd   = input.selectionEnd   ?? input.value.length;
  const hasSelection = selEnd > selStart;
  const text = hasSelection ? input.value.slice(selStart, selEnd) : input.value;

  if (!text) return;

  navigator.clipboard.writeText(text).then(() => {
    toast(cut ? 'Пароль вырезан' : 'Пароль скопирован', 'success', 1400);
  }).catch(() => {
    toast('Не удалось скопировать', 'error');
  });

  if (cut) {
    if (hasSelection) {
      input.value = input.value.slice(0, selStart) + input.value.slice(selEnd);
      try { input.setSelectionRange(selStart, selStart); } catch {}
    } else {
      input.value = '';
    }
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }
}

$$('input[type=password]').forEach(input => {
  input.addEventListener('copy', (e) => {
    e.preventDefault();
    handleSecretCopy(input, { cut: false });
  });
  input.addEventListener('cut', (e) => {
    e.preventDefault();
    handleSecretCopy(input, { cut: true });
  });
});


function scorePassword(pw) {
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(score, 5);
}

const STRENGTH_TEXT = ['—', 'Очень слабый', 'Слабый', 'Средний', 'Хороший', 'Сильный'];
const STRENGTH_COLOR = [
  'var(--error)', 'var(--error)', 'var(--warn)',
  'var(--warn)', 'var(--accent)', 'var(--accent-hover)'
];

$('reg-password').addEventListener('input', (e) => {
  const s = scorePassword(e.target.value);
  const pct = (s / 5) * 100;
  const fill = $('strength-fill');
  fill.style.width = pct + '%';
  fill.style.background = STRENGTH_COLOR[s];
  $('strength-label').textContent = e.target.value ? STRENGTH_TEXT[s] : '';
  $('strength-label').style.color = e.target.value ? STRENGTH_COLOR[s] : '';
});


const RE_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const RE_USERNAME = /^[A-Za-z0-9_]{3,16}$/;

function validateEmail(v) {
  if (!v) return 'Введите email';
  if (v.length > 254) return 'Email слишком длинный';
  if (!RE_EMAIL.test(v)) return 'Некорректный email';
  return null;
}
function validateUsername(v) {
  if (!v) return 'Введите логин';
  if (!RE_USERNAME.test(v)) return 'Логин: 3–16 символов (A–Z, 0–9, _)';
  return null;
}
function validatePassword(v) {
  if (!v) return 'Введите пароль';
  if (v.length < 8) return 'Пароль от 8 символов';
  if (v.length > 128) return 'Пароль слишком длинный';
  if (scorePassword(v) < 2) return 'Пароль слишком простой';
  return null;
}


let pendingUserId = null;
let pendingEmail = null;
let verificationPollTimer = null;




function startVerificationPolling() {
  if (verificationPollTimer) return;
  if (!pendingEmail) return;

  const poll = async () => {
    if (document.visibilityState !== 'visible') return;
    if ($('step-verify').hidden) {
      stopVerificationPolling();
      return;
    }

    try {
      const res = await fetchWithTimeout(
        `${AUTH_ENDPOINT}/api/v1/check-verification`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email: pendingEmail,
            device_id: getDeviceId(),
            ts: Date.now()
          }),
          credentials: 'omit',
          mode: 'cors'
        },
        5000
      );

      if (!res.ok) return;

      const data = await res.json();
      if (data.verified) {
        onEmailVerified();
      }
    } catch (e) {
      
    }
  };

  verificationPollTimer = setInterval(poll, 3000);
  document.addEventListener('visibilitychange', onVisibilityChange);

  
  poll();
}

function stopVerificationPolling() {
  if (verificationPollTimer) {
    clearInterval(verificationPollTimer);
    verificationPollTimer = null;
  }
  document.removeEventListener('visibilitychange', onVisibilityChange);
}

function onVisibilityChange() {
  if (document.visibilityState !== 'visible') return;
  if (!$('step-verify').hidden && pendingEmail) {
    checkVerificationNow();
  }
}

async function checkVerificationNow() {
  if (!pendingEmail) return;
  try {
    const res = await fetchWithTimeout(
      `${AUTH_ENDPOINT}/api/v1/check-verification`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: pendingEmail,
          device_id: getDeviceId(),
          ts: Date.now()
        }),
        credentials: 'omit',
        mode: 'cors'
      },
      5000
    );
    if (!res.ok) return;
    const data = await res.json();
    if (data.verified) onEmailVerified();
  } catch {}
}

function onEmailVerified() {
  stopVerificationPolling();

  
  showPanel('tab-login');
  $('login-email').value = pendingEmail || '';
  $('login-password').value = '';

  
  showVerifiedBanner();

  
  setTimeout(() => $('login-password').focus(), 100);
}

function showVerifiedBanner() {
  const old = document.getElementById('verified-banner');
  if (old) old.remove();

  const banner = document.createElement('div');
  banner.id = 'verified-banner';
  banner.className = 'verified-banner';
  banner.innerHTML = `
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none"
         stroke="currentColor" stroke-width="2"
         stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
    <span>Email подтверждён! Войдите в аккаунт.</span>
  `;

  const loginForm = $('login-form');
  loginForm.insertBefore(banner, loginForm.firstChild);

  setTimeout(() => banner.remove(), 15000);
}


$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = $('login-form');
  const errEl = $('login-error');
  errEl.hidden = true;

  const email = $('login-email').value.trim().toLowerCase();
  const password = $('login-password').value;

  const errs = [
    validateEmail(email),
    !password ? 'Введите пароль' : null
  ].filter(Boolean);

  if (errs.length) {
    form.classList.add('validated');
    errEl.textContent = errs[0];
    errEl.hidden = false;
    return;
  }

  form.classList.remove('validated');

  const btn = $('login-submit');
  setLoading(btn, true, 'Войти');
  try {
    const passwordHash = await hashPassword(password, email);

    const res = await fetchWithTimeout(`${AUTH_ENDPOINT}/api/v1/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password_hash: passwordHash,
        device_id: getDeviceId(),
        client: 'web',
        ts: Date.now()
      }),
      credentials: 'omit',
      mode: 'cors'
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      if (res.status === 403 && data.code === 'EMAIL_NOT_VERIFIED') {
        pendingEmail = data.email || email;
        $('verify-email').textContent = pendingEmail;
        $('resend-status').hidden = true;
        showPanel('step-verify');
        startVerificationPolling();
        return;
      }
      errEl.textContent = data.message || data.detail || `Ошибка ${res.status}`;
      errEl.hidden = false;
      return;
    }

    
    $('auth-code').textContent = data.code;
    showPanel('step-code');
    form.reset();

  } catch (err) {
    console.error(err);
    errEl.textContent = err.name === 'AbortError'
      ? 'Сервер не отвечает.'
      : 'Не удалось связаться с сервером.';
    errEl.hidden = false;
  } finally {
    setLoading(btn, false, 'Войти');
  }
});


$('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = $('register-form');
  const errEl = $('register-error');
  errEl.hidden = true;

  const email = $('reg-email').value.trim().toLowerCase();
  const password = $('reg-password').value;
  const password2 = $('reg-password2').value;
  const agree = $('reg-agree').checked;

  const errs = [
    validateEmail(email),
    validatePassword(password),
    password !== password2 ? 'Пароли не совпадают' : null,
    !agree ? 'Примите условия' : null
  ].filter(Boolean);

  if (errs.length) {
    form.classList.add('validated');
    errEl.textContent = errs[0];
    errEl.hidden = false;
    return;
  }

  form.classList.remove('validated');

  const btn = $('register-submit');
  setLoading(btn, true, 'Создать аккаунт');
  try {
    const passwordHash = await hashPassword(password, email);

    const res = await fetchWithTimeout(`${AUTH_ENDPOINT}/api/v1/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password_hash: passwordHash,
        device_id: getDeviceId(),
        client: 'web',
        ts: Date.now()
      }),
      credentials: 'omit',
      mode: 'cors'
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      errEl.textContent = data.message || data.detail || `Ошибка ${res.status}`;
      errEl.hidden = false;
      return;
    }

    form.reset();
    form.classList.remove('validated');
    $('strength-fill').style.width = '0';
    $('strength-label').textContent = '';

    pendingEmail = email;
    $('verify-email').textContent = email;
    $('resend-status').hidden = true;
    showPanel('step-verify');
    startVerificationPolling();

    const resendBtn = $('resend-btn');
    resendBtn.disabled = false;
    resendBtn.textContent = 'Отправить письмо повторно';
    if (data.resend_after && data.resend_after > 0) {
      let left = data.resend_after;
      resendBtn.disabled = true;
      const tick = setInterval(() => {
        left--;
        if (left <= 0) {
          clearInterval(tick);
          resendBtn.disabled = false;
          resendBtn.textContent = 'Отправить письмо повторно';
        } else {
          resendBtn.textContent = `Повторно через ${left} с`;
        }
      }, 1000);
    }

    toast('Аккаунт создан! Проверьте почту.', 'success', 3500);
  } catch (err) {
    console.error(err);
    errEl.textContent = err.name === 'AbortError'
      ? 'Сервер не отвечает.'
      : 'Не удалось связаться с сервером.';
    errEl.hidden = false;
  } finally {
    setLoading(btn, false, 'Создать аккаунт');
  }
});


$('back-to-register').addEventListener('click', () => {
  stopVerificationPolling();
  showPanel('tab-register');
});

$('resend-btn').addEventListener('click', async () => {
  const btn = $('resend-btn');
  const email = $('verify-email').textContent;
  btn.disabled = true;
  try {
    const res = await fetchWithTimeout(`${AUTH_ENDPOINT}/api/v1/resend-verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, device_id: getDeviceId(), ts: Date.now() }),
      credentials: 'omit'
    });
    const data = await res.json().catch(() => ({}));
    const status = $('resend-status');
    status.hidden = false;
    if (res.ok) {
      status.textContent = 'Письмо отправлено ✓';
      status.style.color = 'var(--accent-hover)';
      setTimeout(() => { btn.disabled = false; }, 60_000);
    } else {
      status.textContent = data.message || data.detail || 'Не удалось отправить';
      status.style.color = 'var(--error)';
      btn.disabled = false;
    }
  } catch {
    btn.disabled = false;
    toast('Сервер не отвечает', 'error');
  }
});


$('copy-code-btn').addEventListener('click', async () => {
  const btn = $('copy-code-btn');
  try {
    await navigator.clipboard.writeText($('auth-code').textContent);
    btn.textContent = '✅';
    setTimeout(() => btn.textContent = '📋', 1200);
  } catch {
    toast('Не удалось скопировать', 'error');
  }
});

$('logout-btn').addEventListener('click', () => {
  $('auth-code').textContent = '------';
  showPanel('tab-login');
  if (pendingEmail) $('login-email').value = pendingEmail;
});


$('setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = $('setup-form');
  const errEl = $('setup-error');
  errEl.hidden = true;

  const username = $('setup-username').value.trim();

  const err = validateUsername(username);
  if (err) {
    form.classList.add('validated');
    errEl.textContent = err;
    errEl.hidden = false;
    return;
  }

  if (!pendingUserId) {
    errEl.textContent = 'Сессия истекла. Войдите заново.';
    errEl.hidden = false;
    return;
  }

  form.classList.remove('validated');

  const btn = $('setup-submit');
  setLoading(btn, true, 'Сохранить логин');
  try {
    const res = await fetchWithTimeout(`${AUTH_ENDPOINT}/api/v1/profile/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: pendingUserId,
        username,
        device_id: getDeviceId(),
        ts: Date.now()
      }),
      credentials: 'omit',
      mode: 'cors'
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      errEl.textContent = data.message || data.detail || `Ошибка ${res.status}`;
      errEl.hidden = false;
      return;
    }

    toast(`Логин сохранён: ${username}`, 'success', 2500);
    showPanel('tab-login');
  } catch (err) {
    console.error(err);
    errEl.textContent = err.name === 'AbortError'
      ? 'Сервер не отвечает.'
      : 'Не удалось связаться с сервером.';
    errEl.hidden = false;
  } finally {
    setLoading(btn, false, 'Сохранить логин');
  }
});

$('setup-skip').addEventListener('click', () => {
  toast('Логин можно задать позже', '', 2500);
  showPanel('tab-login');
});



function getAllHosts() {
  const custom = readCustomHosts();
  const map = new Map();
  [...BUILTIN_HOSTS, ...custom].forEach(h => map.set(h.url, h));
  return [...map.values()];
}

function readCustomHosts() {
  try {
    const raw = localStorage.getItem(STORAGE_CUSTOM_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.filter(h => h && typeof h.url === 'string' && h.url);
  } catch {
    return [];
  }
}

function saveCustomHost(url) {
  const list = readCustomHosts();
  if (list.some(h => h.url === url)) return false;
  list.push({ url, label: 'custom' });
  localStorage.setItem(STORAGE_CUSTOM_KEY, JSON.stringify(list));
  return true;
}

function removeCustomHost(url) {
  const list = readCustomHosts().filter(h => h.url !== url);
  localStorage.setItem(STORAGE_CUSTOM_KEY, JSON.stringify(list));
}

function loadSelectedHost() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) return saved;
  return BUILTIN_HOSTS[0].url;
}

async function selectHost(url) {
  if (!url) return;

  url = url.replace(/\/+$/, '');

  AUTH_ENDPOINT = url;
  localStorage.setItem(STORAGE_KEY, url);

  renderHostList();
  updateHostDisplay();

  await checkHostStatus();
}

async function checkHostStatus() {
  const statusEl = $('host-status');
  if (!statusEl) return;

  statusEl.className = 'host-status checking';

  try {
    const res = await fetchWithTimeout(`${AUTH_ENDPOINT}/health`, {
      method: 'GET',
      credentials: 'omit',
      mode: 'cors'
    }, 5000);

    if (res.ok) {
      statusEl.className = 'host-status online';
    } else {
      statusEl.className = 'host-status offline';
    }
  } catch {
    statusEl.className = 'host-status offline';
  }
}

function updateHostDisplay() {
  const currentEl = $('host-current');
  if (currentEl) {
    currentEl.textContent = AUTH_ENDPOINT;
    currentEl.title = AUTH_ENDPOINT;
  }
}

function renderHostList() {
  const listEl = $('host-list');
  if (!listEl) return;

  listEl.innerHTML = '';
  const hosts = getAllHosts();
  const customUrls = new Set(readCustomHosts().map(h => h.url));

  hosts.forEach(h => {
    const li = document.createElement('li');
    if (h.url === AUTH_ENDPOINT) li.classList.add('selected');

    const name = document.createElement('span');
    name.className = 'host-list-name';
    name.textContent = h.url;
    name.title = h.url;
    li.appendChild(name);

    const label = document.createElement('span');
    label.className = 'host-list-label';
    label.textContent = h.label || 'custom';
    li.appendChild(label);

    if (customUrls.has(h.url)) {
      const del = document.createElement('button');
      del.className = 'host-list-delete';
      del.type = 'button';
      del.title = 'Удалить';
      del.textContent = '×';
      del.addEventListener('click', (e) => {
        e.stopPropagation();
        removeCustomHost(h.url);
        if (h.url === AUTH_ENDPOINT) {
          selectHost(BUILTIN_HOSTS[0].url);
        } else {
          renderHostList();
        }
      });
      li.appendChild(del);
    }

    li.addEventListener('click', () => {
      selectHost(h.url);
      closeHostDropdown();
    });

    listEl.appendChild(li);
  });
}

function openHostDropdown() {
  const dropdown = $('host-dropdown');
  const toggle = $('host-toggle');
  if (!dropdown || !toggle) return;

  renderHostList();
  dropdown.hidden = false;
  toggle.setAttribute('aria-expanded', 'true');

  checkHostStatus();
}

function closeHostDropdown() {
  const dropdown = $('host-dropdown');
  const toggle = $('host-toggle');
  if (!dropdown || !toggle) return;

  dropdown.hidden = true;
  toggle.setAttribute('aria-expanded', 'false');
}

document.addEventListener('DOMContentLoaded', () => {
  updateHostDisplay();
  checkHostStatus();

  const toggle = $('host-toggle');
  const dropdown = $('host-dropdown');
  const customInput = $('host-custom-input');
  const customAdd = $('host-custom-add');

  if (toggle) {
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      if (dropdown.hidden) openHostDropdown();
      else closeHostDropdown();
    });
  }

  document.addEventListener('click', (e) => {
    if (!dropdown || dropdown.hidden) return;
    if (!e.target.closest('.host-picker')) closeHostDropdown();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && dropdown && !dropdown.hidden) closeHostDropdown();
  });

  if (customAdd && customInput) {
    const addCustom = () => {
      let url = customInput.value.trim();
      if (!url) return;

      if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
      url = url.replace(/\/+$/, '');

      try {
        new URL(url);
      } catch {
        toast('Некорректный URL', 'error');
        return;
      }

      saveCustomHost(url);
      customInput.value = '';
      selectHost(url);
      closeHostDropdown();
      toast('Хост добавлен', 'success', 1500);
    };

    customAdd.addEventListener('click', addCustom);
    customInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        addCustom();
      }
    });
  }
});
