/* ---------------------------------------------------------------
   Node 2602 — Authentication front end
   No build step, no framework. Hash routing + fetch.
   --------------------------------------------------------------- */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // --- State --------------------------------------------------------------
  // The access token is deliberately kept in a closure variable, not in
  // localStorage: anything in storage is readable by injected script.
  let accessToken = null;
  let currentUser = null;
  let pendingEmail = null;   // email awaiting OTP verification
  let resetToken = null;     // token taken from a /reset-password/:token link
  let resendTimer = null;

  // --- Toasts -------------------------------------------------------------
  function toast(title, message, kind = 'info', ttl = 5000) {
    const el = document.createElement('div');
    el.className = `toast ${kind}`;
    const body = document.createElement('div');
    body.className = 't-body';
    const t = document.createElement('div');
    t.className = 't-title';
    t.textContent = title;
    body.appendChild(t);
    if (message) {
      const m = document.createElement('div');
      m.className = 't-msg';
      m.textContent = message;
      body.appendChild(m);
    }
    const close = document.createElement('button');
    close.type = 'button';
    close.setAttribute('aria-label', 'Dismiss notification');
    close.textContent = '×';
    close.onclick = () => el.remove();
    el.append(body, close);
    $('#toasts').appendChild(el);
    setTimeout(() => el.remove(), ttl);
  }

  // --- Field errors -------------------------------------------------------
  function clearErrors(form) {
    $$('.field', form).forEach((f) => {
      f.classList.remove('invalid');
      const err = $('.err', f);
      if (err) err.textContent = '';
      const input = $('input', f);
      if (input) input.removeAttribute('aria-invalid');
    });
  }

  function setFieldError(form, fieldName, message) {
    const field = $(`.field[data-field="${fieldName}"]`, form);
    if (!field) return false;
    field.classList.add('invalid');
    const err = $('.err', field);
    if (err) err.textContent = message;
    const input = $('input', field);
    if (input) input.setAttribute('aria-invalid', 'true');
    return true;
  }

  /** Maps a failed API response onto the form, falling back to a toast. */
  function applyApiError(form, payload, fallbackTitle) {
    let placed = false;
    if (Array.isArray(payload?.errors)) {
      payload.errors.forEach((e) => {
        if (setFieldError(form, e.field, e.message)) placed = true;
      });
      // Focus the first field that failed so keyboard users land on it.
      const firstBad = $('.field.invalid input', form);
      if (firstBad) firstBad.focus();
    }
    if (!placed) toast(fallbackTitle, payload?.message || 'Please try again.', 'error');
  }

  // --- Button loading state ----------------------------------------------
  function busy(btn, on) {
    btn.classList.toggle('loading', on);
    btn.disabled = on;
    btn.setAttribute('aria-busy', String(on));
  }

  // --- API ----------------------------------------------------------------
  async function raw(path, { method = 'GET', body, auth = false } = {}) {
    const headers = {};
    if (body) headers['Content-Type'] = 'application/json';
    if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;

    const res = await fetch(path, {
      method,
      headers,
      credentials: 'include',
      body: body ? JSON.stringify(body) : undefined,
    });

    let json = {};
    try { json = await res.json(); } catch { /* empty body */ }
    return { ok: res.ok, status: res.status, json };
  }

  /**
   * Same as raw(), but if a protected call comes back 401 it silently
   * refreshes the access token once and replays the request. This is what
   * makes a 15-minute access token invisible to the user.
   */
  async function api(path, opts = {}) {
    let out = await raw(path, opts);

    if (out.status === 401 && opts.auth && path !== '/api/auth/refresh') {
      const refreshed = await raw('/api/auth/refresh', { method: 'POST' });
      if (refreshed.ok && refreshed.json?.data?.accessToken) {
        accessToken = refreshed.json.data.accessToken;
        out = await raw(path, opts);
      } else {
        signOutLocal();
        toast('Session expired', 'Please sign in again.', 'error');
        go('#/login');
      }
    }

    showRaw(out);
    return out;
  }

  function showRaw(out) {
    const pre = $('#raw');
    if (pre) pre.textContent = JSON.stringify({ status: out.status, ...out.json }, null, 2);
  }

  // --- Password helpers ---------------------------------------------------
  const RULES = {
    len: (v) => v.length >= 8,
    lower: (v) => /[a-z]/.test(v),
    upper: (v) => /[A-Z]/.test(v),
    digit: (v) => /\d/.test(v),
  };
  const LABELS = ['enter a password', 'weak', 'fair', 'good', 'strong'];

  function wireStrength(inputId, meterId, labelId, rulesId) {
    const input = document.getElementById(inputId);
    const meter = document.getElementById(meterId);
    const label = document.getElementById(labelId);
    const list = document.getElementById(rulesId);
    if (!input) return;

    input.addEventListener('input', () => {
      const v = input.value;
      let score = 0;
      $$('li', list).forEach((li) => {
        const met = RULES[li.dataset.rule](v);
        li.classList.toggle('met', met);
        if (met) score += 1;
      });
      if (!v) score = 0;
      meter.dataset.score = String(score);
      label.textContent = `Password strength: ${LABELS[score]}`;
    });
  }

  // --- Show / hide password ----------------------------------------------
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.toggle-pw');
    if (!btn) return;
    const input = document.getElementById(btn.dataset.toggle);
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.textContent = show ? 'Hide' : 'Show';
    btn.setAttribute('aria-pressed', String(show));
  });

  // --- Navigation links ---------------------------------------------------
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-go]');
    if (!btn) return;
    e.preventDefault();
    go(btn.dataset.go);
  });

  // --- OTP boxes ----------------------------------------------------------
  const otpInputs = () => $$('.otp input');

  function wireOtp() {
    const boxes = otpInputs();
    boxes.forEach((box, i) => {
      box.addEventListener('input', () => {
        box.value = box.value.replace(/\D/g, '').slice(-1);
        if (box.value && i < boxes.length - 1) boxes[i + 1].focus();
      });
      box.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !box.value && i > 0) boxes[i - 1].focus();
        if (e.key === 'ArrowLeft' && i > 0) { e.preventDefault(); boxes[i - 1].focus(); }
        if (e.key === 'ArrowRight' && i < boxes.length - 1) { e.preventDefault(); boxes[i + 1].focus(); }
      });
      box.addEventListener('paste', (e) => {
        e.preventDefault();
        const digits = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
        digits.split('').forEach((d, k) => { if (boxes[k]) boxes[k].value = d; });
        boxes[Math.min(digits.length, boxes.length - 1)].focus();
      });
    });
  }

  function readOtp() { return otpInputs().map((b) => b.value).join(''); }
  function fillOtp(code) {
    otpInputs().forEach((b, i) => { b.value = code[i] || ''; });
  }
  function clearOtp() { otpInputs().forEach((b) => { b.value = ''; }); }

  function startResendCooldown(seconds) {
    const btn = $('#resendBtn');
    const label = $('#resendTimer');
    clearInterval(resendTimer);
    let left = seconds;

    const tick = () => {
      if (left <= 0) {
        clearInterval(resendTimer);
        btn.disabled = false;
        label.textContent = '';
        return;
      }
      btn.disabled = true;
      label.textContent = `  available in ${left}s`;
      left -= 1;
    };
    tick();
    resendTimer = setInterval(tick, 1000);
  }

  // --- Router -------------------------------------------------------------
  const VIEWS = ['boot', 'login', 'register', 'verify', 'forgot', 'reset', 'dashboard'];
  const TITLES = {
    login: 'Sign in', register: 'Create account', verify: 'Verify email',
    forgot: 'Reset password', reset: 'New password', dashboard: 'Your account',
  };

  function show(name) {
    VIEWS.forEach((v) => {
      const el = document.getElementById(`view-${v}`);
      if (el) el.hidden = v !== name;
    });
    document.title = `${TITLES[name] || 'Authentication'} — Node 2602`;
    const heading = $(`#view-${name} h1`);
    if (heading) heading.setAttribute('tabindex', '-1');
    // Move focus to the heading so screen readers announce the new screen.
    if (heading) heading.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  function go(hash) {
    if (location.hash === hash) route();
    else location.hash = hash;
  }

  function route() {
    const hash = location.hash || '#/login';
    const name = hash.replace('#/', '').split('?')[0];

    const guarded = name === 'dashboard';
    if (guarded && !accessToken) return go('#/login');
    if (!guarded && accessToken && ['login', 'register', 'forgot'].includes(name)) return go('#/dashboard');

    if (name === 'verify') {
      $('#verify-email').textContent = pendingEmail || 'your inbox';
      clearOtp();
      setTimeout(() => otpInputs()[0]?.focus(), 60);
    }
    if (name === 'dashboard') renderUser();

    show(VIEWS.includes(name) ? name : 'login');
  }

  window.addEventListener('hashchange', route);

  // --- Dashboard rendering ------------------------------------------------
  function renderUser() {
    if (!currentUser) return;
    const initials = (currentUser.name || '?')
      .split(/\s+/).slice(0, 2).map((w) => w[0]).join('').toUpperCase();
    $('#dash-avatar').textContent = initials;
    $('#dash-name').textContent = currentUser.name;
    $('#dash-email').textContent = currentUser.email;

    const badges = $('#dash-badges');
    badges.textContent = '';
    const add = (text, cls) => {
      const b = document.createElement('span');
      b.className = `badge ${cls}`;
      b.textContent = text;
      badges.appendChild(b);
    };
    add(currentUser.role === 'admin' ? 'Administrator' : 'Standard user',
        currentUser.role === 'admin' ? 'accent' : '');
    add(currentUser.isVerified ? 'Email verified' : 'Email not verified',
        currentUser.isVerified ? 'ok' : 'warn');

    $('#verify-nudge').hidden = Boolean(currentUser.isVerified);
  }

  function signOutLocal() {
    accessToken = null;
    currentUser = null;
    $('#usersWrap').hidden = true;
  }

  // --- Forms --------------------------------------------------------------
  $('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    clearErrors(form);
    const btn = $('#loginBtn');
    busy(btn, true);

    const out = await api('/api/auth/login', {
      method: 'POST',
      body: { email: $('#login-email').value.trim(), password: $('#login-password').value },
    });
    busy(btn, false);

    if (!out.ok) return applyApiError(form, out.json, 'Could not sign in');

    accessToken = out.json.data.accessToken;
    currentUser = out.json.data.user;
    form.reset();
    toast('Signed in', `Welcome back, ${currentUser.name}.`, 'ok');
    go('#/dashboard');
  });

  $('#registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    clearErrors(form);
    const btn = $('#registerBtn');
    busy(btn, true);

    const email = $('#reg-email').value.trim();
    const out = await api('/api/auth/register', {
      method: 'POST',
      body: { name: $('#reg-name').value.trim(), email, password: $('#reg-password').value },
    });
    busy(btn, false);

    if (!out.ok) return applyApiError(form, out.json, 'Could not create account');

    accessToken = out.json.data.accessToken;
    currentUser = out.json.data.user;
    pendingEmail = email;
    form.reset();

    // Development only: the API echoes the code so the flow can be demonstrated.
    const devOtp = out.json.data.otp;
    if (devOtp) {
      toast('Account created', `Development code: ${devOtp}`, 'ok', 15000);
    } else {
      toast('Account created', 'Check your email for the code.', 'ok');
    }
    go('#/verify');
    if (devOtp) setTimeout(() => fillOtp(devOtp), 120);
    startResendCooldown(60);
  });

  $('#verifyForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    clearErrors(form);
    const code = readOtp();

    if (code.length !== 6) {
      setFieldError(form, 'otp', 'Enter all six digits.');
      return;
    }

    const btn = $('#verifyBtn');
    busy(btn, true);
    const out = await api('/api/auth/verify-otp', {
      method: 'POST',
      body: { email: pendingEmail || currentUser?.email, otp: code },
    });
    busy(btn, false);

    if (!out.ok) {
      setFieldError(form, 'otp', out.json?.message || 'That code was not accepted.');
      clearOtp();
      otpInputs()[0]?.focus();
      return;
    }

    if (currentUser) currentUser.isVerified = true;
    clearInterval(resendTimer);
    toast('Email verified', 'Your account is fully set up.', 'ok');
    go('#/dashboard');
  });

  $('#resendBtn').addEventListener('click', async () => {
    const out = await api('/api/auth/send-otp', {
      method: 'POST',
      body: { email: pendingEmail || currentUser?.email },
    });

    if (!out.ok) {
      toast('Could not resend', out.json?.message || 'Try again shortly.', 'error');
      return;
    }
    const devOtp = out.json?.data?.otp;
    if (devOtp) { fillOtp(devOtp); toast('Code resent', `Development code: ${devOtp}`, 'ok', 15000); }
    else toast('Code resent', 'Check your email.', 'ok');
    startResendCooldown(60);
  });

  $('#forgotForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    clearErrors(form);
    const btn = $('#forgotBtn');
    busy(btn, true);

    const out = await api('/api/auth/forgot-password', {
      method: 'POST',
      body: { email: $('#forgot-email').value.trim() },
    });
    busy(btn, false);

    if (!out.ok) return applyApiError(form, out.json, 'Could not send the link');

    // Development only: jump straight to the reset screen.
    const devToken = out.json?.data?.resetToken;
    if (devToken) {
      resetToken = devToken;
      toast('Reset link ready', 'Opening the reset form (development only).', 'ok');
      go('#/reset');
    } else {
      toast('Check your email', out.json.message, 'ok');
      go('#/login');
    }
  });

  $('#resetForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    clearErrors(form);

    if (!resetToken) {
      toast('Link missing', 'Request a new reset link.', 'error');
      return go('#/forgot');
    }

    const btn = $('#resetBtn');
    busy(btn, true);
    const out = await api(`/api/auth/reset-password/${encodeURIComponent(resetToken)}`, {
      method: 'PATCH',
      body: { password: $('#reset-password').value },
    });
    busy(btn, false);

    if (!out.ok) return applyApiError(form, out.json, 'Could not reset password');

    resetToken = null;
    signOutLocal();
    form.reset();
    history.replaceState({}, '', '/');
    toast('Password updated', 'Sign in with your new password.', 'ok');
    go('#/login');
  });

  $('#changeForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.currentTarget;
    clearErrors(form);
    const btn = $('#changeBtn');
    busy(btn, true);

    const out = await api('/api/auth/change-password', {
      method: 'PATCH',
      auth: true,
      body: {
        currentPassword: $('#cur-password').value,
        newPassword: $('#new-password').value,
      },
    });
    busy(btn, false);

    if (!out.ok) return applyApiError(form, out.json, 'Could not change password');

    signOutLocal();
    form.reset();
    toast('Password changed', 'All devices were signed out.', 'ok');
    go('#/login');
  });

  // --- Dashboard actions --------------------------------------------------
  $('#meBtn').addEventListener('click', async () => {
    const out = await api('/api/auth/me', { auth: true });
    if (out.ok) {
      currentUser = out.json.data.user;
      renderUser();
      toast('Profile reloaded', null, 'ok', 2500);
    }
  });

  $('#refreshBtn').addEventListener('click', async () => {
    const out = await api('/api/auth/refresh', { method: 'POST' });
    if (out.ok) {
      accessToken = out.json.data.accessToken;
      toast('Token refreshed', 'A new access token was issued and the old refresh token retired.', 'ok');
    } else {
      toast('Refresh failed', out.json?.message || 'Please sign in again.', 'error');
    }
  });

  $('#usersBtn').addEventListener('click', async () => {
    const out = await api('/api/users', { auth: true });
    if (!out.ok) {
      toast('Not allowed', out.json?.message || 'Admins only.', 'error');
      $('#usersWrap').hidden = true;
      return;
    }
    const body = $('#usersBody');
    body.textContent = '';
    out.json.data.users.forEach((u) => {
      const tr = document.createElement('tr');
      [u.name, u.email, u.role, u.isVerified ? 'Yes' : 'No'].forEach((val) => {
        const td = document.createElement('td');
        td.textContent = val;
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    $('#usersWrap').hidden = false;
  });

  $('#logoutBtn').addEventListener('click', async () => {
    await api('/api/auth/logout', { method: 'POST' });
    signOutLocal();
    toast('Signed out', null, 'ok');
    go('#/login');
  });

  $('#logoutAllBtn').addEventListener('click', async () => {
    const out = await api('/api/auth/logout-all', { method: 'POST', auth: true });
    signOutLocal();
    toast(out.ok ? 'Signed out everywhere' : 'Signed out', out.json?.message, 'ok');
    go('#/login');
  });

  // --- Theme --------------------------------------------------------------
  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    $('#themeIcon').textContent = theme === 'dark' ? '☀' : '☾';
    $('#themeBtn').setAttribute('aria-label',
      theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    try { localStorage.setItem('theme', theme); } catch { /* private mode */ }
  }

  $('#themeBtn').addEventListener('click', () => {
    applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
  });

  // --- Boot ---------------------------------------------------------------
  async function boot() {
    let stored = null;
    try { stored = localStorage.getItem('theme'); } catch { /* private mode */ }
    const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches;
    applyTheme(stored || (prefersDark ? 'dark' : 'light'));

    wireOtp();
    wireStrength('reg-password', 'reg-meter', 'reg-meter-label', 'reg-rules');
    wireStrength('reset-password', 'reset-meter', 'reset-meter-label', 'reset-rules');
    wireStrength('new-password', 'new-meter', 'new-meter-label', 'new-rules');

    // A reset link arrives as /reset-password/<token>.
    const match = location.pathname.match(/^\/reset-password\/([A-Za-z0-9]+)$/);
    if (match) {
      resetToken = match[1];
      show('reset');
      return;
    }

    // Try to restore the session from the refresh cookie before showing a
    // login form — otherwise a reload would look like being logged out.
    const refreshed = await raw('/api/auth/refresh', { method: 'POST' });
    if (refreshed.ok && refreshed.json?.data?.accessToken) {
      accessToken = refreshed.json.data.accessToken;
      const me = await raw('/api/auth/me', { auth: true });
      if (me.ok) {
        currentUser = me.json.data.user;
        if (!location.hash || location.hash === '#/login') {
          location.hash = '#/dashboard';
          route();
          return;
        }
      }
    }

    route();
  }

  boot();
})();
