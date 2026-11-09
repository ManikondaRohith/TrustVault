/* TrustVault API client.
 * Same-origin only. The session lives in an HttpOnly cookie the script cannot read.
 * Every state-changing call carries X-Requested-With, which the server requires (CSRF defence).
 * Nothing here decides access: the server answers every request on its own.
 */
'use strict';
(function () {
  const BASE = '/api';

  class ApiError extends Error {
    constructor(status, detail) { super(detail || ('HTTP ' + status)); this.status = status; this.detail = detail; }
  }

  let onSessionLost = null;

  async function request(method, path, { json, form, raw } = {}) {
    const headers = { 'X-Requested-With': 'TrustVault', Accept: raw ? '*/*' : 'application/json' };
    let body;
    if (json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
    else if (form) { body = form; }
    let res;
    try {
      res = await fetch(BASE + path, { method, headers, body, credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
    } catch (e) {
      throw new ApiError(0, 'Cannot reach the server. Check your connection.');
    }
    if (!res.ok) {
      let detail = '';
      try { detail = (await res.json()).detail; } catch (e) { /* not JSON */ }
      if (typeof detail !== 'string') detail = 'Request refused.';
      if (res.status === 401 && onSessionLost && !path.startsWith('/auth/')) onSessionLost(detail);
      throw new ApiError(res.status, detail);
    }
    if (raw) return { blob: await res.blob(), type: res.headers.get('Content-Type') || '', sha: res.headers.get('X-Document-SHA256') || '' };
    if (res.status === 204) return null;
    return res.json();
  }

  const q = o => { const p = new URLSearchParams(); Object.entries(o || {}).forEach(([k, v]) => { if (v !== '' && v != null && v !== false) p.set(k, v); }); const s = p.toString(); return s ? '?' + s : ''; };
  const e = encodeURIComponent;

  window.Vault = {
    ApiError,
    onSessionLost(fn) { onSessionLost = fn; },
    auth: {
      me: () => request('GET', '/auth/me'),
      login: (username, password) => request('POST', '/auth/login', { json: { username, password } }),
      signupStart: (b) => request('POST', '/auth/signup/start', { json: b }),
      signupResend: (challenge_id) => request('POST', '/auth/signup/resend', { json: { challenge_id } }),
      signupVerify: (challenge_id, code) => request('POST', '/auth/signup/verify', { json: { challenge_id, code } }),
      forgotStart: (email) => request('POST', '/auth/forgot/start', { json: { email } }),
      forgotVerify: (challenge_id, code) => request('POST', '/auth/forgot/verify', { json: { challenge_id, code } }),
      forgotReset: (challenge_id, code, new_password) => request('POST', '/auth/forgot/reset', { json: { challenge_id, code, new_password } }),
      logout: () => request('POST', '/auth/logout', { json: {} }),
      changePassword: (current_password, new_password) => request('POST', '/auth/password', { json: { current_password, new_password } }),
    },
    docs: {
      list: (f) => request('GET', '/documents' + q(f)),
      owners: () => request('GET', '/documents/owners'),
      metadata: (id) => request('GET', `/documents/${e(id)}/metadata`),
      content: (id, passcode) => request('POST', `/documents/${e(id)}/content`, { json: { passcode: passcode || null }, raw: true }),
      download: (id, passcode) => request('POST', `/documents/${e(id)}/download`, { json: { passcode: passcode || null }, raw: true }),
      upload: (file, category) => { const f = new FormData(); f.append('file', file); f.append('category', category); return request('POST', '/documents', { form: f }); },
      createText: (name, category, text) => request('POST', '/documents/text', { json: { name, category, text } }),
      editText: (id, text, passcode) => request('PUT', `/documents/${e(id)}/text`, { json: { text, passcode: passcode || null } }),
      rename: (id, name, passcode) => request('PATCH', `/documents/${e(id)}`, { json: { name, passcode: passcode || null } }),
      remove: (id) => request('DELETE', `/documents/${e(id)}`),
      probe: (document_id) => request('POST', '/documents/probe', { json: { document_id } }),
      grants: (id) => request('GET', `/documents/${e(id)}/grants`),
      grant: (id, user, level, can_rename) => request('PUT', `/documents/${e(id)}/grants/${e(user)}`, { json: { level, can_rename } }),
      revoke: (id, user) => request('DELETE', `/documents/${e(id)}/grants/${e(user)}`),
      setPasscode: (id, passcode) => request('PUT', `/documents/${e(id)}/passcode`, { json: { passcode } }),
      removePasscode: (id) => request('DELETE', `/documents/${e(id)}/passcode`),
      grantable: () => request('GET', '/users/grantable'),
    },
    admin: {
      users: () => request('GET', '/admin/users'),
      setRole: (u, role) => request('PATCH', `/admin/users/${e(u)}/role`, { json: { role } }),
      block: (u) => request('POST', `/admin/users/${e(u)}/block`, { json: {} }),
      unblock: (u) => request('POST', `/admin/users/${e(u)}/unblock`, { json: {} }),
      reset: (u) => request('POST', `/admin/users/${e(u)}/reset`, { json: {} }),
      reports: () => request('GET', '/admin/reports'),
      tamperTest: () => request('POST', '/admin/audit/tamper-test', { json: {} }),
      selftest: () => request('POST', '/admin/selftest', { json: {} }),
    },
    audit: {
      list: (f) => request('GET', '/audit' + q(f)),
      verify: () => request('GET', '/audit/verify'),
    },
    stats: () => request('GET', '/stats'),
    safety: {
      policy: () => request('GET', '/safety/policy'),
      reportable: () => request('GET', '/safety/reportable'),
      report: (b) => request('POST', '/safety/reports', { json: b }),
      ack: () => request('POST', '/safety/warnings/ack', { json: {} }),
      message: (document_id, body) => request('POST', '/safety/messages', { json: { document_id, body } }),
      inbox: () => request('GET', '/safety/messages'),
      shared: () => request('GET', '/safety/shared'),
    },
  };
})();
