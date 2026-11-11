/* TrustVault UI. All decisions are made by the server; this file only renders what the API allows.
 * Strict CSP: no inline styles or handlers. Dynamic values go through element.style (CSSOM).
 */
'use strict';
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const ist = iso => { try { return new Date(iso).toLocaleString('sv-SE', { timeZone: 'Asia/Kolkata' }); } catch (e) { return iso; } };
const API = window.Vault;
const CATS = ['HR', 'Contracts', 'Drawings', 'Audit', 'Other'];
const PW_RULE = 'Atleast 12 characters with uppercase, lowercase, a number and a symbol, not containing your username.';
const pwOk = (p, u) => p.length >= 12 && p.length <= 128 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p) && !(u && p.toLowerCase().includes(u.toLowerCase()));

let me = null, cur = null, mode = 'in', RD = null, lastActive = Date.now();
const PC = new Map();   // document passcodes typed during the current view only

/* ---------------------------------------------------------------- helpers */
function toast(t, bad) { const e = $('#ts'); e.textContent = t; e.className = 'ts on' + (bad ? ' bad' : ''); clearTimeout(toast.t); toast.t = setTimeout(() => e.className = 'ts', 3000); }
function shk(e) { if (!e) return; e.classList.remove('shake'); void e.offsetWidth; e.classList.add('shake'); setTimeout(() => e.classList.remove('shake'), 500); }
function errMsg(e) { return e instanceof API.ApiError ? e.detail : 'Something went wrong.'; }
function fail(e) { const m = errMsg(e); if (e.status === 423) blockedAlert(); else toast(m, 1); shk($('#main')); return null; }
async function safe(p) { try { return await p; } catch (e) { return fail(e); } }

/* ---- accessibility: dialogs (focus trap, Esc, focus return, background inert) and small ARIA fix-ups ---- */
const FOC = 'a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
let dlgN = 0, dlgId = 0;
const bgInert = on => ['#login', '#app', '#fab', '#open'].forEach(s => { const e = $(s); if (e) { if (on) e.setAttribute('inert', ''); else e.removeAttribute('inert'); } });
function enhance(root) {
  const r = root || document;
  r.querySelectorAll('.er:not([role])').forEach(e => e.setAttribute('role', 'alert'));
  r.querySelectorAll('svg:not([aria-label]):not([aria-hidden])').forEach(e => { e.setAttribute('aria-hidden', 'true'); e.setAttribute('focusable', 'false'); });
  r.querySelectorAll('thead th:not([scope])').forEach(e => e.setAttribute('scope', 'col'));
  r.querySelectorAll('table:not([aria-label])').forEach(t => {
    const hs = [...document.querySelectorAll('h2,h3')].filter(x => x.compareDocumentPosition(t) & 4);
    t.setAttribute('aria-label', hs.length ? hs[hs.length - 1].textContent.trim() : 'Data table');
  });
}
function dlg(o, opt) {
  const escClose = !!(opt && opt.esc), opener = document.activeElement, box = o.firstElementChild;
  o.setAttribute('role', o.getAttribute('role') || 'dialog'); o.setAttribute('aria-modal', 'true');
  box.querySelectorAll('h3').forEach(h => h.setAttribute('aria-level', '2'));   /* popup titles are level 2 for assistive tech; look unchanged */
  const hd = box.querySelector('h2,h3'); if (hd) { hd.id = hd.id || 'dh' + (++dlgId); o.setAttribute('aria-labelledby', hd.id); }
  enhance(box); box.tabIndex = -1;
  document.querySelectorAll('.md').forEach(x => { if (x !== o) x.setAttribute('inert', ''); }); dlgN++; bgInert(true);
  const rm = o.remove.bind(o); let gone = 0;
  o.remove = () => {
    if (gone) return; gone = 1; rm(); dlgN = Math.max(0, dlgN - 1);
    const rest = [...document.querySelectorAll('.md')]; if (rest.length) rest[rest.length - 1].removeAttribute('inert');
    if (!dlgN) bgInert(false);
    if (opener && opener.isConnected && !opener.closest('[inert]') && !opener.closest('[hidden]')) try { opener.focus(); } catch (e) { /* ignore */ }
  };
  o.addEventListener('keydown', e => {
    if (e.key === 'Escape' && escClose) { e.preventDefault(); e.stopPropagation(); (o.close || o.remove)(); return; }
    if (e.key !== 'Tab') return;
    const f = [...box.querySelectorAll(FOC)].filter(x => x.offsetParent !== null), cu = document.activeElement;
    if (!f.length) { e.preventDefault(); box.focus(); return; }
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && (cu === first || !box.contains(cu) || cu === box)) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && (cu === last || !box.contains(cu))) { e.preventDefault(); first.focus(); }
  });
  (box.querySelector('input:not([type=hidden]),textarea,select') || box.querySelector(FOC) || box).focus();
}

function modal(html, mount, cls) {
  const o = document.createElement('div'); o.className = 'md' + (cls ? ' ' + cls : '');
  o.innerHTML = `<div>${html}</div>`;
  if (!cls || !cls.includes('gt')) o.addEventListener('click', e => { if (e.target === o) close(); });
  const close = () => { o.dispatchEvent(new Event('closed')); o.remove(); };
  o.close = close;
  o.querySelectorAll('.cl').forEach(b => b.addEventListener('click', close));
  document.body.append(o); dlg(o, { esc: !(cls && cls.includes('gt')) }); o.querySelectorAll('input[type=password]').forEach(addEye);
  const first = o.querySelector('input,textarea,select,button'); first && first.focus();
  mount && mount(o, o.firstChild);
  return o;
}
const lockModal = (h, mount) => modal(h, mount, 'gt');

const mini = () => `<svg class="mini" viewBox="0 0 120 140" aria-hidden="true"><g stroke="#0b0b0f" stroke-width="5" stroke-linejoin="round" stroke-linecap="round" fill="#fff"><path d="M26 16H70L96 42V118Q96 126 88 126H26Q18 126 18 118V24Q18 16 26 16Z"/><path d="M70 16V36Q70 42 76 42H96" fill="#dce8ff"/></g><ellipse cx="42" cy="78" rx="4.5" ry="6" fill="#0b0b0f"/><ellipse cx="72" cy="78" rx="4.5" ry="6" fill="#0b0b0f"/><ellipse cx="34" cy="92" rx="8" ry="5" fill="#ffb7c5"/><ellipse cx="80" cy="92" rx="8" ry="5" fill="#ffb7c5"/><path d="M52 90Q57 96 62 90" stroke="#0b0b0f" stroke-width="3.5" fill="none" stroke-linecap="round"/></svg>`;
const EMPTY = t => `<div class="empty">${mini()}<p>${esc(t)}</p></div>`;

/* ---------------------------------------------------------------- mascot */
const MO = { idle: 'M120 170Q130 180 140 170', happy: 'M112 166Q130 192 148 166Z', sad: 'M120 180Q130 168 140 180' };
function mood(m, ms) { const f = $('#fig'); f.dataset.m = ''; void f.getBoundingClientRect(); f.dataset.m = m; $('#mo').setAttribute('d', MO[m]); if (m !== 'idle') f.classList.remove('hide'); if (ms) setTimeout(() => mood('idle'), ms); }
let pmq = 0;
addEventListener('pointermove', e => {
  if (pmq || $('#login').hidden) return;
  pmq = requestAnimationFrame(() => {
    pmq = 0; const r = $('#fig').getBoundingClientRect();
    const nx = Math.max(-1, Math.min(1, (e.clientX - r.left - r.width / 2) / 300)), ny = Math.max(-1, Math.min(1, (e.clientY - r.top - r.height * .55) / 300));
    $('#hd').style.transform = `translate(${nx * 6}px,${ny * 3}px) rotate(${nx * 2}deg)`; $('#ft').style.transform = `translate(${nx * 14}px,${ny * 9}px)`;
  });
}, { passive: true });

/* ---------------------------------------------------------------- Vanta background */
let vanta = null;
function vantaOn() {
  if (vanta || !window.VANTA || !window.THREE || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  try {
    vanta = window.VANTA.NET({ el: '#vanta', THREE: window.THREE, mouseControls: true, touchControls: true, gyroControls: false,
      minHeight: 200, minWidth: 200, scale: 1, scaleMobile: 1, color: 0x60a5fa, backgroundColor: 0x0f172a, points: 9, maxDistance: 21, spacing: 17, showDots: true });
    $('#stage').classList.add('has-vanta');
  } catch (e) { vanta = null; }   // no WebGL: the gradient background stays
}
function vantaOff() { if (vanta) { try { vanta.destroy(); } catch (e) { /* ignore */ } vanta = null; $('#stage').classList.remove('has-vanta'); } }

/* ---------------------------------------------------------------- theme */
const R = document.documentElement; let th; try { th = localStorage.getItem('tv'); } catch (e) { /* storage blocked */ }
th = th || (matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light'); R.dataset.theme = th;
$('#tg').addEventListener('click', () => { th = th === 'dark' ? 'light' : 'dark'; R.dataset.theme = th; try { localStorage.setItem('tv', th); } catch (e) { /* ignore */ } });

/* ---------------------------------------------------------------- password eye */
const EYE = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE0 = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.9 17.9A10.8 10.8 0 0 1 12 19C5 19 1 12 1 12a18 18 0 0 1 5.1-5.9M9.9 5.2A10 10 0 0 1 12 5c7 0 11 7 11 7a18 18 0 0 1-2.2 3.2M1 1l22 22"/></svg>';
function addEye(i) {
  if (!i || i.parentNode.classList.contains('pwf')) return;
  const w = document.createElement('span'); w.className = 'pwf'; i.replaceWith(w); w.append(i);
  const b = document.createElement('button'); b.type = 'button'; b.className = 'eye'; b.setAttribute('aria-label', 'Show password'); b.setAttribute('aria-pressed', 'false'); b.innerHTML = EYE;
  b.addEventListener('click', () => { const s = i.type === 'password'; i.type = s ? 'text' : 'password'; b.innerHTML = s ? EYE0 : EYE; b.setAttribute('aria-pressed', String(s)); b.setAttribute('aria-label', s ? 'Hide password' : 'Show password'); i.focus(); });
  w.append(b);
}
addEye($('#pw'));

/* ---------------------------------------------------------------- sign in / sign up */
$('#pw').addEventListener('focus', () => $('#fig').classList.add('hide'));
$('#pw').addEventListener('blur', () => $('#fig').classList.remove('hide'));
$$('.tabs button').forEach(b => b.addEventListener('click', () => setMode(b.dataset.m)));
function setMode(m) {
  mode = m; $$('.su').forEach(x => x.hidden = mode !== 'up');
  $('#pw').autocomplete = mode === 'up' ? 'new-password' : 'current-password';
  $$('.tabs button').forEach(x => { x.classList.toggle('on', x.dataset.m === mode); x.setAttribute('aria-pressed', String(x.dataset.m === mode)); });
  $('#pw').setAttribute('aria-describedby', mode === 'up' ? 'er pwrule' : 'er');
  $('#sb').textContent = mode === 'in' ? 'Enter the vault' : 'Create my account'; $('#er').textContent = ''; mood('idle');
}
const bad = m => { $('#er').textContent = m; mood('sad', 1400); shk($('#fm')); };

$('#fm').addEventListener('submit', async e => {
  e.preventDefault();
  const u = $('#un').value.trim(), p = $('#pw').value, btn = $('#sb');
  if (!u || !p) return bad('Enter your username and password.');
  btn.disabled = true;
  try {
    if (mode === 'up') {
      if (!/^[A-Za-z][A-Za-z0-9_]{2,31}$/.test(u)) return bad('Username: 3–32 letters, digits or underscores, starting with a letter.');
      if (!pwOk(p, u)) return bad(PW_RULE);
      const email = $('#em0').value.trim();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(email)) return bad('Enter a valid email address.');
      const r = await API.auth.signupStart({ username: u, password: p, email });
      signupCode(r);
    } else {
      const r = await API.auth.login(u, p);
      go(r.user);
    }
  } catch (err) { bad(errMsg(err)); } finally { btn.disabled = false; }
});

function codeBox(o, bx) {
  const err = t => { o.querySelector('.er').textContent = t; shk(bx); bx.classList.add('glow'); setTimeout(() => bx.classList.remove('glow'), 900); };
  o.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); o.querySelector('.go').click(); } });
  o.querySelectorAll('input[inputmode=numeric]').forEach(i => i.addEventListener('input', () => { i.value = i.value.replace(/\D/g, '').slice(0, 6); }));
  return err;
}
function signupCode(r) {
  lockModal(`<h3>🔐 Enter your verification code</h3><p class="mut">A 6-digit code was sent to ${esc(r.email)}. Enter it to create your account.</p>
    <label>Email code<input id="c1" inputmode="numeric" maxlength="6" autocomplete="one-time-code"></label><div class="er"></div>
    <p class="acts"><button class="go" type="button">Verify &amp; create account</button><button class="g" id="rs2" type="button">Resend code</button><button class="g cl" type="button">Cancel</button></p>`, (o, bx) => {
    const err = codeBox(o, bx);
    o.querySelector('#rs2').addEventListener('click', async () => { try { await API.auth.signupResend(r.challenge_id); toast('New code sent.'); } catch (e) { err(e.detail); } });
    o.querySelector('.go').addEventListener('click', async () => {
      const a = o.querySelector('#c1').value.trim();
      if (!/^\d{6}$/.test(a)) return err('The code is exactly 6 digits.');
      try { const u = await API.auth.signupVerify(r.challenge_id, a); o.remove(); go(u); } catch (e) { err(e.detail); }
    });
  });
}

function go(u) {
  me = u; lastActive = Date.now(); mood('happy'); $('#er').textContent = '';
  setTimeout(() => {
    $('#open').classList.add('on');
    setTimeout(() => { $('#login').hidden = true; $('#app').hidden = false; vantaOff(); build(); }, 2900);
    setTimeout(() => $('#open').classList.remove('on'), 3700);
  }, 650);
}

function out(msg, skipServer) {
  if (!me) return;
  if (!skipServer) API.auth.logout().catch(() => { /* session may already be gone */ });
  me = null; cur = null; RD = null; PC.clear();
  $$('.md').forEach(o => o.remove()); $('#app').hidden = true; $('#login').hidden = false; $('#fm').reset(); setMode('in');
  $('#fab').hidden = true; mood('idle'); vantaOn(); msg && toast(msg, 1);
}
API.onSessionLost(d => out(d || 'Your session ended. Please sign in again.', true));
$('#lo').addEventListener('click', () => out());

['pointerdown', 'keydown'].forEach(v => addEventListener(v, () => { lastActive = Date.now(); }, { passive: true }));
setInterval(async () => {
  if (!me) return;
  if (Date.now() - lastActive > 15 * 60e3) return out('Session expired after 15 idle minutes.');
  if (Date.now() - lastActive < 60e3) {             // only while the person is active, so polling never keeps an idle session alive
    try { const u = await API.auth.me(); const changed = u.warnings !== me.warnings; me = u; badges(); if (changed) warnCheck(); }
    catch (e) { if (e.status === 403) out(e.detail, true); }
  }
}, 30e3);

/* ---------------------------------------------------------------- shell */
const ALL = ['ADMIN', 'OWNER', 'VIEWER'];
const NAV = [['home', 'Overview', ALL], ['docs', 'Documents', ALL], ['policy', 'Safety & Support', ['OWNER', 'VIEWER']], ['people', 'People & Roles', ['ADMIN']], ['access', 'Access', ['OWNER']], ['audit', 'Audit trail', ALL]];
const V = {};

function build() {
  if (me.must_reset) return resetPw(build);
  $('#who').textContent = me.display_name; $('#rl').textContent = me.role.toLowerCase();
  $('#nv').innerHTML = NAV.filter(n => n[2].includes(me.role)).map((n, i) => `<button type="button" data-v="${n[0]}"><i aria-hidden="true">0${i + 1}</i>${n[1]}</button>`).join('');
  badges(); fabClose(); $('#fab').hidden = me.role !== 'OWNER'; cur = null; show('home');
}
$('#nv').addEventListener('click', e => { const b = e.target.closest('button'); if (b && b.dataset.v !== cur) show(b.dataset.v).then(() => { const h = $('#main h2'); if (h) { h.tabIndex = -1; h.focus({ preventScroll: true }); } }); });

async function show(v) {
  if (!me || !NAV.some(n => n[0] === v && n[2].includes(me.role))) return;
  const m = $('#main');
  if (cur) { m.className = 'out-' + cur; await new Promise(r => setTimeout(r, 290)); }
  cur = v; RD = null; PC.clear(); m.className = ''; m.innerHTML = ''; void m.offsetWidth;
  try { await V[v](m); } catch (e) { fail(e); }
  m.querySelectorAll('input[type=password]').forEach(addEye); m.classList.add('in-' + v); warnCheck();
  $$('#nv button').forEach(b => { b.classList.toggle('on', b.dataset.v === v); if (b.dataset.v === v) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
  const nm = (NAV.find(n => n[0] === v) || [])[1]; document.title = (nm ? nm + ' · ' : '') + 'TrustVault'; enhance(m);
}

function badges() { $('#bd').innerHTML = (me.is_verified ? '<b class="bdg v">✓ VERIFIED</b>' : '') + (me.warnings ? `<b class="bdg w">⚠ WARNINGS ${me.warnings}</b>` : ''); }

function warnCheck() {
  if (!me || me.role !== 'VIEWER' || !(me.warnings > me.warnings_seen) || $('.md.wn')) return;
  const o = document.createElement('div'); o.className = 'md gt wn'; o.setAttribute('role', 'alertdialog');
  o.innerHTML = `<div><h2>⚠ Warning</h2><p>STAY ALERT. Tampering with documents without owner consent is strictly prohibited. This action violates vault security, is logged as improper behavior, and is immediately reported to the owner.</p><p class="mut">Warnings on record: ${me.warnings}. A fourth warning blocks this account.</p><button id="wk" type="button">I Understand &amp; Agree</button></div>`;
  document.body.append(o); dlg(o);
  o.querySelector('#wk').addEventListener('click', async () => { try { const r = await API.safety.ack(); me.warnings_seen = r.warnings_seen; o.remove(); } catch (e) { fail(e); } });
}

function resetPw(next) {
  lockModal(`<h3>Choose a new password</h3><p class="mut">This account must set a new password before continuing.</p>
    <label>Current password<input id="cp" type="password" autocomplete="current-password"></label>
    <label>New password<input id="np" type="password" autocomplete="new-password"></label><p class="pwrule">${PW_RULE}</p>
    <p class="acts"><button id="nb" type="button">Save</button><button class="g" id="no" type="button">Sign out</button></p><div class="er" id="ne"></div>`, (o, bx) => {
    o.querySelector('#no').addEventListener('click', () => { o.remove(); out(); });
    o.querySelector('#nb').addEventListener('click', async () => {
      const c = o.querySelector('#cp').value, p = o.querySelector('#np').value;
      if (!pwOk(p, me.username)) { o.querySelector('#ne').textContent = PW_RULE; return shk(bx); }
      try { me = await API.auth.changePassword(c, p); o.remove(); toast('Password changed.'); next(); }
      catch (e) { o.querySelector('#ne').textContent = e.detail; shk(bx); }
    });
  });
}

function blockedAlert() {
  if ($('.md.ba')) return;
  modal(`<h3 class="danger">⚠️ This Document Owner has been Blocked by Admin</h3><p class="mut">The document stays listed for audit, but it cannot be opened until an administrator unblocks the owner.</p><div class="acts"><button class="cl" type="button">Close</button></div>`,
    (o, bx) => { o.classList.add('ba'); bx.classList.add('glow'); o.setAttribute('role', 'alertdialog'); });
}

/* ---------------------------------------------------------------- overview */
const RC = { ADMIN: ['Administrator', 'Sees every document’s details, the full audit trail (History) and refused attempts, and sets roles. Cannot read content: administrators can never hold a grant but have control over Owners and Viewers.'], OWNER: ['Owner', 'Uploads, organises, shares and revokes access, and deletes their own documents. Sees the trail for their documents.'], VIEWER: ['Viewer', 'Opens or edits only what was granted. Sees their own trail. Cannot upload or share.'] };
const rolesHtml = () => `<div class="rcs">${Object.entries(RC).map(([k, v]) => `<div class="rc${k === me.role ? ' me' : ''}"><h3>${v[0]}${k === me.role ? ' · you' : ''}</h3><p>${v[1]}</p></div>`).join('')}</div>`;
V.home = async m => {
  const s = await API.stats();
  m.innerHTML = `<h2>Hello, ${esc(me.display_name)}</h2><p class="mut">Every file stays locked until its owner says otherwise.</p><div class="home"><div class="show">${mini()}<svg class="arr" viewBox="0 0 40 20" width="40" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M3 10H34M26 3l8 7-8 7"/></svg><div class="sx"><div class="fmt"><span>PDF</span><span>DOC</span><span>DOCX</span><span>TXT</span></div></div></div><div class="stats"><div><b>${s.documents}</b>documents you can see</div><div><b>${s.refused}</b>refused attempts</div><div><b>${s.audit_entries}</b>audit entries</div></div></div>${rolesHtml()}`;
};

/* ---------------------------------------------------------------- documents */
const IMG = /\.(jpe?g|png|webp|svg)$/i;
async function withPasscode(d, fn) {
  // Try without (or with a passcode typed earlier in this view); ask only if the server says 428.
  try { return await fn(PC.get(d.id)); }
  catch (e) {
    if (e.status !== 428 && !(e.status === 403 && PC.has(d.id) && /passcode/i.test(e.detail))) throw e;
    PC.delete(d.id);
    return new Promise((resolve, reject) => {
      modal(`<h3>🔒 Passcode required</h3><p class="mut">The owner protected ${esc(d.name)}.</p><p><input id="pcq" aria-label="Document passcode" class="w100" type="password" placeholder="Document passcode" autocomplete="off"></p><div class="er"></div><div class="acts"><button id="pcu" type="button">Unlock</button><button class="g cl" type="button">Cancel</button></div>`, (o, bx) => {
        o.addEventListener('closed', () => resolve(null));
        const go = async () => {
          const v = o.querySelector('#pcq').value;
          try { const r = await fn(v); PC.set(d.id, v); o.remove(); resolve(r); }
          catch (err) { if (err.status === 403 || err.status === 429) { o.querySelector('.er').textContent = err.detail; shk(bx); bx.classList.add('glow'); } else { o.remove(); reject(err); } }
        };
        o.querySelector('#pcu').addEventListener('click', go);
        o.querySelector('#pcq').addEventListener('keydown', ev => { if (ev.key === 'Enter') go(); });
      });
    });
  }
}

const A = {
  async open(d) {
    const r = await safe(withPasscode(d, pc => API.docs.content(d.id, pc))); if (!r) return;
    let body;
    if (d.is_text) body = `<pre>${esc(await r.blob.text())}</pre>`;
    else if (IMG.test(d.name)) body = `<img alt="Preview of ${esc(d.name)}" class="preview" id="pv">`;
    else body = `<p>Binary file, ${(d.size / 1024).toFixed(1)} KB. Use Download to open it.</p>`;
    modal(`<h3>${esc(d.name)}</h3><p class="meta">${esc(d.id)} · SHA-256 ${esc(d.sha256.slice(0, 16))}…</p>${body}<div class="acts"><button class="g cl" type="button">Close</button></div>`, o => {
      const img = o.querySelector('#pv');
      if (img) { const url = URL.createObjectURL(r.blob); img.src = url; o.addEventListener('closed', () => URL.revokeObjectURL(url)); }
    });
  },
  async dl(d) {
    const r = await safe(withPasscode(d, pc => API.docs.download(d.id, pc))); if (!r) return;
    const url = URL.createObjectURL(r.blob), a = document.createElement('a'); a.href = url; a.download = d.name; document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10e3); toast('Download issued and logged.');
  },
  async meta(d) {
    const x = await safe(API.docs.metadata(d.id)); if (!x) return;
    modal(`<h3>${esc(x.name)}</h3><p class="meta">Metadata only</p><p>ID ${esc(x.id)}<br>Owner ${esc(x.owner)} · ${esc(x.category)}<br>Created ${esc(x.date)} · ${x.size} bytes<br>SHA-256 <code class="brk">${esc(x.sha256)}</code><br>Passcode ${x.has_passcode ? '<b class="bdg l">LOCKED</b>' : 'none'} · Grants ${x.grants}</p><p class="mut">Content hidden: it needs a grant from the owner.</p><div class="acts"><button class="g cl" type="button">Close</button></div>`);
  },
  async edt(d) {
    const r = await safe(withPasscode(d, pc => API.docs.content(d.id, pc))); if (!r) return;
    const text = await r.blob.text();
    modal(`<h3>Edit ${esc(d.name)}</h3><p><textarea id="et" aria-label="Document text" class="w100" rows="9" maxlength="20000">${esc(text)}</textarea></p><div class="acts"><button id="es" type="button">Save</button><button class="g cl" type="button">Cancel</button></div>`, o =>
      o.querySelector('#es').addEventListener('click', async () => {
        if (await safe(API.docs.editText(d.id, o.querySelector('#et').value, PC.get(d.id)))) { toast('Saved and logged.'); o.remove(); RD && RD(); }
      }));
  },
  ren(d) {
    modal(`<h3>Rename</h3><p><input id="rn" aria-label="New file name" class="w100" value="${esc(d.name)}" maxlength="80"></p><div class="acts"><button id="rs" type="button">Save</button><button class="g cl" type="button">Cancel</button></div>`, o =>
      o.querySelector('#rs').addEventListener('click', async () => {
        const n = o.querySelector('#rn').value.trim(), x = s => s.split('.').pop().toLowerCase();
        if (!n || x(n) !== x(d.name)) return toast('Name needed, and the file type cannot change.', 1);
        o.remove();
        if (await safe(withPasscode(d, pc => API.docs.rename(d.id, n, pc)))) { toast('Renamed.'); RD && RD(); }
      }));
  },
  del(d) {
    modal(`<h3>Delete this document?</h3><p class="mut">It leaves every list at once. The audit record stays.</p><div class="acts"><button id="ds" type="button">Delete</button><button class="g cl" type="button">Keep</button></div>`, o =>
      o.querySelector('#ds').addEventListener('click', async () => { if (await safe(API.docs.remove(d.id))) toast('Deleted.'); o.remove(); RD && RD(); }));
  },
  dm(d) {
    modal(`<h3>Message ${esc(d.owner)}</h3><p class="meta">About ${esc(d.id)} · ${esc(d.name)}</p><label>Message<textarea id="mt" rows="4" maxlength="500"></textarea></label><div class="er"></div><div class="acts"><button id="ms" type="button">Send</button><button class="g cl" type="button">Cancel</button></div>`, (o, bx) =>
      o.querySelector('#ms').addEventListener('click', async () => {
        const t = o.querySelector('#mt').value.trim();
        if (t.length < 5) { o.querySelector('#mt').classList.add('inv'); o.querySelector('.er').textContent = 'Write at least 5 characters.'; return shk(bx); }
        if (await safe(API.safety.message(d.id, t))) { o.remove(); toast('Message sent to ' + d.owner + '.'); }
      }));
  },
};

V.docs = async m => {
  const owners = await API.docs.owners();
  m.innerHTML = `<h2>Documents</h2><p class="mut">${me.role === 'ADMIN' ? 'Administrators see metadata only. Content needs a grant, and administrators cannot hold one.' : 'Only what you own or were granted appears here.'}</p>
  <div class="bar" id="bar"><span class="mag" id="mg"><svg viewBox="0 0 24 24" fill="none" stroke-width="2.6" stroke-linecap="round"><circle cx="10" cy="10" r="6"/><path d="M15 15l6 6"/></svg></span><input id="q" aria-label="Search documents by name" placeholder="Search name" maxlength="80"><select id="fo" aria-label="Filter by owner"><option value="">Any owner</option>${owners.map(o => `<option>${esc(o)}</option>`).join('')}</select><select id="fc" aria-label="Filter by category"><option value="">Any category</option>${CATS.map(c => `<option>${c}</option>`).join('')}</select><label class="ck">From <input type="date" id="fd"></label></div>
  <div class="grid" id="gr"></div>${me.role === 'ADMIN' ? '' : '<div class="bar"><input id="pb" aria-label="Document ID to probe" placeholder="Probe a document ID" maxlength="24"><button class="g" id="pg" type="button">Probe</button></div>'}`;
  let docs = [], seq = 0;
  RD = async () => {
    const my = ++seq;
    const r = await safe(API.docs.list({ q: $('#q').value.trim(), owner: $('#fo').value, category: $('#fc').value, from_date: $('#fd').value }));
    if (!r || my !== seq || cur !== 'docs') return;
    docs = r.documents;
    $('#gr').innerHTML = docs.map((d, i) => {
      let b = d.can.read ? [['open', 'Open'], ['dl', 'Download']] : [['meta', 'Metadata'], ['open', 'Try open']];
      if (d.can.edit && d.is_text) b.push(['edt', 'Edit']); if (d.can.rename) b.push(['ren', 'Rename']);
      if (d.access !== 'owner' && me.role !== 'ADMIN' && d.can.read) b.push(['dm', 'Message owner']);
      if (d.can.own) b.push(['del', 'Delete']); if (d.owner_blocked) b = [['open', 'Open']];
      return `<article class="card" data-i="${i}"><span class="ext">${esc(d.name.split('.').pop())}</span><h3>${esc(d.name)}</h3><p class="meta">${esc(d.id)} · ${esc(d.owner)} · ${esc(d.category)} · ${esc(d.date)}</p><span class="lv">${esc(d.access)}</span>${d.has_passcode ? '<b class="bdg l">Private Document 🔒</b>' : ''}${d.owner_blocked ? '<b class="bdg b">OWNER BLOCKED</b>' : ''}<div class="acts">${b.map(x => `<button class="g" type="button" data-a="${x[0]}" data-i="${i}" aria-label="${x[1]}: ${esc(d.name)}">${x[1]}</button>`).join('')}</div></article>`;
    }).join('') || EMPTY('No documents found. Try a different search.');
    $$('#gr .card').forEach(c => c.style.setProperty('--d', (Number(c.dataset.i) * 70) + 'ms'));
  };
  let t; $$('#bar input,#bar select').forEach(e => e.addEventListener('input', () => { clearTimeout(t); t = setTimeout(RD, 200); }));
  $('#q').addEventListener('input', () => { const g = $('#mg'); g.classList.add('on'); clearTimeout(g.t); g.t = setTimeout(() => g.classList.remove('on'), 700); });
  $('#gr').addEventListener('click', e => { const b = e.target.closest('button[data-a]'); if (b) A[b.dataset.a](docs[Number(b.dataset.i)]); });
  if ($('#pg')) $('#pg').addEventListener('click', async () => { if (await safe(API.docs.probe($('#pb').value.trim()))) toast('Readable. Probe logged.'); });
  await RD();
};

/* ---------------------------------------------------------------- access (owners) */
V.access = async m => {
  const [list, users] = await Promise.all([API.docs.list({}), API.docs.grantable()]);
  const mine = list.documents.filter(d => d.access === 'owner');
  m.innerHTML = '<h2>Who may open what</h2>' + (mine.length ? `<div class="bar"><select id="ad" aria-label="Choose a document">${mine.map(d => `<option value="${esc(d.id)}">${esc(d.id)} · ${esc(d.name)}</option>`).join('')}</select></div><div id="gl"></div>
  <div class="bar"><select id="gu" aria-label="Viewer to give access to">${users.map(u => `<option value="${esc(u.username)}">${esc(u.username)} (${u.role.toLowerCase()})</option>`).join('')}</select><select id="gp" aria-label="Permission"><option>read</option><option>edit</option></select><label class="ck"><input type="checkbox" id="gc"> can rename</label><button id="gb" type="button">Grant</button></div>
  <div class="bar"><input id="pcv" aria-label="New document passcode, 8 or more characters" type="password" placeholder="Document passcode (8+ characters)" autocomplete="new-password"><button id="pcs" type="button">Set passcode</button><button class="g" id="pcc" type="button">Remove</button><b id="pst"></b></div>
  <p class="mut">Owners you share with get read-only access. Revocation applies to the very next request. Others need the passcode before opening a protected file.</p>` : EMPTY('You own no documents yet.'));
  if (!mine.length) return;
  const id = () => $('#ad').value;
  const rg = async () => {
    const g = await safe(API.docs.grants(id())); if (!g) return;
    $('#pst').innerHTML = g.has_passcode ? '<span class="bdg v">🔑 PASSCODE SET</span>' : '<span class="bdg l">NO PASSCODE</span>';
    $('#gl').innerHTML = g.grants.length ? g.grants.map(x => {
      const ow = x.role === 'OWNER', u = esc(x.username);
      return `<div class="row"><b>${u}</b>${ow ? '<span class="lv">read only (owner)</span>' : `<select data-p="${u}" aria-label="Permission for ${u}"><option ${x.level === 'read' ? 'selected' : ''}>read</option><option ${x.level === 'edit' ? 'selected' : ''}>edit</option></select><label class="ck"><input type="checkbox" data-r="${u}" ${x.can_rename ? 'checked' : ''}> can rename</label>`}<button class="g" type="button" data-u="${u}" aria-label="Revoke access for ${u}">Revoke</button>${x.role === 'VIEWER' ? `<button class="g" type="button" data-rp="${u}" aria-label="Report ${u}">Report</button>` : ''}</div>`;
    }).join('') : EMPTY('Private to you. No one else has access.');
  };
  $('#ad').addEventListener('change', rg);
  $('#gl').addEventListener('click', async e => {
    const b = e.target.closest('button'); if (!b) return;
    if (b.dataset.rp) return reportModal(b.dataset.rp, id(), rg);
    if (await safe(API.docs.revoke(id(), b.dataset.u))) { toast('Access withdrawn.'); rg(); }
  });
  $('#gl').addEventListener('change', async e => {
    const t = e.target, row = t.closest('.row'), u = t.dataset.p || t.dataset.r; if (!u) return;
    const level = row.querySelector('select').value, rn = row.querySelector('input[type=checkbox]').checked;
    if (await safe(API.docs.grant(id(), u, level, rn))) toast('Permission updated.'); else rg();
  });
  $('#gb').addEventListener('click', async () => { if (await safe(API.docs.grant(id(), $('#gu').value, $('#gp').value, $('#gc').checked))) { toast('Access granted.'); rg(); } });
  $('#pcs').addEventListener('click', async () => {
    const v = $('#pcv').value; if (v.length < 8) return toast('Passcode needs 8 or more characters.', 1);
    if (await safe(API.docs.setPasscode(id(), v))) { $('#pcv').value = ''; toast('Passcode set.'); rg(); }
  });
  $('#pcc').addEventListener('click', async () => { if (await safe(API.docs.removePasscode(id()))) { toast('Passcode removed.'); rg(); } });
  await rg();
};

/* ---------------------------------------------------------------- safety & support */
const RT = ['Harassment', 'Inappropriate content', 'Data misuse', 'Other misconduct'];
const rpHtml = (viewers, fixed) => `<label>Category<select id="rt"><option value="">Choose…</option>${RT.map(t => `<option>${t}</option>`).join('')}</select></label><label>Viewer<select id="ru"${fixed ? ' disabled' : ''}><option value="">Choose…</option>${viewers.map(u => `<option${u === fixed ? ' selected' : ''}>${esc(u)}</option>`).join('')}</select></label><label>Details<textarea id="rx" rows="4" maxlength="500" placeholder="What happened? (10 to 500 characters)"></textarea></label><div class="er" id="re"></div>${viewers.length ? '' : '<p class="mut">No viewer currently has access to your documents.</p>'}`;
async function rpSend(root, fixed, docId) {
  const g = s => root.querySelector(s), ty = g('#rt').value, u = fixed || g('#ru').value, tx = g('#rx').value.trim(), badf = [];
  if (!RT.includes(ty)) badf.push('#rt'); if (!u) badf.push('#ru'); if (tx.length < 10 || tx.length > 500) badf.push('#rx');
  ['#rt', '#ru', '#rx'].forEach(s => g(s).classList.remove('inv'));
  if (badf.length) { badf.forEach(s => g(s).classList.add('inv')); g('#re').textContent = 'Choose a category and a viewer, and describe the issue (10 to 500 characters).'; shk(g('#re').parentNode); return false; }
  try { const r = await API.safety.report({ category: ty, viewer: u, details: tx, document_id: docId || null }); toast(r.blocked ? 'Report sent. The viewer is now blocked.' : 'Report sent. Warning recorded.'); return true; }
  catch (e) { g('#re').textContent = e.detail; shk(g('#re').parentNode); return false; }
}
async function reportModal(user, docId, after) {
  const viewers = await safe(API.safety.reportable()); if (!viewers) return;
  modal(`<h3>Report ${esc(user)}</h3><p class="meta">About ${esc(docId)}</p>${rpHtml(viewers, user)}<div class="acts"><button id="rb" type="button">Send report</button><button class="g cl" type="button">Cancel</button></div>`, o =>
    o.querySelector('#rb').addEventListener('click', async () => { if (await rpSend(o, user, docId)) { o.remove(); after && after(); } }));
}

V.policy = async m => {
  if (me.role === 'VIEWER') {
    const sh = await API.safety.shared();
    m.innerHTML = `<h2>Safety & Support</h2><div class="note pol"><h3>TrustVault safety guidelines</h3><ul><li>Your session ends after 15 minutes of inactivity. Sign out on shared devices.</li><li>Sign in with your username and password. Never share your password or any code emailed to you.</li><li>Owners can protect a file with a passcode. Wrong passcodes are recorded, and five misses lock you out for 15 minutes.</li><li>Every open, download, edit and refused attempt is written to a tamper-evident audit trail.</li><li>You can edit or rename a file only if its owner switched that permission on for you.</li><li>Owners can report misconduct. Each report is a warning. Three warnings is the limit: Remember a fourth warning will blocks your account automatically.</li><li>Stuck or need access? Message the document’s owner below. You cannot file reports yourself.</li><li>For Support or Technical assistance, reach out to manikondarohith2005@gmail.com.</li><li>** Notice: Admin time is strictly protected because inproper behaviour of any Owner can't be report and block by any user. So, make sure with valid proofs. Misusing support for time-pass messages will lead to a direct, unannounced account suspension. **</li></ul></div>
    <h3 class="sec">Shared with you</h3>${sh.length ? sh.map((d, i) => `<div class="row"><b>${esc(d.name)}</b><span class="lv">${esc(d.owner)}</span>${d.has_passcode ? '<b class="bdg l">Private Document 🔒</b>' : ''}<button class="g" type="button" data-i="${i}">Direct Message Owner</button></div>`).join('') : EMPTY('Nothing has been shared with you yet.')}`;
    m.querySelectorAll('button[data-i]').forEach(b => b.addEventListener('click', () => A.dm(sh[Number(b.dataset.i)])));
    return;
  }
  const [p, viewers, inbox] = await Promise.all([API.safety.policy(), API.safety.reportable(), API.safety.inbox()]);
  m.innerHTML = `<h2>Safety & Support</h2><div class="note pol"><h3>System policy settings</h3><p class="mut">Security-sensitive settings are fully under your control and your sole responsibility.</p><ul>
    <li>Allowed document types: ${p.allowed_types.map(esc).join(', ')}</li><li>Maximum upload size: ${p.max_upload_mib} MiB</li><li>Idle session lifetime: ${p.session_idle_minutes} minutes</li><li>Sign-in lockout: ${esc(p.lockout)}</li><li>Anonymous guest links: ${esc(p.guest_links)}</li><li>System configuration: ${esc(p.configuration)}</li></ul></div>
    <h3 class="sec">Incident / user report</h3><div class="rpf">${rpHtml(viewers, '')}<p><button id="rb" type="button">Send report</button></p></div>
    <h3 class="sec">Messages from people you share with</h3>${inbox.length ? `<div class="tw"><table><thead><tr><th scope="col">Time (IST)</th><th scope="col">From</th><th scope="col">Doc</th><th scope="col">Message</th></tr></thead><tbody>${inbox.map(x => `<tr><td>${esc(ist(x.at))}</td><td>${esc(x.from)}</td><td>${esc(x.document)}</td><td>${esc(x.body)}</td></tr>`).join('')}</tbody></table></div>` : EMPTY('No messages yet.')}`;
  $('#rb').addEventListener('click', async () => { if (await rpSend(m, '', null)) V.policy(m); });
};

/* ---------------------------------------------------------------- people (admin) */
V.people = async m => {
  const [users, reps] = await Promise.all([API.admin.users(), API.admin.reports()]);
  const bd = u => (u.verified ? '<b class="bdg v">VERIFIED</b>' : '<b class="bdg l">UNVERIFIED</b>') + (u.blocked ? '<b class="bdg b">BLOCKED</b>' : '') + (u.warnings ? `<b class="bdg w">WARNINGS ${u.warnings}</b>` : '') + (u.reset_pending ? '<b class="bdg l">RESET PENDING</b>' : '');
  m.innerHTML = `<h2>People and roles</h2><p class="mut">Email addresses come from sign-up email checks. Opening this page is logged.</p>${rolesHtml()}
  <div class="tw"><table><thead><tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Email</th><th scope="col">Status</th><th scope="col">Actions</th></tr></thead><tbody>${users.map(u => { const n = esc(u.username); return `<tr><td>${n}</td><td><select data-u="${n}" aria-label="Role for ${n}"><option value="OWNER" ${u.role === 'OWNER' ? 'selected' : ''}>owner</option><option value="VIEWER" ${u.role === 'VIEWER' ? 'selected' : ''}>viewer</option></select></td><td>${u.email ? esc(u.email) : '—'}</td><td>${bd(u)}</td><td><button class="g" type="button" data-x="reset" data-id="${n}" aria-label="Reset credentials for ${n}">Reset credentials</button> <button class="g" type="button" data-x="${u.blocked ? 'unblock' : 'block'}" data-id="${n}" aria-label="${u.blocked ? 'Unblock' : 'Block'} ${n}">${u.blocked ? 'Unblock' : 'Block'}</button></td></tr>`; }).join('')}</tbody></table></div>
  <h3 class="sec">Reports</h3><div class="tw"><table><thead><tr><th scope="col">Time (IST)</th><th scope="col">From</th><th scope="col">Category</th><th scope="col">About</th><th scope="col">Doc</th><th scope="col">Details</th></tr></thead><tbody>${reps.map(r => `<tr><td>${esc(ist(r.at))}</td><td>${esc(r.from)}</td><td>${esc(r.category)}</td><td>${esc(r.about)}</td><td>${esc(r.document || '—')}</td><td>${esc(r.details)}</td></tr>`).join('') || '<tr><td colspan="6">No reports yet.</td></tr>'}</tbody></table></div>`;
  m.querySelectorAll('select[data-u]').forEach(s => s.addEventListener('change', async () => { if (await safe(API.admin.setRole(s.dataset.u, s.value))) toast('Role updated and logged.'); else V.people(m); }));
  m.querySelectorAll('button[data-x]').forEach(b => b.addEventListener('click', async () => {
    if (await safe(API.admin[b.dataset.x](b.dataset.id))) { toast('Done and logged.'); V.people(m); }
  }));
};

/* ---------------------------------------------------------------- audit */
V.audit = async m => {
  const adm = me.role === 'ADMIN';
  m.innerHTML = `<h2>${adm ? 'Activity and permission changes' : 'Your trail'}</h2><div class="bar"><button id="vf" type="button">Verify chain</button>${adm ? '<button class="g" id="tp" type="button">Try to tamper</button><button class="g" id="st" type="button">Run access self-tests</button><select id="fa" aria-label="Filter by actor"><option value="">All actors</option></select><select id="fx" aria-label="Filter by action"><option value="">All actions</option></select>' : ''}<label class="ck"><input type="checkbox" id="od"> refused only</label><b id="vs"></b></div>${adm ? '<div class="note" id="wn"></div><div id="tr"></div>' : ''}
  <div class="tw"><table><thead><tr><th scope="col">#</th><th scope="col">Time (IST)</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Doc</th><th scope="col">Result</th><th scope="col">Detail</th><th scope="col">Hash</th></tr></thead><tbody id="tb"></tbody></table></div>`;
  let facetsDone = false;
  const draw = async () => {
    const r = await safe(API.audit.list({ denied_only: $('#od').checked, actor: adm ? $('#fa').value : '', action: adm ? $('#fx').value : '' })); if (!r || cur !== 'audit') return;
    $('#tb').innerHTML = r.entries.map(e => `<tr><td>${e.id}</td><td>${esc(ist(e.at))}</td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td><td>${esc(e.document)}</td><td class="${e.result === 'denied' ? 'den' : 'alw'}">${e.result}</td><td>${esc(e.detail)}</td><td><code>${esc(e.hash.slice(0, 8))}</code></td></tr>`).join('') || '<tr><td colspan="8">No entries.</td></tr>';
    if (adm && !facetsDone) {
      facetsDone = true;
      $('#fa').insertAdjacentHTML('beforeend', r.actors.map(a => `<option>${esc(a)}</option>`).join(''));
      $('#fx').insertAdjacentHTML('beforeend', r.actions.map(a => `<option>${esc(a)}</option>`).join(''));
      const w = r.worth_noticing;
      $('#wn').innerHTML = `<b>Worth noticing</b><br>${w.refused_3_plus.length ? w.refused_3_plus.map(x => `${esc(x.actor)}: ${x.count} refused attempts`).join('<br>') : 'No one has 3 or more refused attempts.'}<br>${w.permission_changes} permission changes recorded.`;
    }
  };
  $$('#od,#fa,#fx').forEach(e => e && e.addEventListener('change', draw));
  $('#vf').addEventListener('click', async () => { const r = await safe(API.audit.verify()); if (!r) return; const s = $('#vs'); s.textContent = r.ok ? `✓ ${r.entries} entries, chain intact` : `✕ Chain broken at entry #${r.broken_at}`; s.className = r.ok ? 'alw' : 'den'; });
  if (adm) {
    $('#tp').addEventListener('click', async () => {
      const r = await safe(API.admin.tamperTest()); if (!r) return;
      $('#tr').innerHTML = `<div class="note"><b>Tamper attempt</b> (UPDATE and DELETE sent straight to MySQL)<div class="${r.protected ? 'alw' : 'den'}">${r.protected ? '✓ Both refused by the database (least-privilege grants and append-only triggers)' : '✕ Audit table is NOT protected'}</div>${Object.entries(r.results).map(([k, v]) => `<div class="mut">${esc(k)}: ${esc(v)}</div>`).join('')}<div class="${r.chain.ok ? 'alw' : 'den'}">${r.chain.ok ? '✓' : '✕'} chain ${r.chain.ok ? 'intact' : 'broken'} (${r.chain.entries} entries)</div></div>`;
      draw();
    });
    $('#st').addEventListener('click', async () => {
      const r = await safe(API.admin.selftest()); if (!r) return;
      $('#tr').innerHTML = `<div class="note"><b>Access self-tests</b> ${r.passed}/${r.total} (run on the server against the same can() every route uses)${r.tests.map(t => `<div class="${t.ok ? 'alw' : 'den'}">${t.ok ? '✓' : '✕'} ${esc(t.name)}</div>`).join('')}</div>`;
    });
  }
  await draw();
};

/* ---------------------------------------------------------------- owner quick upload */
const fab = $('#fab');
function fabClose() { fab.classList.remove('exp'); $('#fb').setAttribute('aria-expanded', 'false'); }
$('#fb').addEventListener('click', () => { const o = fab.classList.toggle('exp'); $('#fb').setAttribute('aria-expanded', String(o)); });
fab.addEventListener('click', e => { const b = e.target.closest('.sub'); if (!b) return; fabClose(); if (b.dataset.f === 'file') $('#ff').click(); else txtPage(); });
addEventListener('keydown', e => { if (e.key === 'Escape') { const was = fab.classList.contains('exp'); fabClose(); if (was && fab.contains(document.activeElement)) $('#fb').focus(); } });
document.addEventListener('pointerdown', e => { if (!fab.contains(e.target)) fabClose(); });
$('#ff').addEventListener('change', e => { quick(e.target.files[0]); e.target.value = ''; });
const catSel = id => `<label>Category<select id="${id}">${CATS.map(c => `<option>${c}</option>`).join('')}</select></label>`;
const OK_EXT = ['pdf', 'txt', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'webp', 'svg'];

function quick(f) {
  if (!f) return;
  const ext = f.name.split('.').pop().toLowerCase();
  if (!OK_EXT.includes(ext)) return toast('File type .' + ext + ' is not allowed.', 1);   // convenience only; the server re-checks everything
  if (f.size > 10485760) return toast('Larger than 10 MiB.', 1);
  modal(`<h3>Seal into vault</h3><p class="meta">${esc(f.name)} · ${(f.size / 1024).toFixed(1)} KB</p>${catSel('uc')}<div class="acts"><button id="us" type="button">Seal</button><button class="g cl" type="button">Cancel</button></div>`, o =>
    o.querySelector('#us').addEventListener('click', async e => {
      e.target.disabled = true;
      const d = await safe(API.docs.upload(f, o.querySelector('#uc').value)); o.remove();
      if (d) { toast('Sealed as ' + d.id + '.'); cur === 'docs' && RD && RD(); }
    }));
}
function txtPage() {
  modal(`<h3>📝 New text page</h3><label>File name<input id="tn" maxlength="60" placeholder="meeting-notes"></label>${catSel('tc')}<label>Text<textarea id="tx" rows="8" maxlength="20000"></textarea></label><div class="acts"><button id="tv" type="button">Save to vault</button><button class="g cl" type="button">Cancel</button></div>`, o =>
    o.querySelector('#tv').addEventListener('click', async () => {
      const tx = o.querySelector('#tx').value; if (!tx.trim()) return toast('Write something first.', 1);
      const d = await safe(API.docs.createText(o.querySelector('#tn').value.trim() || 'note', o.querySelector('#tc').value, tx));
      if (d) { o.remove(); toast('Saved as ' + d.id + '.'); cur === 'docs' && RD && RD(); }
    }));
}

/* ---------------------------------------------------------------- boot: resume an existing session */
(async () => {
  vantaOn();
  try { const u = await API.auth.me(); me = u; $('#login').hidden = true; $('#app').hidden = false; vantaOff(); build(); }
  catch (e) { /* not signed in */ }
})();

/* Forgot Password feature (external file so it also runs under the server's strict CSP) */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };

  var ov = $('fpw-ov'), card = $('fpw-card'), link = $('fpw-link'), row = $('fpw-row');
  var ttl = $('fpw-ttl'), dots = $('fpw-dots').children;
  var titles = ['', 'Forgot password', 'Verify code', 'Security check', 'New password', 'All set'];
  var st = { step: 1, tok: 0, closing: false, ct: 0, email: '', cid: '', code: '', expires: 0, dead: false, timer: 0, cap: '', opener: null, sess: 0, busy: false };

  /* ---------- helpers ---------- */
  function rnd(n) { var a = new Uint32Array(1); crypto.getRandomValues(a); return a[0] % n; }
  function err(n, msg) { $('fpw-e' + n).textContent = msg || ''; }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function isDark() {
    var els = [document.documentElement, document.body], i, v;
    for (i = 0; i < els.length; i++) {
      v = ((els[i].getAttribute('data-theme') || '') + ' ' + (els[i].className || '')).toLowerCase();
      if (/\bdark\b/.test(v)) return true;
      if (/\blight\b/.test(v)) return false;
    }
    for (i = 1; i >= 0; i--) {
      var m = (getComputedStyle(els[i]).backgroundColor || '').match(/[\d.]+/g);
      if (m && m.length >= 3 && !(m.length > 3 && +m[3] === 0)) {
        return (0.299 * m[0] + 0.587 * m[1] + 0.114 * m[2]) < 140;
      }
    }
    return !!(window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches);
  }

  /* ---------- show link only on the Sign in tab ---------- */
  var tabs = document.querySelector('.tabs'), fm = $('fm');
  var calm = !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
  var rowOn = true, rowT = 0;
  function isSignup() {
    var on = tabs && tabs.querySelector('.on');
    if (on && on.getAttribute('data-m') === 'up') return true;
    var su = document.querySelector('.fm .su');           /* sign-up-only fields are visible */
    return !!(su && !su.hidden && su.offsetParent !== null);
  }
  function sync() {
    var want = !isSignup();
    if (want === rowOn) return;
    rowOn = want;
    clearTimeout(rowT);
    row.classList.remove('fpw-rin', 'fpw-rout');
    if (want) {
      row.hidden = false;
      if (!calm) row.classList.add('fpw-rin');
    } else if (calm) {
      row.hidden = true;
    } else {
      row.classList.add('fpw-rout');
      rowT = setTimeout(function () { row.hidden = true; row.classList.remove('fpw-rout'); }, 180);
    }
  }
  if (window.MutationObserver && fm) new MutationObserver(sync).observe(fm, { attributes: true, subtree: true, attributeFilter: ['class', 'hidden'] });
  if (tabs) tabs.addEventListener('click', function () { setTimeout(sync, 0); });
  sync();

  /* ---------- steps ---------- */
  function paint(n) {
    for (var j = 0; j < dots.length; j++) dots[j].className = (j < Math.min(n, 4)) ? 'on' : '';
    $('fpw-dots').hidden = (n >= 5);
    ttl.textContent = titles[n];
  }
  function show(n, instant) {
    var prev = st.step, tok = ++st.tok;
    st.step = n;
    paint(n);
    var fid = ['', 'fpw-em', 'fpw-otp', 'fpw-ci', 'fpw-n1', 'fpw-b5'][n];
    function swap() {
      if (tok !== st.tok) return;
      for (var i = 1; i <= 5; i++) { var el = $('fpw-s' + i); el.classList.remove('fpw-so', 'fpw-si'); el.hidden = (i !== n); }
      if (!instant && !calm) $('fpw-s' + n).classList.add('fpw-si');
      setTimeout(function () { if (tok !== st.tok) return; var f = $(fid); if (f) f.focus(); }, 30);
    }
    var pe = $('fpw-s' + prev);
    if (instant || calm || prev === n || pe.hidden) swap();
    else { pe.classList.add('fpw-so'); setTimeout(swap, 140); }
  }

  function reset() {
    stopTimer();
    st.sess++; st.busy = false;
    st.email = ''; st.cid = ''; st.code = ''; st.dead = false; st.cap = '';
    ['fpw-em', 'fpw-otp', 'fpw-ci', 'fpw-n1', 'fpw-n2'].forEach(function (id) { $(id).value = ''; });
    $('fpw-sh').checked = false; togglePw();
    for (var i = 1; i <= 4; i++) err(i, '');
    renderRules();
  }

  function open() {
    if (st.closing) { clearTimeout(st.ct); st.closing = false; } else { st.opener = document.activeElement; }
    card.classList.toggle('fpw-d', isDark());
    reset();
    show(1, true);
    ov.classList.remove('fpw-out', 'fpw-in');
    ov.hidden = false; $('login').setAttribute('inert', '');
    if (!calm) { void ov.offsetWidth; ov.classList.add('fpw-in'); }
    document.body.classList.add('fpw-lock');
  }
  function close() {
    if (ov.hidden || st.closing) return;
    stopTimer();
    document.body.classList.remove('fpw-lock');
    function fin() {
      st.closing = false;
      ov.hidden = true; $('login').removeAttribute('inert');
      ov.classList.remove('fpw-in', 'fpw-out');
      reset();
      var back = (st.opener && document.contains(st.opener)) ? st.opener : link;
      if (back && back.focus) back.focus();
    }
    if (calm) { fin(); return; }
    st.closing = true;
    ov.classList.remove('fpw-in');
    ov.classList.add('fpw-out');
    st.ct = setTimeout(fin, 210);
  }

  /* ---------- server calls ---------- */
  var EMAIL_OK = /^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$/;
  function api() { return window.Vault.auth; }
  function msgOf(e) { return (e && e.detail) ? e.detail : 'Something went wrong. Please try again.'; }
  /* run one request; the button is freed before ok/fail run, and nothing fires if the dialog was closed or reopened meanwhile */
  function call(btn, req, ok, fail) {
    if (st.busy) return;
    var sess = st.sess;
    function done() { st.busy = false; if (btn) btn.disabled = false; }
    st.busy = true; if (btn) btn.disabled = true;
    req().then(function (r) { if (sess === st.sess) { done(); ok(r); } },
               function (e) { if (sess === st.sess) { done(); fail(e); } });
  }

  /* ---------- step 1: email ---------- */
  function sendEmail(again) {
    var em = again ? st.email : $('fpw-em').value.trim().toLowerCase();
    if (!EMAIL_OK.test(em)) { err(1, 'Enter a valid email address.'); return; }
    err(1, ''); err(2, '');
    call(again ? null : $('fpw-b1'), function () { return api().forgotStart(em); }, function (r) {
      st.email = em; st.cid = r.challenge_id; st.code = '';
      $('fpw-m2').textContent = 'If that email is registered, we sent a 6-digit code to ' + r.email + '.';
      startOtp(r.expires_in || 300);
      show(2);
    }, function (e) {
      if (again) { err(2, msgOf(e)); $('fpw-rs').disabled = false; } else err(1, msgOf(e));
    });
  }

  /* ---------- step 2: emailed code with a countdown ---------- */
  function startOtp(secs) {
    stopTimer();
    st.dead = false;
    st.expires = Date.now() + secs * 1000;
    $('fpw-otp').value = ''; err(2, '');
    $('fpw-b2').disabled = false; $('fpw-otp').disabled = false; $('fpw-rs').disabled = true;
    tick();
    st.timer = setInterval(tick, 250);
  }
  function stopTimer() { if (st.timer) { clearInterval(st.timer); st.timer = 0; } }
  function tick() {
    var left = Math.max(0, Math.ceil((st.expires - Date.now()) / 1000));
    var t = $('fpw-tm');
    t.textContent = pad(Math.floor(left / 60)) + ':' + pad(left % 60);
    t.className = left <= 10 ? 'warn' : '';
    if (left <= 0) expire('Code expired. Press Resend code.');
  }
  function expire(msg) {
    stopTimer(); st.dead = true;
    $('fpw-b2').disabled = true; $('fpw-otp').disabled = true; $('fpw-rs').disabled = false;
    err(2, msg);
  }
  function verifyOtp() {
    if (st.dead) { err(2, 'Code expired. Press Resend code.'); return; }
    var v = $('fpw-otp').value.replace(/\D/g, '');
    if (v.length !== 6) { err(2, 'Enter all 6 digits.'); return; }
    err(2, '');
    call($('fpw-b2'), function () { return api().forgotVerify(st.cid, v); }, function () {
      st.code = v; stopTimer(); err(2, '');
      drawCap(); $('fpw-ci').value = ''; err(3, '');
      show(3);
    }, function (e) {
      if (e.status === 410) expire(msgOf(e));
      else { err(2, msgOf(e)); $('fpw-otp').select(); }
    });
  }

  /* ---------- step 3: captcha ---------- */
  function drawCap() {
    var cv = $('fpw-cv'), g = cv.getContext('2d'), dk = card.classList.contains('fpw-d');
    var chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', i;
    st.cap = ''; for (i = 0; i < 5; i++) st.cap += chars.charAt(rnd(chars.length));
    g.setTransform(2, 0, 0, 2, 0, 0);
    g.clearRect(0, 0, 200, 60);
    g.fillStyle = dk ? '#232836' : '#eef2fb'; g.fillRect(0, 0, 200, 60);
    function line(w) {
      g.strokeStyle = 'hsla(' + rnd(360) + ',55%,' + (dk ? '65%' : '45%') + ',.55)';
      g.lineWidth = w; g.beginPath(); g.moveTo(rnd(200), rnd(60));
      g.bezierCurveTo(rnd(200), rnd(60), rnd(200), rnd(60), rnd(200), rnd(60)); g.stroke();
    }
    for (i = 0; i < 5; i++) line(1.4);
    for (i = 0; i < 45; i++) {
      g.fillStyle = 'hsla(' + rnd(360) + ',50%,' + (dk ? '70%' : '40%') + ',.5)';
      g.fillRect(rnd(200), rnd(60), 2, 2);
    }
    g.font = '700 32px ui-monospace, Menlo, Consolas, monospace';
    g.textAlign = 'center'; g.textBaseline = 'middle';
    for (i = 0; i < 5; i++) {
      g.save();
      g.translate(24 + i * 38, 31 + rnd(9) - 4);
      g.rotate((rnd(41) - 20) * Math.PI / 180);
      g.fillStyle = dk ? '#eef1f8' : '#171b29';
      g.fillText(st.cap.charAt(i), 0, 0);
      g.restore();
    }
    line(2);
  }
  function verifyCap() {
    var v = $('fpw-ci').value.trim().toUpperCase();
    if (!v) { err(3, 'Type the characters from the image.'); return; }
    if (v !== st.cap) {
      err(3, 'Characters do not match. Try the new image.');
      drawCap(); $('fpw-ci').value = ''; $('fpw-ci').focus();
      return;
    }
    err(3, ''); err(4, '');
    show(4);
  }

  /* ---------- step 4: new password ---------- */
  var rules = [
    ['12+ characters', function (s) { return s.length >= 12; }],
    ['Uppercase letter', function (s) { return /[A-Z]/.test(s); }],
    ['Lowercase letter', function (s) { return /[a-z]/.test(s); }],
    ['A number', function (s) { return /\d/.test(s); }],
    ['A symbol', function (s) { return /[^A-Za-z0-9]/.test(s); }]
  ];
  function renderRules() {
    var s = $('fpw-n1').value, ul = $('fpw-rules');
    if (ul.children.length !== rules.length) {
      ul.textContent = '';
      rules.forEach(function (r) { var li = document.createElement('li'); li.textContent = r[0]; ul.appendChild(li); });
    }
    rules.forEach(function (r, i) { ul.children[i].className = r[1](s) ? 'ok' : ''; });
  }
  function togglePw() {
    var t = $('fpw-sh').checked ? 'text' : 'password';
    $('fpw-n1').type = t; $('fpw-n2').type = t;
  }
  function resetPw() {
    var a = $('fpw-n1').value, b = $('fpw-n2').value;
    if (!rules.every(function (r) { return r[1](a); })) { err(4, 'Password does not meet all the requirements.'); return; }
    if (a !== b) { err(4, 'Passwords do not match.'); return; }
    err(4, '');
    call($('fpw-b4'), function () { return api().forgotReset(st.cid, st.code, a); }, function () {
      $('fpw-n1').value = ''; $('fpw-n2').value = ''; st.code = ''; st.cid = '';
      show(5);
    }, function (e) {
      if (e.status === 400 || e.status === 410) { err(1, msgOf(e)); show(1); }   /* the code is no longer valid: start again */
      else err(4, msgOf(e));
    });
  }

  /* ---------- events ---------- */
  link.addEventListener('click', open);
  $('fpw-x').addEventListener('click', close);
  $('fpw-b5').addEventListener('click', function () {
    st.opener = $('un') || link;
    close();
  });
  $('fpw-b1').addEventListener('click', function () { sendEmail(false); });
  $('fpw-b2').addEventListener('click', verifyOtp);
  $('fpw-b3').addEventListener('click', verifyCap);
  $('fpw-b4').addEventListener('click', resetPw);
  $('fpw-rf').addEventListener('click', function () { drawCap(); $('fpw-ci').value = ''; $('fpw-ci').focus(); });
  $('fpw-chg').addEventListener('click', function () { stopTimer(); err(1, ''); show(1); });
  $('fpw-rs').addEventListener('click', function () { sendEmail(true); });
  $('fpw-sh').addEventListener('change', togglePw);
  $('fpw-n1').addEventListener('input', renderRules);
  $('fpw-otp').addEventListener('input', function (e) { e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6); });

  card.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { e.stopPropagation(); close(); return; }
    if (e.key === 'Enter' && e.target.tagName === 'INPUT' && e.target.type !== 'checkbox') {
      e.preventDefault();
      var b = { 1: 'fpw-b1', 2: 'fpw-b2', 3: 'fpw-b3', 4: 'fpw-b4' }[st.step];
      if (b) $(b).click();
      return;
    }
    if (e.key === 'Tab') {
      var f = Array.prototype.filter.call(card.querySelectorAll('button:not([disabled]),input:not([disabled])'), function (el) { return el.offsetParent !== null; });
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !ov.hidden) close(); });

  renderRules();
})();


/* ---- accessibility: skip link and late-rendered content ---- */
$('#sk').addEventListener('click', e => { e.preventDefault(); ($('#login').hidden ? $('#main') : $('#un')).focus(); });
new MutationObserver(() => { clearTimeout(enhance.t); enhance.t = setTimeout(() => enhance($('#main')), 60); }).observe($('#main'), { childList: true, subtree: true });
enhance();
