// 세 겹 줄 — 1차 웹앱
import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js';
import {
  getAuth, GoogleAuthProvider, signInWithPopup, signInWithRedirect, onAuthStateChanged,
  signOut, deleteUser, reauthenticateWithPopup
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js';
import {
  getFirestore, doc, getDoc, setDoc, updateDoc, addDoc, deleteDoc, collection, query, where,
  orderBy, limit, getDocs, onSnapshot, serverTimestamp, arrayUnion, writeBatch, Timestamp
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js';
import { firebaseConfig } from './firebase-config.js';
import {
  DEFAULT_PROMISES, STAGES, CHECK_A, CHECK_B, SCORE_LABELS, TALK_STEPS, FOUNDATIONS,
  CATEGORIES, TOPICS, DAILY_REFS, HELP_LINES
} from './content.js';

const fbApp = initializeApp(firebaseConfig);
const auth = getAuth(fbApp);
const db = getFirestore(fbApp);

// ---------- 상태 ----------
const S = {
  user: null, profile: null, hid: null, hh: null,
  partner: null,               // { uid, name, role }
  promises: [],                // 가정 전체 약속
  today: {},                   // { uid: { promiseId: true } }
  thanks: [], sharedNotes: [], myNotes: [],
  talkDone: null,
  tab: 'home', sub: null,      // sub: { type, ... }
  check: { mine: null, partner: null, draft: {} },
  promiseView: 'mine', editing: null, talkStep: 0, confirmDelete: false,
  myNotesRaw: [], noteKey: null, pendingNote: null, confirmForgot: false,
};
let unsubs = [];

// ---------- 도우미 ----------
const $ = (sel) => document.querySelector(sel);
const view = $('#view');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const pad = (n) => String(n).padStart(2, '0');
const ymd = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const todayStr = () => ymd(new Date());
const periodKey = () => todayStr().slice(0, 7);
function mondayStr() { const d = new Date(); d.setDate(d.getDate() - ((d.getDay() + 6) % 7)); return ymd(d); }
function daysToSunday() { return (7 - new Date().getDay()) % 7; }
const myStage = () => (S.hh?.stages?.[S.user.uid]) || 1;
const partnerStage = () => (S.partner ? (S.hh?.stages?.[S.partner.uid] || 1) : 1);
const roleName = (r) => (r === 'husband' ? '남편' : r === 'wife' ? '아내' : '');

function toast(msg) {
  const t = $('#toast'); t.textContent = msg; t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => { t.hidden = true; }, 2600);
}
function fail(e, msg = '저장하지 못했어요. 인터넷 연결을 확인하고 다시 시도해 주세요.') { console.error(e); toast(msg); }
function setTabs(show) {
  $('#tabs').hidden = !show;
  document.querySelectorAll('#tabs button').forEach((b) => b.classList.toggle('on', b.dataset.tab === S.tab));
}
function stopListeners() { unsubs.forEach((u) => u()); unsubs = []; }

// ---------- 나만 보기 메모 잠금 (기기에서 암호화) ----------
// 메모 비밀번호로 만든 열쇠는 이 휴대폰 안에만 있고 서버로 보내지 않습니다.
const te = new TextEncoder(), td = new TextDecoder();
const b64 = (buf) => { let s = ''; new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); }); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function deriveKey(pw, salt) {
  const base = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 310000, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj)));
  return { iv: b64(iv), ct: b64(ct) };
}
async function unseal(key, { iv, ct }) {
  return JSON.parse(td.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, unb64(ct))));
}
// 기기 저장소(IndexedDB)에 열쇠 보관 — 꺼낼 수 없는 형태라 이 기기에서만 쓸 수 있어요.
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('sgj', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('keys');
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function idbDo(mode, fn) {
  try {
    const d = await idb();
    return await new Promise((res, rej) => {
      const tx = d.transaction('keys', mode); const req = fn(tx.objectStore('keys'));
      tx.oncomplete = () => res(req?.result); tx.onerror = () => rej(tx.error);
    });
  } catch { return undefined; }
}
const keyGet = (uid) => idbDo('readonly', (st) => st.get(uid));
const keyPut = (uid, k) => idbDo('readwrite', (st) => st.put(k, uid));
const keyDel = (uid) => idbDo('readwrite', (st) => st.delete(uid));

async function loadDeviceKey() {
  S.noteKey = null;
  const lock = S.profile?.noteLock; if (!lock) return;
  const k = await keyGet(S.user.uid);
  if (!k) return;
  try { await unseal(k, lock.check); S.noteKey = k; } catch { await keyDel(S.user.uid); }
}

async function setupLock(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(pw, salt);
  const noteLock = { salt: b64(salt), check: await seal(key, { ok: 'segyeopjul' }) };
  await updateDoc(doc(db, 'users', S.user.uid), { noteLock });
  S.profile.noteLock = noteLock;
  await afterUnlock(key);
}

async function unlock(pw) {
  const lock = S.profile.noteLock;
  const key = await deriveKey(pw, unb64(lock.salt));
  try { await unseal(key, lock.check); } catch { return false; }
  await afterUnlock(key);
  return true;
}

async function afterUnlock(key) {
  S.noteKey = key;
  await keyPut(S.user.uid, key);
  // 예전에 잠금 없이 저장된 메모가 있으면 잠가서 다시 저장
  for (const n of S.myNotesRaw.filter((x) => x.text !== undefined && !x.ct)) {
    const sealed = await seal(key, { text: n.text, context: n.context || '' });
    await setDoc(doc(db, 'users', S.user.uid, 'notes', n.id), { author: S.user.uid, ...sealed, createdAt: n.createdAt || serverTimestamp() });
  }
  if (S.pendingNote) {
    const pn = S.pendingNote; S.pendingNote = null;
    const t = document.getElementById('note-text'); if (t) t.value = '';
    await addDoc(collection(db, 'users', S.user.uid, 'notes'), { author: S.user.uid, ...(await seal(key, pn)), createdAt: serverTimestamp() });
    toast('잠가서 저장했어요.');
  }
  await refreshMyNotes();
}

async function refreshMyNotes() {
  const out = [];
  for (const n of S.myNotesRaw) {
    if (n.ct && S.noteKey) {
      try { const o = await unseal(S.noteKey, n); out.push({ ...n, text: o.text, context: o.context, locked: false }); }
      catch { out.push({ ...n, text: '', locked: true }); }
    } else if (n.ct) out.push({ ...n, text: '', locked: true });
    else out.push({ ...n, locked: false });
  }
  S.myNotes = out;
  render();
}

async function resetLock() {
  const batch = writeBatch(db);
  (await getDocs(collection(db, 'users', S.user.uid, 'notes'))).forEach((d) => batch.delete(d.ref));
  batch.update(doc(db, 'users', S.user.uid), { noteLock: null });
  await batch.commit();
  S.profile.noteLock = null; S.noteKey = null; await keyDel(S.user.uid);
  toast('잠긴 메모를 지웠어요. 새 비밀번호를 정해 주세요.');
  render();
}

function lockCard() {
  const has = !!S.profile.noteLock;
  const lockedCount = S.myNotes.filter((n) => n.locked).length;
  if (has && S.noteKey) return '';
  if (!has) return `<form id="lock-setup" class="card stack lock">
    <h2 class="h2">메모 비밀번호 정하기</h2>
    ${S.pendingNote ? '<p class="warn">비밀번호를 정하면 방금 쓴 메모가 잠겨서 저장돼요.</p>' : ''}
    <p class="fine">‘나만 보기’ 메모는 이 비밀번호로 잠가서 저장해요. 배우자도, 운영자도 읽을 수 없어요. <b>잊으면 누구도 찾아 줄 수 없으니</b> 꼭 기억해 두세요.</p>
    <label for="pw1">비밀번호 (8자 이상)</label><input id="pw1" name="pw1" type="password" minlength="8" required autocomplete="new-password">
    <label for="pw2">한 번 더</label><input id="pw2" name="pw2" type="password" minlength="8" required autocomplete="new-password">
    <button class="btn primary" type="submit">정하기</button></form>`;
  return `<form id="lock-open" class="card stack lock">
    <h2 class="h2">잠긴 메모 열기</h2>
    ${S.pendingNote ? '<p class="warn">비밀번호를 넣으면 방금 쓴 메모가 잠겨서 저장돼요.</p>' : `<p class="fine">‘나만 보기’ 메모 ${lockedCount}개가 잠겨 있어요. 이 휴대폰에서 한 번만 넣으면 돼요.</p>`}
    <label for="pw-open">메모 비밀번호</label><input id="pw-open" name="pw" type="password" required autocomplete="current-password">
    <button class="btn primary" type="submit">열기</button>
    <button type="button" class="link danger-text" data-action="forgot-lock">비밀번호를 잊었어요</button></form>`;
}

function bindLockForms() {
  $('#lock-setup')?.addEventListener('submit', async (ev) => {
    ev.preventDefault(); const f = ev.target;
    if (f.pw1.value.length < 8) return toast('8자 이상으로 정해 주세요.');
    if (f.pw1.value !== f.pw2.value) return toast('두 비밀번호가 달라요.');
    try { f.querySelector('button').disabled = true; await setupLock(f.pw1.value); toast('메모 비밀번호를 정했어요.'); }
    catch (e) { fail(e); }
  });
  $('#lock-open')?.addEventListener('submit', async (ev) => {
    ev.preventDefault(); const f = ev.target;
    try { f.querySelector('button').disabled = true; if (!(await unlock(f.pw.value))) { toast('비밀번호가 맞지 않아요.'); render(); } }
    catch (e) { fail(e); }
  });
}

// ---------- 로그인 ----------
onAuthStateChanged(auth, async (user) => {
  stopListeners();
  S.user = user;
  if (!user) { S.profile = null; S.hid = null; S.hh = null; return renderLogin(); }
  try { await boot(); } catch (e) { fail(e, '불러오지 못했어요. 새로고침해 주세요.'); }
});

async function boot() {
  const snap = await getDoc(doc(db, 'users', S.user.uid));
  S.profile = snap.exists() ? snap.data() : null;
  if (!S.profile || !S.profile.role) return renderOnboarding();
  if (!S.profile.householdId) return renderConnect();
  S.hid = S.profile.householdId;
  const hs = await getDoc(doc(db, 'households', S.hid)).catch(() => null);
  if (!hs || !hs.exists() || !(hs.data().members || []).includes(S.user.uid)) {
    await updateDoc(doc(db, 'users', S.user.uid), { householdId: null });
    S.profile.householdId = null; S.hid = null;
    return renderConnect();
  }
  S.hh = hs.data();
  await loadDeviceKey();
  await seedPromisesIfNeeded();
  listen();
  setTabs(true);
  render();
}

async function login() {
  const provider = new GoogleAuthProvider();
  try { await signInWithPopup(auth, provider); }
  catch (e) {
    if (['auth/popup-blocked', 'auth/operation-not-supported-in-this-environment', 'auth/cancelled-popup-request'].includes(e.code)) {
      await signInWithRedirect(auth, provider);
    } else if (e.code !== 'auth/popup-closed-by-user') fail(e, '로그인하지 못했어요. 다시 시도해 주세요.');
  }
}

function renderLogin() {
  setTabs(false);
  view.innerHTML = `
  <section class="login">
    <div class="beams" aria-hidden="true"></div>
    <div class="login-text">
      <span class="kicker">세 겹 줄</span>
      <h1>함께 자라가는<br>가정</h1>
      <p>남편과 아내가 각자 로그인하고,<br>하나의 약속으로 연결됩니다.</p>
      <button type="button" class="btn big light" data-action="login">Google 계정으로 시작하기</button>
      <p class="fine">배우자에게는 내가 나눈 메모만 보여요.</p>
      ${privacyBlock()}
    </div>
  </section>`;
}

// ---------- 보안 안내 ----------
function privacyBlock(open = false) {
  return `<details class="card privacy" ${open ? 'open' : ''}>
    <summary>내 기록은 누가 볼 수 있나요?</summary>
    <div class="pv-row"><span class="pv-tag both">함께 봐요</span><p>약속 체크, 감사, 나눈 메모, 주간 대화</p></div>
    <div class="pv-row"><span class="pv-tag cond">둘 다 마치면</span><p>월간 점검 점수</p></div>
    <div class="pv-row"><span class="pv-tag me">나만 봐요</span><p>‘나만 보기’ 메모는 내 비밀번호로 잠가서 저장해요. 배우자도, 운영자도 읽을 수 없어요.</p></div>
    <p class="fine pv-foot">광고를 넣지 않고, 기록을 팔지 않아요. 계정을 삭제하면 내 기록은 모두 지워져요.</p>
  </details>`;
}

// ---------- 처음 설정 ----------
function renderOnboarding() {
  setTabs(false);
  view.innerHTML = `
  <section class="page narrow">
    <span class="kicker">처음 설정</span>
    <h1 class="title">반가워요</h1>
    <p class="lead">배우자에게 보일 이름과 역할을 알려 주세요. 역할에 맞는 기본 약속이 준비됩니다.</p>
    <form id="onb" class="stack">
      <label for="onb-name">이름</label>
      <input id="onb-name" name="name" required maxlength="20" value="${esc(S.user.displayName || '')}">
      <fieldset class="seg">
        <legend>나는</legend>
        <label><input type="radio" name="role" value="husband" required> 남편</label>
        <label><input type="radio" name="role" value="wife"> 아내</label>
      </fieldset>
      <button class="btn primary big" type="submit">시작하기</button>
    </form>
    ${privacyBlock()}
  </section>`;
  $('#onb').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const profile = { name: fd.get('name').trim(), role: fd.get('role'), email: S.user.email || '', householdId: null, createdAt: serverTimestamp() };
    try { await setDoc(doc(db, 'users', S.user.uid), profile, { merge: true }); S.profile = profile; renderConnect(); }
    catch (e) { fail(e); }
  });
}

// ---------- 부부 연결 ----------
function renderConnect(code = null) {
  setTabs(false);
  view.innerHTML = `
  <section class="page narrow">
    <span class="kicker">${esc(S.profile.name)}님 로그인됨</span>
    <h1 class="title">배우자와 연결하기</h1>
    <p class="lead">한 사람이 초대 코드를 만들고, 다른 사람이 그 코드를 입력하면 하나의 가정으로 묶입니다.</p>
    ${connectBlock(code)}
    <button type="button" class="btn ghost" data-action="solo-start">연결은 나중에 하고 먼저 둘러보기</button>
    ${privacyBlock()}
  </section>`;
}

function connectBlock(code) {
  return `
    <div class="card stack">
      <h2 class="h2">내가 초대하기</h2>
      ${code ? `<div class="code-box"><span class="code">${esc(code)}</span><button type="button" class="btn small dark" data-action="copy-code" data-code="${esc(code)}">복사</button></div>
        <p class="fine">24시간 동안 쓸 수 있어요. 문자나 카톡으로 보내 주세요. 배우자가 입력하면 자동으로 연결됩니다.</p>`
      : `<button type="button" class="btn primary" data-action="make-invite">초대 코드 만들기</button>`}
    </div>
    <div class="or"><span>또는</span></div>
    <form id="join" class="card stack">
      <label for="join-code" class="h2">받은 코드 입력하기</label>
      <input id="join-code" name="code" placeholder="예: K7M2QX" maxlength="8" autocomplete="off" autocapitalize="characters" class="code-input">
      <button class="btn primary" type="submit">연결하기</button>
    </form>`;
}

async function ensureHousehold() {
  if (S.hid) return S.hid;
  const ref = await addDoc(collection(db, 'households'), {
    members: [S.user.uid], names: { [S.user.uid]: S.profile.name }, roles: { [S.user.uid]: S.profile.role },
    stages: { [S.user.uid]: 1 }, createdAt: serverTimestamp(),
  });
  await updateDoc(doc(db, 'users', S.user.uid), { householdId: ref.id });
  S.hid = ref.id; S.profile.householdId = ref.id;
  return ref.id;
}

function newCode() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const a = new Uint32Array(6); crypto.getRandomValues(a);
  return Array.from(a, (n) => chars[n % chars.length]).join('');
}

async function makeInvite() {
  try {
    const hid = await ensureHousehold();
    const code = newCode();
    await setDoc(doc(db, 'invites', code), {
      householdId: hid, createdBy: S.user.uid,
      expiresAt: Timestamp.fromDate(new Date(Date.now() + 24 * 3600 * 1000)), createdAt: serverTimestamp(),
    });
    if (S.tab === 'me' && S.hh) { S.inviteCode = code; render(); }
    else {
      renderConnect(code);
      // 배우자가 코드를 입력하면 자동으로 홈으로 넘어갑니다.
      stopListeners();
      unsubs.push(onSnapshot(doc(db, 'households', hid), (s) => {
        if (s.exists() && (s.data().members || []).length > 1) { stopListeners(); boot(); }
      }));
    }
  } catch (e) { fail(e, '코드를 만들지 못했어요.'); }
}

async function joinWithCode(raw) {
  const code = String(raw || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (code.length !== 6) return toast('코드 6자리를 확인해 주세요.');
  try {
    const inv = await getDoc(doc(db, 'invites', code));
    if (!inv.exists()) return toast('코드를 찾지 못했어요. 다시 확인해 주세요.');
    const { householdId, expiresAt } = inv.data();
    if (expiresAt.toDate() < new Date()) return toast('기한이 지난 코드예요. 새 코드를 받아 주세요.');
    if (householdId === S.hid) return toast('내가 만든 코드예요. 배우자 휴대폰에서 입력해 주세요.');
    const oldHid = S.hid;
    await updateDoc(doc(db, 'households', householdId), {
      members: arrayUnion(S.user.uid),
      [`names.${S.user.uid}`]: S.profile.name,
      [`roles.${S.user.uid}`]: S.profile.role,
      [`stages.${S.user.uid}`]: 1,
      joinCode: code,
    });
    await updateDoc(doc(db, 'users', S.user.uid), { householdId });
    if (oldHid) {
      // 혼자 쓰던 가정의 내 약속은 새 가정에서 다시 만들어집니다.
      await clearMyHouseholdData(oldHid);
      await deleteDoc(doc(db, 'households', oldHid)).catch(() => {});
    }
    toast('연결되었어요.');
    stopListeners(); S.hid = null; S.tab = 'home'; S.sub = null;
    await boot();
  } catch (e) { fail(e, '연결하지 못했어요. 코드가 맞는지, 이미 두 사람이 연결된 가정은 아닌지 확인해 주세요.'); }
}

async function clearMyHouseholdData(hid) {
  const batch = writeBatch(db);
  const ps = await getDocs(query(collection(db, 'households', hid, 'promises'), where('owner', '==', S.user.uid)));
  ps.forEach((d) => batch.delete(d.ref));
  await batch.commit();
}

async function soloStart() {
  try { await ensureHousehold(); await boot(); } catch (e) { fail(e); }
}

async function leaveHousehold() {
  try {
    const hid = S.hid;
    await clearMyHouseholdData(hid);
    const others = (S.hh.members || []).filter((m) => m !== S.user.uid);
    if (others.length === 0) await deleteDoc(doc(db, 'households', hid));
    else {
      const names = { ...S.hh.names }; delete names[S.user.uid];
      const roles = { ...S.hh.roles }; delete roles[S.user.uid];
      const stages = { ...S.hh.stages }; delete stages[S.user.uid];
      await updateDoc(doc(db, 'households', hid), { members: others, names, roles, stages });
    }
    await updateDoc(doc(db, 'users', S.user.uid), { householdId: null });
    stopListeners(); S.hid = null; S.hh = null; S.partner = null; S.profile.householdId = null;
    toast('연결을 해제했어요.');
    renderConnect();
  } catch (e) { fail(e, '연결을 해제하지 못했어요.'); }
}

// ---------- 실시간 구독 ----------
function listen() {
  const hid = S.hid, uid = S.user.uid;
  unsubs.push(onSnapshot(doc(db, 'households', hid), (s) => {
    if (!s.exists()) return;
    S.hh = s.data();
    const p = (S.hh.members || []).find((m) => m !== uid);
    S.partner = p ? { uid: p, name: S.hh.names?.[p] || '배우자', role: S.hh.roles?.[p] } : null;
    render();
  }));
  unsubs.push(onSnapshot(collection(db, 'households', hid, 'promises'), (qs) => {
    S.promises = qs.docs.map((d) => ({ id: d.id, ...d.data() })).sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
    render();
  }));
  unsubs.push(onSnapshot(query(collection(db, 'households', hid, 'days'), where('date', '==', todayStr())), (qs) => {
    S.today = {}; qs.forEach((d) => { const v = d.data(); S.today[v.uid] = v.done || {}; });
    render();
  }));
  unsubs.push(onSnapshot(query(collection(db, 'households', hid, 'thanks'), orderBy('createdAt', 'desc'), limit(30)), (qs) => {
    S.thanks = qs.docs.map((d) => ({ id: d.id, ...d.data() })); render();
  }));
  unsubs.push(onSnapshot(query(collection(db, 'households', hid, 'notes'), orderBy('createdAt', 'desc'), limit(50)), (qs) => {
    S.sharedNotes = qs.docs.map((d) => ({ id: d.id, shared: true, ...d.data() })); render();
  }));
  unsubs.push(onSnapshot(query(collection(db, 'users', uid, 'notes'), orderBy('createdAt', 'desc'), limit(100)), (qs) => {
    S.myNotesRaw = qs.docs.map((d) => ({ id: d.id, shared: false, ...d.data() })); refreshMyNotes();
  }));
  unsubs.push(onSnapshot(doc(db, 'households', hid, 'talks', mondayStr()), (s) => {
    S.talkDone = s.exists() ? s.data() : null; render();
  }));
}

async function seedPromisesIfNeeded() {
  const mine = await getDocs(query(collection(db, 'households', S.hid, 'promises'), where('owner', '==', S.user.uid)));
  if (!mine.empty) return;
  const list = DEFAULT_PROMISES[S.profile.role] || DEFAULT_PROMISES.husband;
  const batch = writeBatch(db);
  list.forEach((p, i) => {
    batch.set(doc(collection(db, 'households', S.hid, 'promises')), {
      ...p, owner: S.user.uid, active: true, custom: false, order: i, updatedAt: serverTimestamp(),
    });
  });
  await batch.commit();
}

// ---------- 화면 그리기 ----------
function render() {
  if (!S.hh) return;
  // 배우자 쪽 변화로 화면이 다시 그려져도, 쓰던 글은 지워지지 않게
  const keep = {}; let focusId = document.activeElement?.id;
  view.querySelectorAll('input[id], textarea[id]').forEach((el) => {
    if (el.type === 'password') return;
    keep[el.id] = el.type === 'checkbox' ? el.checked : el.value;
  });
  draw();
  Object.entries(keep).forEach(([id, v]) => {
    const el = document.getElementById(id); if (!el) return;
    if (el.type === 'checkbox') el.checked = v; else if (v && !el.value) el.value = v;
  });
  if (focusId) document.getElementById(focusId)?.focus?.({ preventScroll: true });
}

function draw() {
  setTabs(true);
  if (S.sub?.type === 'talk') return renderTalk();
  if (S.sub?.type === 'topic') return renderTopic(S.sub.id);
  if (S.sub?.type === 'foundation') return renderFoundation(S.sub.id);
  ({ home: renderHome, promises: renderPromises, check: renderCheck, guide: renderGuide, me: renderMe }[S.tab] || renderHome)();
}

const visibleFor = (uid, stage) => S.promises.filter((p) => p.owner === uid && p.active && (p.stage || 1) <= stage);
const tick = '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2 6.5l2.5 2.5L10 3.5" fill="none" stroke="#fff" stroke-width="2"/></svg>';

function promiseRows(list, uid, editable) {
  const done = S.today[uid] || {};
  if (!list.length) return '<p class="fine">아직 약속이 없어요.</p>';
  return list.map((p) => {
    const on = !!done[p.id];
    const label = `${esc(p.title)}${p.amount ? ` <small>${esc(p.amount)}</small>` : ''}`;
    return editable
      ? `<button type="button" class="row ${on ? 'done' : ''}" data-action="toggle-day" data-id="${p.id}" aria-pressed="${on}"><span class="box">${on ? tick : ''}</span><span>${label}</span></button>`
      : `<div class="row ${on ? 'done' : ''}"><span class="box">${on ? tick : ''}</span><span>${label}</span></div>`;
  }).join('');
}

function header(kicker, title) {
  return `<header class="head"><div><span class="kicker">${esc(kicker)}</span><h1 class="title">${esc(title)}</h1></div>
    <span class="chip ${S.partner ? 'ok' : ''}"><i></i>${S.partner ? `${esc(S.profile.name)} · ${esc(S.partner.name)}` : '연결 전'}</span></header>`;
}

function renderHome() {
  const uid = S.user.uid;
  const d = new Date();
  const dateLabel = `${d.getMonth() + 1}월 ${d.getDate()}일 ${'일월화수목금토'[d.getDay()]}요일`;
  const mine = visibleFor(uid, myStage());
  const doneMine = mine.filter((p) => S.today[uid]?.[p.id]).length;
  const theirs = S.partner ? visibleFor(S.partner.uid, partnerStage()) : [];
  const doneTheirs = S.partner ? theirs.filter((p) => S.today[S.partner.uid]?.[p.id]).length : 0;
  const lastThanks = S.thanks.find((t) => t.to === uid);
  const dts = daysToSunday();
  const ref = DAILY_REFS[(d.getDate() + d.getMonth()) % DAILY_REFS.length];
  const focus = S.hh.focus?.period === periodKey() ? TOPICS.find((t) => t.id === S.hh.focus.topicId) : null;

  view.innerHTML = `
  <section class="page">
    ${header('세 겹 줄', dateLabel)}
    ${!S.partner ? `<div class="card warm"><strong>아직 배우자와 연결되지 않았어요.</strong><p class="fine">메모·설정에서 초대 코드를 만들어 보내 주세요.</p><button type="button" class="btn small" data-action="go" data-tab="me">연결하러 가기</button></div>` : ''}
    <div class="card">
      <div class="card-head"><h2 class="h2">오늘의 약속</h2><button type="button" class="link" data-action="go" data-tab="promises">편집</button></div>
      <div class="cols ${S.partner ? 'two' : ''}">
        <div><span class="who me">나 · ${doneMine}/${mine.length}</span>${promiseRows(mine, uid, true)}</div>
        ${S.partner ? `<div class="divider"><span class="who partner">${esc(S.partner.name)} · ${doneTheirs}/${theirs.length}</span>${promiseRows(theirs, S.partner.uid, false)}</div>` : ''}
      </div>
    </div>
    ${S.partner ? `
    <div class="card warm">
      ${lastThanks ? `<span class="who partner">${esc(S.partner.name)}이(가) 보낸 감사</span><p class="quote">${esc(lastThanks.text)}</p>` : `<span class="who partner">감사</span><p class="fine">무엇이, 왜 고마운지 구체적으로 말해 보세요.</p>`}
      <form id="thanks-form" class="inline">
        <label for="thanks-text" class="sr">감사 보내기</label>
        <input id="thanks-text" name="text" maxlength="300" placeholder="오늘 ~해 줘서, ~할 수 있었어. 고마워." required>
        <button class="btn small dark" type="submit">보내기</button>
      </form>
    </div>` : ''}
    <div class="grid2">
      <button type="button" class="card tile" data-action="talk-start">
        <span class="fine">주간 대화</span>
        <strong class="big-num">${S.talkDone ? '완료' : dts === 0 ? '오늘' : `D-${dts}`}</strong>
        <span class="fine">${S.talkDone ? '이번 주 대화를 마쳤어요' : '일요일 · 눌러서 시작'}</span>
      </button>
      <button type="button" class="card tile" data-action="go" data-tab="${focus ? 'guide' : 'check'}">
        <span class="fine">이번 달 주제</span>
        <strong>${focus ? `${esc(focus.id)} ${esc(focus.title)}` : '점검 후 정하기'}</strong>
      </button>
    </div>
    <div class="card">
      <span class="fine">오늘의 말씀</span>
      <p class="quote">${esc(ref)}</p>
      <p class="fine">말씀 본문(개역한글·영어·원어)은 다음 업데이트에서 함께 보여 드려요.</p>
    </div>
  </section>`;

  $('#thanks-form')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const text = ev.target.text.value.trim(); if (!text) return;
    try {
      await addDoc(collection(db, 'households', S.hid, 'thanks'), { from: uid, to: S.partner.uid, text, createdAt: serverTimestamp() });
      ev.target.reset(); toast('감사를 보냈어요.');
    } catch (e) { fail(e); }
  });
}

async function toggleDay(pid) {
  const uid = S.user.uid; const date = todayStr();
  const cur = !!S.today[uid]?.[pid];
  try { await setDoc(doc(db, 'households', S.hid, 'days', `${date}_${uid}`), { uid, date, done: { [pid]: !cur } }, { merge: true }); }
  catch (e) { fail(e); }
}

// ---------- 약속 ----------
function renderPromises() {
  const uid = S.user.uid;
  const showMine = S.promiseView === 'mine' || !S.partner;
  const owner = showMine ? uid : S.partner.uid;
  const list = S.promises.filter((p) => p.owner === owner);
  const stage = showMine ? myStage() : partnerStage();

  const card = (p) => {
    const editing = S.editing === p.id && showMine;
    const base = !p.custom && (DEFAULT_PROMISES[S.profile.role] || []).find((b) => b.baseId === p.baseId);
    if (editing) {
      return `<form class="card stack edit" data-id="${p.id}">
        <span class="fine">${esc(p.area)} · ${p.stage}단계</span>
        <label for="t-${p.id}">약속</label><input id="t-${p.id}" name="title" value="${esc(p.title)}" maxlength="60" required>
        <div class="grid2"><div><label for="w-${p.id}">언제</label><input id="w-${p.id}" name="when" value="${esc(p.when)}" maxlength="30"></div>
        <div><label for="a-${p.id}">얼마나</label><input id="a-${p.id}" name="amount" value="${esc(p.amount)}" maxlength="30"></div></div>
        ${base ? `<p class="fine">초안: ${esc(base.title)} · ${esc(base.when)} · ${esc(base.amount)}</p>` : ''}
        <div class="btns"><button class="btn primary small" type="submit">저장</button>
        <button type="button" class="btn small" data-action="edit-cancel">취소</button>
        ${base ? `<button type="button" class="btn small" data-action="reset-promise" data-id="${p.id}">초안으로 되돌리기</button>` : ''}
        ${p.custom ? `<button type="button" class="btn small danger" data-action="delete-promise" data-id="${p.id}">삭제</button>` : ''}</div>
      </form>`;
    }
    const off = (p.stage || 1) > stage;
    return `<article class="card promise ${!p.active || off ? 'dim' : ''}">
      <div class="card-head"><span class="fine">${esc(p.area)} · ${p.stage}단계${off ? ' (아직 시작 전)' : ''}</span>
      ${showMine ? `<button type="button" class="link" data-action="toggle-active" data-id="${p.id}">${p.active ? '쉬기' : '다시 켜기'}</button>` : ''}</div>
      <strong class="ptitle">${esc(p.title)}</strong>
      <div class="chips">${p.when ? `<span class="adj">${esc(p.when)}</span>` : ''}${p.amount ? `<span class="adj">${esc(p.amount)}</span>` : ''}</div>
      ${showMine ? `<button type="button" class="link" data-action="edit-promise" data-id="${p.id}">시간·횟수 고치기</button>` : ''}
    </article>`;
  };

  view.innerHTML = `
  <section class="page">
    ${header('약속표', showMine ? '나의 약속' : `${S.partner.name}의 약속`)}
    ${S.partner ? `<div class="seg-tabs" role="tablist"><button type="button" role="tab" aria-selected="${showMine}" data-action="pview" data-v="mine">나</button><button type="button" role="tab" aria-selected="${!showMine}" data-action="pview" data-v="partner">${esc(S.partner.name)}</button></div>` : ''}
    ${showMine ? `<div class="card"><span class="fine">지금 단계</span><div class="stage-row">${STAGES.map((s) => `<button type="button" class="stage ${s.n === stage ? 'on' : ''}" data-action="set-stage" data-n="${s.n}"><b>${s.n}단계</b><small>${esc(s.name)}</small></button>`).join('')}</div><p class="fine">${esc(STAGES[stage - 1].note)}. 다음 단계로 넘어가는 때는 주간 대화에서 둘이 함께 정해요.</p></div>` : ''}
    ${list.map(card).join('')}
    ${showMine ? `<form id="add-p" class="card stack"><h2 class="h2">나만의 약속 추가</h2>
      <label for="np-title">약속</label><input id="np-title" name="title" maxlength="60" required placeholder="예: 퇴근 후 첫 30분은 아이 전담">
      <div class="grid2"><div><label for="np-when">언제</label><input id="np-when" name="when" maxlength="30" placeholder="예: 평일"></div>
      <div><label for="np-amount">얼마나</label><input id="np-amount" name="amount" maxlength="30" placeholder="예: 30분"></div></div>
      <button class="btn primary" type="submit">추가하기</button></form>` : ''}
  </section>`;

  view.querySelectorAll('form.edit').forEach((f) => f.addEventListener('submit', async (ev) => {
    ev.preventDefault(); const fd = new FormData(f);
    try {
      await updateDoc(doc(db, 'households', S.hid, 'promises', f.dataset.id), {
        title: fd.get('title').trim(), when: fd.get('when').trim(), amount: fd.get('amount').trim(), updatedAt: serverTimestamp(),
      });
      S.editing = null; toast('저장했어요.');
    } catch (e) { fail(e); }
  }));
  $('#add-p')?.addEventListener('submit', async (ev) => {
    ev.preventDefault(); const fd = new FormData(ev.target);
    try {
      await addDoc(collection(db, 'households', S.hid, 'promises'), {
        owner: uid, baseId: null, custom: true, area: '나의 약속', title: fd.get('title').trim(),
        when: fd.get('when').trim(), amount: fd.get('amount').trim(), stage: myStage(), active: true,
        order: 100 + S.promises.length, updatedAt: serverTimestamp(),
      });
      ev.target.reset(); toast('약속을 추가했어요.');
    } catch (e) { fail(e); }
  });
}

// ---------- 점검 ----------
const ALL_Q = [...CHECK_A, ...CHECK_B];
async function loadCheck() {
  const p = periodKey(); const base = ['households', S.hid, 'assessments', p, 'answers'];
  const mine = await getDoc(doc(db, ...base, S.user.uid)).catch(() => null);
  S.check.mine = mine?.exists() ? mine.data() : null;
  S.check.draft = { ...(S.check.mine?.scores || {}) };
  S.check.partner = null;
  if (S.partner && S.check.mine?.completed) {
    const ps = await getDoc(doc(db, ...base, S.partner.uid)).catch(() => null);
    S.check.partner = ps?.exists() ? ps.data() : null;
  }
  S.check.loaded = p;
  render();
}

function renderCheck() {
  if (S.check.loaded !== periodKey()) { view.innerHTML = '<section class="page"><p class="fine">불러오는 중…</p></section>'; loadCheck(); return; }
  const done = !!S.check.mine?.completed;
  const p = periodKey();
  const qBlock = (q) => {
    const v = S.check.draft[q.id];
    return `<div class="qrow"><p><span class="fine">${esc(q.area)}</span> ${esc(q.q)}</p>
      <div class="scores" role="radiogroup" aria-label="${esc(q.q)}">${SCORE_LABELS.map((l, i) =>
        `<button type="button" role="radio" aria-checked="${v === i + 1}" class="sc ${v === i + 1 ? 'on' : ''}" data-action="score" data-q="${q.id}" data-v="${i + 1}" ${done ? 'disabled' : ''}>${i + 1}<small>${l}</small></button>`).join('')}</div></div>`;
  };
  let result = '';
  if (done && S.check.partner?.completed) {
    const a = S.check.mine.scores, b = S.check.partner.scores;
    const recs = new Set();
    const rows = ALL_Q.map((q) => {
      const x = a[q.id], y = b[q.id];
      let tag = '';
      if (Math.abs(x - y) >= 2) tag = '<span class="tag diff">서로 다르게 봄</span>';
      else if (x <= 2 && y <= 2) { tag = '<span class="tag low">함께 아픈 곳</span>'; (q.topics || []).forEach((t) => recs.add(t)); }
      else if (x >= 4 && y >= 4) tag = '<span class="tag good">우리의 힘</span>';
      return `<tr><td>${esc(q.q)}</td><td class="num">${x}</td><td class="num">${y}</td><td>${tag}</td></tr>`;
    }).join('');
    result = `<div class="card"><h2 class="h2">함께 보는 결과</h2>
      <div class="tbl"><table><thead><tr><th>문항</th><th>나</th><th>${esc(S.partner.name)}</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      <p class="fine">2점 이상 다른 문항은 해결보다 먼저 "당신은 왜 그렇게 느꼈어?"를 물어보세요.</p>
      ${recs.size ? `<h3 class="h3">이번 달 추천 주제</h3>${[...recs].map((id) => { const t = TOPICS.find((x) => x.id === id); return t ? `<button type="button" class="btn small" data-action="open-topic" data-id="${t.id}">${esc(t.id)} ${esc(t.title)}</button>` : ''; }).join(' ')}` : ''}
    </div>`;
  } else if (done) {
    result = `<div class="card warm"><strong>결과는 둘 다 마치면 열려요.</strong><p class="fine">${S.partner ? `${esc(S.partner.name)}님이 아직 마치지 않았어요.` : '배우자와 연결하면 함께 볼 수 있어요.'}</p><button type="button" class="btn small" data-action="reload-check">다시 확인</button></div>`;
  }
  const answered = ALL_Q.filter((q) => S.check.draft[q.id]).length;
  view.innerHTML = `
  <section class="page">
    ${header(`${p.slice(0, 4)}년 ${Number(p.slice(5))}월 점검`, '함께 점검')}
    <p class="lead">각자 따로 고르고, 둘 다 마치면 결과가 함께 열려요. 점수는 성적표가 아니라 대화의 출발점입니다.</p>
    ${result}
    <div class="card"><h2 class="h2">A. 나의 상태</h2>${CHECK_A.map(qBlock).join('')}</div>
    <div class="card"><h2 class="h2">B. 우리 부부의 상태</h2>${CHECK_B.map(qBlock).join('')}</div>
    ${done ? '<p class="fine center">이번 달 점검을 마쳤어요. 다음 달에 다시 해 보세요.</p>' : `
    <div class="btns sticky"><span class="fine">${answered}/${ALL_Q.length}</span>
      <button type="button" class="btn" data-action="save-check">임시 저장</button>
      <button type="button" class="btn primary" data-action="submit-check" ${answered < ALL_Q.length ? 'disabled' : ''}>마치기</button></div>`}
  </section>`;
}

async function saveCheck(complete) {
  try {
    await setDoc(doc(db, 'households', S.hid, 'assessments', periodKey(), 'answers', S.user.uid), {
      uid: S.user.uid, scores: S.check.draft, completed: !!complete, updatedAt: serverTimestamp(),
    });
    toast(complete ? '점검을 마쳤어요.' : '저장했어요.');
    S.check.loaded = null; render();
  } catch (e) { fail(e); }
}

// ---------- 지침서 ----------
function renderGuide() {
  view.innerHTML = `
  <section class="page">
    ${header('결혼 지침서', '함께 자라가는 가정')}
    <h2 class="h2">결혼의 기초</h2>
    ${FOUNDATIONS.map((f, i) => `<button type="button" class="card list-item" data-action="open-foundation" data-id="${f.id}"><span class="fine">기초 ${i + 1}</span><strong>${esc(f.title)}</strong></button>`).join('')}
    ${CATEGORIES.map((c, ci) => `<h2 class="h2">${ci + 1}. ${esc(c)}</h2>${TOPICS.filter((t) => t.cat === c).map((t) =>
      `<button type="button" class="card list-item" data-action="open-topic" data-id="${t.id}"><span class="fine">${esc(t.id)}</span><strong>${esc(t.title)}</strong><span class="fine">“${esc(t.voice)}”</span></button>`).join('')}`).join('')}
    <div class="card"><h2 class="h2">도움이 필요할 때</h2><p class="fine">폭언, 폭력, 깊은 우울처럼 안전이 걸린 상황은 앱이 다룰 수 없어요. 먼저 도움을 받으세요.</p>
      ${HELP_LINES.map((h) => `<div class="help"><strong>${esc(h.num)}</strong><span>${esc(h.name)} · ${esc(h.when)}</span></div>`).join('')}</div>
  </section>`;
}

function backBar(title) { return `<header class="back"><button type="button" class="link" data-action="back">← 뒤로</button><span class="fine">${esc(title)}</span></header>`; }

function renderFoundation(id) {
  const f = FOUNDATIONS.find((x) => x.id === id);
  view.innerHTML = `<section class="page">${backBar('결혼의 기초')}
    <h1 class="title">${esc(f.title)}</h1>
    ${f.body.map((b) => `<p class="body">${esc(b)}</p>`).join('')}
    <div class="card word"><span class="fine">함께 읽을 말씀</span><p>${f.refs.map(esc).join(' · ')}</p></div>
    ${noteForm(`기초: ${f.title}`)}
  </section>`;
  bindNoteForm();
}

function renderTopic(id) {
  const t = TOPICS.find((x) => x.id === id);
  const isFocus = S.hh.focus?.period === periodKey() && S.hh.focus?.topicId === id;
  view.innerHTML = `<section class="page">${backBar(`${t.cat} · ${t.id}`)}
    <h1 class="title">${esc(t.title)}</h1>
    <div class="card voice"><span class="fine">아내의 목소리</span><p class="quote">“${esc(t.voice)}”</p></div>
    <h2 class="h2">이럴 때</h2>
    ${t.situations.map((s) => `<div class="card sit"><strong>${esc(s.moment)}</strong>
      <div class="sit-row"><span class="who me">남편</span><span>${esc(s.husband)}</span></div>
      <div class="sit-row"><span class="who partner">아내</span><span>${esc(s.wife)}</span></div></div>`).join('')}
    <div class="card word"><span class="fine">성경 속 장면 · ${esc(t.scene.ref)}</span><strong>${esc(t.scene.title)}</strong><p>${esc(t.scene.text)}</p><span class="fine">말씀: ${t.refs.map(esc).join(' · ')}</span></div>
    <div class="card"><h2 class="h2">대화 질문</h2><ul>${t.questions.map((q) => `<li>${esc(q)}</li>`).join('')}</ul></div>
    <button type="button" class="btn ${isFocus ? '' : 'primary'}" data-action="set-focus" data-id="${t.id}" ${isFocus ? 'disabled' : ''}>${isFocus ? '이번 달 우리 주제예요' : '이번 달 우리 주제로 정하기'}</button>
    ${noteForm(`주제 ${t.id}`)}
  </section>`;
  bindNoteForm();
}

// ---------- 메모 ----------
function noteForm(context = '') {
  return `<form id="note-form" class="card stack" data-context="${esc(context)}">
    <label for="note-text" class="h2">메모 남기기</label>
    <textarea id="note-text" name="text" rows="3" maxlength="2000" required placeholder="떠오른 생각, 기도 제목, 경험을 적어 보세요."></textarea>
    <label class="switch"><input type="checkbox" name="share" ${S.partner ? '' : 'disabled'}> 배우자와 나누기 <span class="fine">(끄면 잠가서 나만 봐요)</span></label>
    <button class="btn primary" type="submit">저장</button></form>`;
}
function bindNoteForm() {
  $('#note-form')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = ev.target; const text = f.text.value.trim(); if (!text) return;
    const context = f.dataset.context || '';
    const shared = !!(f.share.checked && S.partner);
    if (!shared && !S.noteKey) {
      // 잠금이 아직 없거나 이 기기에서 열리지 않음 → 메모·설정에서 비밀번호부터
      S.pendingNote = { text, context }; S.tab = 'me'; S.sub = null; window.scrollTo(0, 0); render();
      return toast(S.profile.noteLock ? '메모 비밀번호를 넣어 주세요.' : '먼저 메모 비밀번호를 정해 주세요.');
    }
    try {
      if (shared) await addDoc(collection(db, 'households', S.hid, 'notes'), { author: S.user.uid, text, context, createdAt: serverTimestamp() });
      else await addDoc(collection(db, 'users', S.user.uid, 'notes'), { author: S.user.uid, ...(await seal(S.noteKey, { text, context })), createdAt: serverTimestamp() });
      f.reset(); toast(shared ? '배우자와 나눴어요.' : '잠가서 저장했어요.');
    } catch (e) { fail(e); }
  });
}

function renderMe() {
  const notes = [...S.myNotes, ...S.sharedNotes].sort((a, b) => (b.createdAt?.seconds || 0) - (a.createdAt?.seconds || 0));
  const when = (n) => { const d = n.createdAt?.toDate?.(); return d ? `${d.getMonth() + 1}/${d.getDate()}` : ''; };
  const noteCard = (n) => {
    const mine = n.author === S.user.uid;
    const who = mine ? '나' : (S.partner?.name || '배우자');
    return `<article class="card note ${n.shared ? 'shared' : ''}"><div class="card-head"><span class="fine">${esc(who)} · ${n.shared ? '나눈 메모' : '🔒 나만 보기'}${n.context ? ` · ${esc(n.context)}` : ''} · ${when(n)}</span>
      ${mine ? `<button type="button" class="link" data-action="delete-note" data-id="${n.id}" data-shared="${n.shared}">삭제</button>` : ''}</div>${n.locked ? '<p class="fine">잠겨 있어요</p>' : `<p>${esc(n.text)}</p>`}</article>`;
  };
  view.innerHTML = `
  <section class="page">
    ${header('메모·설정', '나의 공간')}
    ${lockCard()}
    ${S.confirmForgot ? `<div class="card warm stack"><strong>잠긴 메모를 모두 지우고 새로 시작할까요?</strong><p class="fine">비밀번호 없이는 누구도 열 수 없어서, 잠긴 메모는 지울 수밖에 없어요. 나눈 메모는 그대로 남아요.</p><div class="btns"><button type="button" class="btn danger small" data-action="forgot-yes">지우고 새로 시작</button><button type="button" class="btn small" data-action="forgot-no">취소</button></div></div>` : ''}
    ${noteForm('')}
    <h2 class="h2">메모</h2>
    ${notes.length ? notes.map(noteCard).join('') : '<p class="fine">아직 메모가 없어요.</p>'}

    <h2 class="h2">연결</h2>
    <div class="card stack">
      ${S.partner ? `<p><strong>${esc(S.partner.name)}</strong>님(${esc(roleName(S.partner.role))})과 연결되어 있어요.</p>
        <p class="fine">약속 체크와 감사는 서로 보여요. 점검 점수는 둘 다 마쳐야 열리고, 메모는 나눈 것만 보여요.</p>
        <button type="button" class="btn small" data-action="leave">연결 해제</button>`
      : `${connectBlock(S.inviteCode || null)}`}
    </div>

    <h2 class="h2">개인정보와 보안</h2>
    ${privacyBlock(true)}

    <h2 class="h2">설정</h2>
    <form id="profile-form" class="card stack">
      <label for="pf-name">이름</label><input id="pf-name" name="name" value="${esc(S.profile.name)}" maxlength="20" required>
      <p class="fine">역할: ${esc(roleName(S.profile.role))} · ${esc(S.user.email || '')}</p>
      <button class="btn small" type="submit">이름 저장</button>
    </form>
    ${S.noteKey ? '<div class="card stack"><p class="fine">‘나만 보기’ 메모가 이 휴대폰에서 열려 있어요. 다른 사람과 함께 쓰는 기기라면 잠가 두세요.</p><button type="button" class="btn small" data-action="lock-device">이 휴대폰에서 메모 잠그기</button></div>' : ''}
    <div class="card"><h2 class="h2">도움이 필요할 때</h2>${HELP_LINES.map((h) => `<div class="help"><strong>${esc(h.num)}</strong><span>${esc(h.name)} · ${esc(h.when)}</span></div>`).join('')}</div>
    <div class="btns"><button type="button" class="btn" data-action="logout">로그아웃</button>
      ${S.confirmDelete ? `<button type="button" class="btn danger" data-action="delete-account-yes">정말 삭제하기</button><button type="button" class="btn" data-action="delete-account-no">취소</button>`
      : `<button type="button" class="btn ghost danger-text" data-action="delete-account">계정 삭제</button>`}</div>
    ${S.confirmDelete ? '<p class="fine">내 약속, 메모, 감사, 점검 기록과 계정이 지워지고 연결도 해제돼요. 되돌릴 수 없어요.</p>' : ''}
  </section>`;
  bindNoteForm();
  bindLockForms();
  if (S.pendingNote && $('#note-text') && !$('#note-text').value) $('#note-text').value = S.pendingNote.text;
  $('#profile-form')?.addEventListener('submit', async (ev) => {
    ev.preventDefault(); const name = ev.target.name.value.trim(); if (!name) return;
    try {
      await updateDoc(doc(db, 'users', S.user.uid), { name });
      await updateDoc(doc(db, 'households', S.hid), { [`names.${S.user.uid}`]: name });
      S.profile.name = name; toast('저장했어요.');
    } catch (e) { fail(e); }
  });
}

async function deleteAccount() {
  const uid = S.user.uid;
  try {
    const batch = writeBatch(db);
    (await getDocs(collection(db, 'users', uid, 'notes'))).forEach((d) => batch.delete(d.ref));
    if (S.hid) {
      const col = (n) => collection(db, 'households', S.hid, n);
      (await getDocs(query(col('notes'), where('author', '==', uid)))).forEach((d) => batch.delete(d.ref));
      (await getDocs(query(col('thanks'), where('from', '==', uid)))).forEach((d) => batch.delete(d.ref));
      (await getDocs(query(col('days'), where('uid', '==', uid)))).forEach((d) => batch.delete(d.ref));
      // 월간 점검: 2026년 10월(앱 시작)부터 이번 달까지
      for (let d = new Date(2026, 9, 1); d <= new Date(); d.setMonth(d.getMonth() + 1)) {
        const per = `${d.getFullYear()}-${pad(d.getMonth() + 1)}`;
        batch.delete(doc(db, 'households', S.hid, 'assessments', per, 'answers', uid));
      }
    }
    await batch.commit();
    if (S.hid) await leaveHousehold();
    await deleteDoc(doc(db, 'users', uid));
    await keyDel(uid);
    try { await deleteUser(auth.currentUser); }
    catch (e) {
      if (e.code === 'auth/requires-recent-login') { await reauthenticateWithPopup(auth.currentUser, new GoogleAuthProvider()); await deleteUser(auth.currentUser); }
      else throw e;
    }
    toast('계정을 삭제했어요.');
  } catch (e) { fail(e, '삭제하지 못했어요. 다시 로그인한 뒤 시도해 주세요.'); }
}

// ---------- 주간 대화 ----------
async function renderTalk() {
  const step = S.talkStep; const st = TALK_STEPS[step];
  const monday = mondayStr();
  let extra = '';
  if (step === 0) {
    const wk = S.thanks.filter((t) => (t.createdAt?.toDate?.() || new Date()) >= new Date(`${monday}T00:00:00`));
    extra = wk.length ? `<div class="card"><span class="fine">이번 주 주고받은 감사</span>${wk.map((t) => `<p class="quote small">${esc(t.from === S.user.uid ? '나' : S.partner?.name)}: ${esc(t.text)}</p>`).join('')}</div>` : '<p class="fine">이번 주 감사 기록이 없어요. 지금 말로 나눠 보세요.</p>';
  }
  if (step === 1) {
    extra = '<div class="card" id="week-summary"><p class="fine">이번 주 기록을 모으는 중…</p></div>';
  }
  if (step === 3) {
    extra = `<label for="next-focus" class="h2">다음 주 우리가 집중할 것</label><input id="next-focus" maxlength="80" value="${esc(S.talkNext || '')}" placeholder="예: 저녁 15분 휴대폰 내려놓기">`;
  }
  view.innerHTML = `<section class="page talk">${backBar('주간 대화')}
    <div class="steps">${TALK_STEPS.map((s, i) => `<span class="${i === step ? 'on' : i < step ? 'past' : ''}"></span>`).join('')}</div>
    <span class="kicker">${step + 1} / ${TALK_STEPS.length}</span>
    <h1 class="title">${esc(st.title)}</h1>
    <p class="lead">${esc(st.guide)}</p>
    ${extra}
    <div class="btns">${step > 0 ? '<button type="button" class="btn" data-action="talk-prev">이전</button>' : ''}
      ${step < TALK_STEPS.length - 1 ? '<button type="button" class="btn primary" data-action="talk-next">다음</button>' : '<button type="button" class="btn primary" data-action="talk-finish">대화 마치기</button>'}</div>
  </section>`;
  if (step === 1) {
    const qs = await getDocs(query(collection(db, 'households', S.hid, 'days'), where('date', '>=', monday))).catch(() => null);
    const counts = {};
    qs?.forEach((d) => { const v = d.data(); Object.entries(v.done || {}).forEach(([pid, on]) => { if (on) counts[pid] = (counts[pid] || 0) + 1; }); });
    const line = (uid, stage) => visibleFor(uid, stage).map((p) => `<div class="sum-row"><span>${esc(p.title)}</span><b>${counts[p.id] || 0}일</b></div>`).join('');
    const box = $('#week-summary');
    if (box) box.innerHTML = `<span class="who me">나</span>${line(S.user.uid, myStage())}${S.partner ? `<span class="who partner">${esc(S.partner.name)}</span>${line(S.partner.uid, partnerStage())}` : ''}`;
  }
}

async function finishTalk() {
  try {
    await setDoc(doc(db, 'households', S.hid, 'talks', mondayStr()), { done: true, next: S.talkNext || '', by: S.user.uid, completedAt: serverTimestamp() });
    S.sub = null; S.talkStep = 0; toast('이번 주 대화를 마쳤어요.'); render();
  } catch (e) { fail(e); }
}

// ---------- 이벤트 ----------
document.addEventListener('click', async (ev) => {
  const tab = ev.target.closest('#tabs button');
  if (tab) { S.tab = tab.dataset.tab; S.sub = null; S.editing = null; S.confirmDelete = false; window.scrollTo(0, 0); return render(); }
  const el = ev.target.closest('[data-action]'); if (!el) return;
  const a = el.dataset.action, id = el.dataset.id;
  switch (a) {
    case 'login': return login();
    case 'make-invite': return makeInvite();
    case 'copy-code':
      try { await navigator.clipboard.writeText(el.dataset.code); toast('복사했어요.'); } catch { toast(`코드: ${el.dataset.code}`); }
      return;
    case 'solo-start': return soloStart();
    case 'go': S.tab = el.dataset.tab; S.sub = null; window.scrollTo(0, 0); return render();
    case 'back': S.sub = null; window.scrollTo(0, 0); return render();
    case 'toggle-day': return toggleDay(id);
    case 'pview': S.promiseView = el.dataset.v; return render();
    case 'edit-promise': S.editing = id; return render();
    case 'edit-cancel': S.editing = null; return render();
    case 'toggle-active': {
      const p = S.promises.find((x) => x.id === id);
      try { await updateDoc(doc(db, 'households', S.hid, 'promises', id), { active: !p.active }); } catch (e) { fail(e); }
      return;
    }
    case 'reset-promise': {
      const p = S.promises.find((x) => x.id === id);
      const b = (DEFAULT_PROMISES[S.profile.role] || []).find((x) => x.baseId === p.baseId);
      if (!b) return;
      try { await updateDoc(doc(db, 'households', S.hid, 'promises', id), { title: b.title, when: b.when, amount: b.amount }); S.editing = null; toast('초안으로 되돌렸어요.'); } catch (e) { fail(e); }
      return;
    }
    case 'delete-promise':
      try { await deleteDoc(doc(db, 'households', S.hid, 'promises', id)); S.editing = null; toast('삭제했어요.'); } catch (e) { fail(e); }
      return;
    case 'set-stage':
      try { await updateDoc(doc(db, 'households', S.hid), { [`stages.${S.user.uid}`]: Number(el.dataset.n) }); } catch (e) { fail(e); }
      return;
    case 'score': S.check.draft[el.dataset.q] = Number(el.dataset.v); return render();
    case 'save-check': return saveCheck(false);
    case 'submit-check': return saveCheck(true);
    case 'reload-check': S.check.loaded = null; return render();
    case 'open-topic': S.sub = { type: 'topic', id }; window.scrollTo(0, 0); return render();
    case 'open-foundation': S.sub = { type: 'foundation', id }; window.scrollTo(0, 0); return render();
    case 'set-focus':
      try { await updateDoc(doc(db, 'households', S.hid), { focus: { topicId: id, period: periodKey(), setBy: S.user.uid } }); toast('이번 달 주제로 정했어요.'); } catch (e) { fail(e); }
      return;
    case 'delete-note':
      try {
        const ref = el.dataset.shared === 'true' ? doc(db, 'households', S.hid, 'notes', id) : doc(db, 'users', S.user.uid, 'notes', id);
        await deleteDoc(ref); toast('삭제했어요.');
      } catch (e) { fail(e); }
      return;
    case 'talk-start': S.sub = { type: 'talk' }; S.talkStep = 0; S.talkNext = ''; window.scrollTo(0, 0); return render();
    case 'talk-prev': S.talkStep = Math.max(0, S.talkStep - 1); return render();
    case 'talk-next': { const nf = $('#next-focus'); if (nf) S.talkNext = nf.value.trim(); S.talkStep += 1; return render(); }
    case 'talk-finish': return finishTalk();
    case 'leave': return leaveHousehold();
    case 'logout': stopListeners(); await keyDel(S.user.uid); S.noteKey = null; return signOut(auth);
    case 'lock-device': await keyDel(S.user.uid); S.noteKey = null; return refreshMyNotes();
    case 'forgot-lock': S.confirmForgot = true; return render();
    case 'forgot-no': S.confirmForgot = false; return render();
    case 'forgot-yes': S.confirmForgot = false; try { await resetLock(); } catch (e) { fail(e); } return;
    case 'delete-account': S.confirmDelete = true; return render();
    case 'delete-account-no': S.confirmDelete = false; return render();
    case 'delete-account-yes': return deleteAccount();
  }
});

document.addEventListener('submit', (ev) => {
  if (ev.target.id === 'join') { ev.preventDefault(); joinWithCode(ev.target.code.value); }
});

if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
