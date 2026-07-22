/*
 * 저장소 어댑터
 *
 *  1. Vercel KV / Upstash Redis  — 환경변수 KV_REST_API_URL + KV_REST_API_TOKEN
 *  2. 로컬 파일(scores.json)     — 쓰기 가능한 파일시스템일 때 (사내 서버·로컬)
 *  3. 메모리                     — 위 둘 다 없을 때. 서버리스에서는 인스턴스마다
 *                                  따로 놀고 재배포하면 사라지므로 임시 확인용.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const HASH_KEY = 'gyedan:players';
const SALT_KEY = 'gyedan:salt';

const ROOT = path.join(__dirname, '..');
const DATA_FILE = path.join(ROOT, 'scores.json');
const SECRET_FILE = path.join(ROOT, '.secret');

function canWriteFiles() {
  if (process.env.VERCEL) return false;
  try {
    fs.accessSync(ROOT, fs.constants.W_OK);
    return true;
  } catch (e) {
    return false;
  }
}

const MODE = KV_URL && KV_TOKEN ? 'kv' : (canWriteFiles() ? 'file' : 'memory');

// ---------- Upstash REST ----------
async function redis(cmd) {
  const res = await fetch(KV_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + KV_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await res.json();
  if (j.error) throw new Error('KV: ' + j.error);
  return j.result;
}

// ---------- 파일 / 메모리 ----------
let mem = { players: {} };
let fileLoaded = false;
let saveTimer = null;
let dirty = false;

function loadFile() {
  if (fileLoaded) return;
  fileLoaded = true;
  try {
    const d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (d && typeof d.players === 'object') mem.players = d.players;
  } catch (e) { /* 첫 실행 */ }
}

function writeFileNow() {
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  if (!dirty) return;
  try {
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify({ players: mem.players }));
    fs.renameSync(tmp, DATA_FILE);
    dirty = false;
  } catch (e) {
    console.error('저장 실패:', e.message);
  }
}

function scheduleFileSave() {
  dirty = true;
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; writeFileNow(); }, 250);
}

// ---------- 공개 API ----------

// 익명 ID용 소금. 바뀌면 순위표 식별자가 전부 달라지므로 한 번 만들면 계속 쓴다.
// 플레이어 한 명당 한 번씩 불리므로 반드시 캐시해야 한다 — 캐시가 없으면
// 순위표 한 번에 인원수만큼 네트워크 왕복이 생긴다.
let saltCache = null;
let saltInflight = null;

async function loadSalt() {
  if (MODE === 'kv') {
    let s = await redis(['GET', SALT_KEY]);
    if (!s) {
      s = crypto.randomBytes(32).toString('hex');
      // 여러 인스턴스가 동시에 만들어도 먼저 쓴 값이 이기도록 NX
      const ok = await redis(['SET', SALT_KEY, s, 'NX']);
      if (!ok) s = await redis(['GET', SALT_KEY]);
    }
    return s;
  }
  if (MODE === 'file') {
    try {
      return fs.readFileSync(SECRET_FILE, 'utf8').trim();
    } catch (e) {
      const s = crypto.randomBytes(32).toString('hex');
      try { fs.writeFileSync(SECRET_FILE, s, { mode: 0o600 }); } catch (e2) {}
      return s;
    }
  }
  return crypto.randomBytes(32).toString('hex');
}

function getSalt() {
  if (saltCache) return Promise.resolve(saltCache);
  if (saltInflight) return saltInflight;            // 동시 호출 합치기
  saltInflight = loadSalt().then((s) => {
    saltCache = s;
    saltInflight = null;
    return s;
  }).catch((e) => {
    saltInflight = null;
    throw e;
  });
  return saltInflight;
}

async function allPlayers() {
  if (MODE === 'kv') {
    const flat = await redis(['HGETALL', HASH_KEY]);
    const out = {};
    if (Array.isArray(flat)) {
      for (let i = 0; i + 1 < flat.length; i += 2) {
        try { out[flat[i]] = JSON.parse(flat[i + 1]); } catch (e) {}
      }
    } else if (flat && typeof flat === 'object') {
      for (const k of Object.keys(flat)) {
        try { out[k] = typeof flat[k] === 'string' ? JSON.parse(flat[k]) : flat[k]; } catch (e) {}
      }
    }
    return out;
  }
  if (MODE === 'file') loadFile();
  return mem.players;
}

async function getPlayer(oid) {
  if (MODE === 'kv') {
    const v = await redis(['HGET', HASH_KEY, oid]);
    if (!v) return null;
    try { return typeof v === 'string' ? JSON.parse(v) : v; } catch (e) { return null; }
  }
  if (MODE === 'file') loadFile();
  return mem.players[oid] || null;
}

async function putPlayer(oid, entry) {
  if (MODE === 'kv') {
    await redis(['HSET', HASH_KEY, oid, JSON.stringify(entry)]);
    return;
  }
  if (MODE === 'file') { loadFile(); mem.players[oid] = entry; scheduleFileSave(); return; }
  mem.players[oid] = entry;
}

// 서버리스에서는 인스턴스가 여러 개라 메모리 카운터가 정확하지 않다.
// KV가 있으면 INCR + 만료로 공유 카운터를 쓴다.
const memRl = new Map();
async function hitRate(key, limitPerMin) {
  if (MODE === 'kv') {
    const bucket = 'gyedan:rl:' + key + ':' + Math.floor(Date.now() / 60000);
    const n = await redis(['INCR', bucket]);
    if (n === 1) await redis(['EXPIRE', bucket, 120]);
    return n > limitPerMin;
  }
  const now = Date.now();
  let e = memRl.get(key);
  if (!e || now - e.start > 60000) { e = { start: now, n: 0 }; memRl.set(key, e); }
  e.n++;
  if (memRl.size > 5000) {
    for (const [k, v] of memRl) if (now - v.start > 60000) memRl.delete(k);
  }
  return e.n > limitPerMin;
}

module.exports = {
  MODE,
  getSalt,
  allPlayers,
  getPlayer,
  putPlayer,
  hitRate,
  flush: () => { if (MODE === 'file') writeFileNow(); },
};
