/*
 * 게임 서버 로직 (사내 Node 서버와 Vercel 서버리스 함수가 함께 쓴다)
 *
 * 인증: 클라이언트가 PKCE 흐름으로 받은 Entra ID(Azure AD) ID 토큰을
 *       Authorization: Bearer 헤더로 보내면, 마이크로소프트 JWKS 공개키로
 *       서명·발급자·대상·테넌트·만료를 직접 검증한다.
 *       조회(leaderboard)도 인증이 필요하다 — 사내 이름·사진 명부가
 *       비인증 요청에 노출되지 않도록.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const store = require('./store');

// ---------- config ----------
let fileConfig = {};
try {
  fileConfig = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config.json'), 'utf8'));
} catch (e) { /* Vercel 등에서는 환경변수만 사용 */ }

function envFlag(name, fallback) {
  const v = process.env[name];
  if (v === undefined) return fallback === true;
  return ['1', 'true', 'yes', 'on'].includes(v.toLowerCase());
}

const CONFIG = {
  tenantId: process.env.TENANT_ID || fileConfig.tenantId || '',
  clientId: process.env.CLIENT_ID || fileConfig.clientId || '',
  // 회사 도메인(예: contoso.com). 지정하면 "어느 계정으로 로그인할지" 고르는
  // 단계를 건너뛰고 곧바로 회사 로그인 화면으로 간다.
  domainHint: process.env.DOMAIN_HINT || fileConfig.domainHint || '',
  port: parseInt(process.env.PORT || fileConfig.port || '8443', 10),
  bind: process.env.BIND || fileConfig.bind || '0.0.0.0',
  trustProxy: envFlag('TRUST_PROXY', fileConfig.trustProxy === true),
  devFakeAuth: envFlag('DEV_FAKE_AUTH', fileConfig.devFakeAuth === true),
};

// 실제 Entra 자격증명이 설정된 곳에서는 가짜 로그인을 아예 봉인한다.
// (설정 드리프트로 운영에 dev 모드가 남는 사고를 코드 레벨에서 차단)
const DEV_AUTH_ALLOWED = CONFIG.devFakeAuth && !CONFIG.tenantId && !CONFIG.clientId;

const MAX_SCORE = 100000;
const MAX_PHOTO_BYTES = 24 * 1024;
const MAX_PLAYERS_RETURNED = 100;
const RATE_WRITE = 30;
const RATE_READ = 120;

// ---------- 익명 ID ----------
async function publicId(oid) {
  const salt = await store.getSalt();
  return crypto.createHmac('sha256', salt).update(String(oid)).digest('hex').slice(0, 16);
}

// ---------- HTTPS 요청 (사내 프록시 지원) ----------
const PROXY = process.env.HTTPS_PROXY || process.env.https_proxy || fileConfig.httpsProxy || '';

function httpsGetJson(targetUrl) {
  if (!PROXY) {
    return fetch(targetUrl, { signal: AbortSignal.timeout(10000) }).then((r) => {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    });
  }
  // 프록시 CONNECT 터널 (사내망)
  const http = require('http');
  const https = require('https');
  return new Promise((resolve, reject) => {
    const u = new URL(targetUrl);
    const p = new URL(PROXY);
    const headers = {};
    if (p.username) {
      headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(
        decodeURIComponent(p.username) + ':' + decodeURIComponent(p.password)
      ).toString('base64');
    }
    const creq = http.request({
      host: p.hostname, port: p.port || 80, method: 'CONNECT',
      path: u.hostname + ':443', headers, timeout: 10000,
    });
    creq.on('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        reject(new Error('프록시 CONNECT 실패: HTTP ' + res.statusCode));
        return;
      }
      const req = https.get({
        host: u.hostname, path: u.pathname + u.search,
        socket, agent: false, servername: u.hostname, timeout: 10000,
      }, (r2) => {
        if (r2.statusCode !== 200) { r2.resume(); reject(new Error('HTTP ' + r2.statusCode)); return; }
        let body = '';
        r2.setEncoding('utf8');
        r2.on('data', (c) => { body += c; if (body.length > 1e6) r2.destroy(); });
        r2.on('end', () => {
          try { resolve(JSON.parse(body)); } catch (e) { reject(new Error('JSON 파싱 실패')); }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('요청 타임아웃')));
    });
    creq.on('error', reject);
    creq.on('timeout', () => creq.destroy(new Error('프록시 타임아웃')));
    creq.end();
  });
}

// ---------- Entra ID 토큰 검증 ----------
let jwksCache = { keys: null, fetchedAt: 0 };
let jwksLastTry = 0;
let jwksInflight = null;

function fetchJwks() {
  if (jwksInflight) return jwksInflight;
  jwksLastTry = Date.now();
  const url = `https://login.microsoftonline.com/${CONFIG.tenantId}/discovery/v2.0/keys`;
  jwksInflight = httpsGetJson(url).then((parsed) => {
    if (!Array.isArray(parsed.keys)) throw new Error('keys 없음');
    jwksCache = { keys: parsed.keys, fetchedAt: Date.now() };
    jwksInflight = null;
    return jwksCache.keys;
  }).catch((e) => { jwksInflight = null; throw e; });
  return jwksInflight;
}

async function getJwk(kid) {
  const cached = jwksCache.keys ? jwksCache.keys.find((k) => k.kid === kid) : null;
  const fresh = Date.now() - jwksCache.fetchedAt < 24 * 3600 * 1000;
  if (cached && fresh) return cached;
  if (Date.now() - jwksLastTry > 60 * 1000 || !jwksCache.keys) {
    try {
      await fetchJwks();
    } catch (e) {
      // 조회 실패해도 캐시에 키가 있으면 계속 — 일시 장애로 로그인이 끊기지 않도록
      if (!cached) throw new Error('JWKS 조회 실패: ' + e.message);
      return cached;
    }
    const found = jwksCache.keys.find((k) => k.kid === kid);
    if (found) return found;
  }
  return cached || null;
}

function b64urlToBuf(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('base64url 형식 오류');
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

async function verifyIdToken(token) {
  if (DEV_AUTH_ALLOWED && token.startsWith('dev:')) {
    // HTTP 헤더는 latin-1이므로 dev 토큰은 URL 인코딩되어 온다
    const p = JSON.parse(decodeURIComponent(token.slice(4)));
    if (!p.oid || !p.name) throw new Error('dev 토큰 형식 오류');
    return { oid: 'dev-' + String(p.oid).slice(0, 60), name: String(p.name).slice(0, 40) };
  }
  if (!CONFIG.tenantId || !CONFIG.clientId) throw new Error('서버에 인증 설정이 없습니다');

  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('JWT 형식 오류');
  const header = JSON.parse(b64urlToBuf(parts[0]).toString('utf8'));
  const payload = JSON.parse(b64urlToBuf(parts[1]).toString('utf8'));

  if (header.alg !== 'RS256') throw new Error('지원하지 않는 alg');
  if (typeof header.kid !== 'string') throw new Error('kid 없음');
  const now = Math.floor(Date.now() / 1000);
  const skew = 300;
  if (typeof payload.exp !== 'number' || now > payload.exp + skew) throw new Error('토큰 만료');
  if (typeof payload.nbf === 'number' && now < payload.nbf - skew) throw new Error('토큰 유효 이전');
  if (payload.iss !== `https://login.microsoftonline.com/${CONFIG.tenantId}/v2.0`) throw new Error('발급자 불일치');
  if (payload.aud !== CONFIG.clientId) throw new Error('대상 불일치');
  if (payload.tid !== CONFIG.tenantId) throw new Error('테넌트 불일치');
  if (!payload.oid) throw new Error('oid 없음');

  const jwk = await getJwk(header.kid);
  if (!jwk) throw new Error('서명 키를 찾을 수 없음');
  if (jwk.kty !== 'RSA') throw new Error('RSA 키가 아님');
  const ok = crypto.verify(
    'RSA-SHA256',
    Buffer.from(parts[0] + '.' + parts[1]),
    crypto.createPublicKey({ key: jwk, format: 'jwk' }),
    b64urlToBuf(parts[2])
  );
  if (!ok) throw new Error('서명 검증 실패');

  return {
    oid: payload.oid,
    name: String(payload.name || payload.preferred_username || '이름없음').slice(0, 40),
  };
}

async function authOrThrow(authHeader) {
  const auth = authHeader || '';
  if (!auth.startsWith('Bearer ')) { const e = new Error('로그인이 필요합니다'); e.code = 401; throw e; }
  try {
    return await verifyIdToken(auth.slice(7));
  } catch (err) {
    const e = new Error('인증 실패: ' + err.message); e.code = 401; throw e;
  }
}

// data:image/png;base64,... 형태만, 디코딩 크기까지 검사
const PHOTO_RE = /^data:image\/(png|jpeg|jpg|gif|webp);base64,([A-Za-z0-9+/]+={0,2})$/;
function validPhoto(s) {
  if (typeof s !== 'string' || s.length > MAX_PHOTO_BYTES * 2) return false;
  const m = PHOTO_RE.exec(s);
  if (!m) return false;
  const bytes = Math.floor(m[2].length * 3 / 4);
  return bytes > 0 && bytes <= MAX_PHOTO_BYTES;
}

// ---------- 핸들러 ----------
function configPayload() {
  return {
    clientId: CONFIG.clientId,
    tenantId: CONFIG.tenantId,
    domainHint: CONFIG.domainHint,
    devFakeAuth: DEV_AUTH_ALLOWED,
    // 배포 후 설정이 제대로 붙었는지 확인용.
    // storage가 'memory'면 점수가 저장되지 않는다(KV 연결 필요).
    storage: store.MODE,
  };
}

async function handleLeaderboard(authHeader, ip) {
  if (await store.hitRate(ip, RATE_READ)) return { status: 429, body: { error: '잠시 후 다시 시도하세요' } };
  let user;
  try { user = await authOrThrow(authHeader); }
  catch (e) { return { status: e.code || 401, body: { error: e.message } }; }

  const players = await store.allPlayers();
  const meId = await publicId(user.oid);
  const rows = [];
  for (const [oid, p] of Object.entries(players)) {
    rows.push({ id: await publicId(oid), name: p.name, photo: p.photo || null, best: p.best, updatedAt: p.updatedAt });
  }
  rows.sort((a, b) => b.best - a.best || a.updatedAt - b.updatedAt);

  const mine = players[user.oid];
  const rank = mine ? 1 + Object.values(players).filter((q) => q.best > mine.best).length : null;
  return {
    status: 200,
    body: {
      players: rows.slice(0, MAX_PLAYERS_RETURNED).map((x) => (x.id === meId ? Object.assign({ self: true }, x) : x)),
      me: { id: meId, best: mine ? mine.best : 0, rank },
    },
  };
}

async function handleScore(authHeader, ip, body) {
  if (await store.hitRate(ip, RATE_WRITE)) return { status: 429, body: { error: '잠시 후 다시 시도하세요' } };
  let user;
  try { user = await authOrThrow(authHeader); }
  catch (e) { return { status: e.code || 401, body: { error: e.message } }; }

  const score = body && body.score;
  if (!Number.isInteger(score) || score < 1 || score > MAX_SCORE) {
    return { status: 400, body: { error: '점수가 올바르지 않습니다' } };
  }

  const prev = await store.getPlayer(user.oid);
  const entry = prev || { name: user.name, photo: null, best: 0, updatedAt: 0 };
  entry.name = user.name;
  if (body.photo !== undefined && validPhoto(body.photo)) entry.photo = body.photo;
  if (score > entry.best) { entry.best = score; entry.updatedAt = Date.now(); }
  await store.putPlayer(user.oid, entry);

  const players = await store.allPlayers();
  const rank = 1 + Object.values(players).filter((q) => q.best > entry.best).length;
  return { status: 200, body: { id: await publicId(user.oid), best: entry.best, rank } };
}

module.exports = {
  CONFIG, DEV_AUTH_ALLOWED, PROXY,
  configPayload, handleLeaderboard, handleScore,
};
