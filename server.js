/*
 * 별까지 계단 — 사내 리더보드 서버 (Node 18+, 외부 의존성 없음)
 *
 * 실행:   node server.js
 * 설정:   config.json 또는 환경변수 (TENANT_ID, CLIENT_ID, PORT, BIND,
 *         DEV_FAKE_AUTH, TRUST_PROXY, HTTPS_PROXY)
 * 저장:   scores.json / .secret (같은 폴더, 자동 생성)
 *
 * Vercel 배포 시에는 api/ 폴더의 서버리스 함수가 같은 lib/api.js 로직을 쓴다.
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const api = require('./lib/api');
const store = require('./lib/store');

const CONFIG = api.CONFIG;
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY_BYTES = 64 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function sendJson(res, code, obj) {
  if (res.writableEnded || res.destroyed) return;
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(JSON.stringify(obj));
}

function clientIp(req) {
  if (CONFIG.trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.length) {
      const parts = xff.split(',');
      return parts[parts.length - 1].trim();
    }
  }
  return req.socket.remoteAddress || '?';
}

function readBody(req, res) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let rejected = false;
    const chunks = [];
    req.on('data', (c) => {
      if (rejected) return;
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        // 소켓을 즉시 끊으면 응답이 전달되지 않는다 — 응답을 보낸 뒤 정리
        rejected = true;
        sendJson(res, 413, { error: '요청 본문이 너무 큽니다' });
        req.resume();
        reject(new Error('SENT'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => { if (!rejected) resolve(Buffer.concat(chunks).toString('utf8')); });
    req.on('error', (e) => { if (!rejected) reject(e); });
  });
}

const server = http.createServer(async (req, res) => {
  let p;
  try {
    // 잘못된 요청 대상(절대형 URL 등)이 프로세스를 죽이지 않도록 파싱부터 보호
    p = new URL(req.url, 'http://localhost').pathname;
  } catch (e) {
    return sendJson(res, 400, { error: '잘못된 요청 경로' });
  }

  try {
    const isRead = req.method === 'GET' || req.method === 'HEAD';

    if (isRead && p === '/api/config') return sendJson(res, 200, api.configPayload());

    if (isRead && p === '/api/leaderboard') {
      const r = await api.handleLeaderboard(req.headers.authorization, clientIp(req));
      return sendJson(res, r.status, r.body);
    }

    if (req.method === 'POST' && p === '/api/score') {
      let raw;
      try { raw = await readBody(req, res); }
      catch (e) { return e.message === 'SENT' ? undefined : sendJson(res, 400, { error: '본문 읽기 실패' }); }
      let body;
      try { body = JSON.parse(raw); }
      catch (e) { return sendJson(res, 400, { error: '본문 파싱 실패' }); }
      const r = await api.handleScore(req.headers.authorization, clientIp(req), body);
      return sendJson(res, r.status, r.body);
    }

    // ---------- static files ----------
    if (isRead) {
      let rel;
      try { rel = decodeURIComponent(p === '/' ? '/index.html' : p); }
      catch (e) { return sendJson(res, 400, { error: '잘못된 경로' }); }
      if (rel.indexOf('\0') !== -1) return sendJson(res, 400, { error: '잘못된 경로' });

      const file = path.normalize(path.join(PUBLIC_DIR, rel));
      if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep)) {
        return sendJson(res, 404, { error: 'not found' });
      }
      let data, st;
      try {
        st = fs.statSync(file);
        if (!st.isFile()) throw new Error('not a file');
        data = fs.readFileSync(file);
      } catch (e) { return sendJson(res, 404, { error: 'not found' }); }

      const ext = path.extname(file).toLowerCase();
      const etag = '"' + st.size.toString(16) + '-' + st.mtimeMs.toString(16) + '"';
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304, { ETag: etag });
        return res.end();
      }
      res.writeHead(200, {
        'Content-Type': MIME[ext] || 'application/octet-stream',
        'Content-Length': data.length,
        'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600, must-revalidate',
        ETag: etag,
        'X-Content-Type-Options': 'nosniff',
      });
      return res.end(req.method === 'HEAD' ? undefined : data);
    }

    return sendJson(res, 405, { error: 'method not allowed' });
  } catch (e) {
    console.error('요청 처리 오류:', e);
    return sendJson(res, 500, { error: '서버 오류' });
  }
});

// 종료 시 미저장분 flush — 디바운스 창에 들어온 점수를 잃지 않도록
let shuttingDown = false;
function shutdown(sig) {
  if (shuttingDown) return;
  shuttingDown = true;
  store.flush();
  console.log(`\n${sig} — 저장 완료 후 종료합니다`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('exit', () => store.flush());

// 가짜 로그인 모드에서는 외부에 열지 않는다
const bindAddr = api.DEV_AUTH_ALLOWED ? '127.0.0.1' : CONFIG.bind;

server.listen(CONFIG.port, bindAddr, () => {
  console.log(`별까지 계단 서버 → http://${bindAddr === '0.0.0.0' ? 'localhost' : bindAddr}:${CONFIG.port}`);
  console.log('저장소:', store.MODE === 'kv' ? 'Vercel KV / Upstash'
    : store.MODE === 'file' ? 'scores.json' : '메모리(재시작 시 사라짐)');
  if (!CONFIG.tenantId || !CONFIG.clientId) {
    console.log('⚠ tenantId/clientId 미설정 — 실제 로그인 비활성화 (README 2번 참고)');
  }
  if (api.DEV_AUTH_ALLOWED) {
    console.log('⚠ 가짜 로그인 모드 — 127.0.0.1에만 바인딩됩니다. 실배포 금지!');
  }
  if (api.PROXY) console.log('프록시 사용:', api.PROXY.replace(/\/\/.*@/, '//***@'));
});
