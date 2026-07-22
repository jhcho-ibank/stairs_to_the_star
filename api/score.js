'use strict';
const api = require('../lib/api');

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) {
    const parts = xff.split(',');
    return parts[parts.length - 1].trim();
  }
  return req.socket.remoteAddress || '?';
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'method not allowed' });
    return;
  }
  try {
    // Vercel은 JSON 본문을 파싱해 주지만, 문자열로 오는 경우도 방어한다
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch (e) {
        res.status(400).json({ error: '본문 파싱 실패' });
        return;
      }
    }
    const r = await api.handleScore(req.headers.authorization, clientIp(req), body || {});
    res.status(r.status).json(r.body);
  } catch (e) {
    console.error('score 오류:', e);
    res.status(500).json({ error: '서버 오류' });
  }
};
