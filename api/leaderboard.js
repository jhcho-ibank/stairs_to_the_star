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
  try {
    const r = await api.handleLeaderboard(req.headers.authorization, clientIp(req));
    res.status(r.status).json(r.body);
  } catch (e) {
    console.error('leaderboard 오류:', e);
    res.status(500).json({ error: '서버 오류' });
  }
};
