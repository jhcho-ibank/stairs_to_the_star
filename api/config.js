'use strict';
const api = require('../lib/api');

module.exports = (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json(api.configPayload());
};
