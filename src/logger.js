
'use strict';

const { AsyncLocalStorage } = require('node:async_hooks');
const config = require('./config.js');

const context = new AsyncLocalStorage();
const settings = config.logging || {};

function sanitize(value, key = '', depth = 0) {
  if (depth > 12) return '[truncated]';

  if (/password|token|secret|authorization|api.?key|cookie|jwt|email/i.test(key)) {
    return '[REDACTED]';
  }

  if (typeof value === 'string') {
    return value
      .replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]')
      .replace(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/g, '[REDACTED EMAIL]')
      .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED JWT]')
      .slice(0, 4000);
  }

  if (Array.isArray(value)) {
    return value.slice(0, 50).map(v => sanitize(v, '', depth + 1));
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        k, sanitize(v, k, depth + 1)
      ])
    );
  }

  return value;
}

function safeBody(value) {
  if (typeof value === 'string') {
    try {
      return sanitize(JSON.parse(value));
    } catch {
      return sanitize(value);
    }
  }
  return sanitize(value);
}

function currentUser() {
  const req = context.getStore()?.req;
  return req?.user?.id ?? null;
}

function log(level, type, data = {}) {
  if (!settings.endpointUrl || !settings.accountId || !settings.apiKey) {
    return;
  }

  const entry = {
    ...sanitize(data),
    userId: currentUser(),
  };

  const event = {
    streams: [{
      stream: {
        component: settings.source || 'jwt-pizza-service',
        level,
        type,
      },
      values: [[
        (BigInt(Date.now()) * 1000000n).toString(),
        JSON.stringify(entry),
      ]],
    }],
  };

  const auth = Buffer.from(
    `${settings.accountId}:${settings.apiKey}`
  ).toString('base64');

  fetch(settings.endpointUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${auth}`,
    },
    body: JSON.stringify(event),
    signal: AbortSignal.timeout(5000),
  })
    .then(res => {
      if (!res.ok) console.error('Loki logging HTTP', res.status);
    })
    .catch(err => {
      console.error('Loki logging failed:', err.message);
    });
}

function httpLogger(req, res, next) {
  context.run({ req }, () => {
    const originalSend = res.send.bind(res);
    let responseBody;

    res.send = function (body) {
      responseBody = safeBody(body);
      return originalSend(body);
    };

    res.once('finish', () => {
      const status = res.statusCode;

      log(
        status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info',
        'http',
        {
          method: req.method,
          path: req.path,
          statusCode: status,
          authorized: Boolean(req.headers.authorization),
          requestBody: safeBody(req.body),
          responseBody,
        }
      );
    });

    next();
  });
}

function sqlStatement(sql) {
  // Hide inline quoted values such as emails and password hashes.
  return String(sql)
    .replace(/'(?:''|\\'|[^'])*'/g, '?')
    .slice(0, 2000);
}

module.exports = {
  log,
  httpLogger,
  sanitize,
  safeBody,
  sqlStatement,
  currentUser,
};
