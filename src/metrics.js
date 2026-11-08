'use strict';

// JWT Pizza OTel metrics. Uses only Node built-ins, no new npm dependency.
const os = require('node:os');
const config = require('./config.js');
const settings = config.metrics || {};
const counts = Object.fromEntries(['GET', 'PUT', 'POST', 'DELETE'].map((m) => [m, 0]));
const attempts = { success: 0, failure: 0 };
const activeUsers = new Map();
const endpointDurations = new Map();
const purchases = { sold: 0, failures: 0, revenueCents: 0, latencyMs: 0 };
let previousCpu = process.cpuUsage();
let previousCpuTime = process.hrtime.bigint();
let sending = false;
const started = BigInt(Date.now()) * 1000000n;

function requestTracker(req, res, next) {
  const begin = process.hrtime.bigint();
  if (req.user?.id != null) activeUsers.set(String(req.user.id), Date.now());
  res.once('finish', () => {
    const method = req.method.toUpperCase();
    if (Object.hasOwn(counts, method)) counts[method]++;
    const path = req.route?.path || req.path.replace(/\/\d+(?=\/|$)/g, '/:id');
    const endpoint = `${method} ${path}`;
    endpointDurations.set(endpoint, Number(process.hrtime.bigint() - begin) / 1e6);
    if (method === 'PUT' && req.originalUrl.split('?')[0] === '/api/auth') {
      attempts[res.statusCode >= 200 && res.statusCode < 300 ? 'success' : 'failure']++;
    }
  });
  next();
}

function pizzaPurchase(success, durationMs, items, revenueDollars) {
  if (success) {
    purchases.sold += Math.max(0, Number(items) || 0);
    purchases.revenueCents += Math.round(Math.max(0, Number(revenueDollars) || 0) * 100);
  } else {
    purchases.failures++;
  }
  purchases.latencyMs = Math.max(0, Number(durationMs) || 0);
}

function metric(name, value, kind = 'gauge', unit = '1', labels = {}) {
  const datapoint = {
    asDouble: Number(value),
    startTimeUnixNano: started.toString(),
    timeUnixNano: (BigInt(Date.now()) * 1000000n).toString(),
    attributes: Object.entries({ source: settings.source || 'jwt-pizza-service', ...labels }).map(([key, val]) => ({
      key, value: { stringValue: String(val) },
    })),
  };
  const spec = { dataPoints: [datapoint] };
  if (kind === 'sum') {
    spec.aggregationTemporality = 'AGGREGATION_TEMPORALITY_CUMULATIVE';
    spec.isMonotonic = true;
  }
  return { name, unit, [kind]: spec };
}

function buildMetrics() {
  const now = Date.now();
  for (const [id, last] of activeUsers) if (now - last > 5 * 60 * 1000) activeUsers.delete(id);
  const current = process.cpuUsage();
  const nano = process.hrtime.bigint();
  const elapsedUs = Math.max(1, Number(nano - previousCpuTime) / 1000);
  const cpuPercent = Math.min(100, 100 * (current.user + current.system - previousCpu.user - previousCpu.system) / elapsedUs);
  previousCpu = current;
  previousCpuTime = nano;
  const usedMemoryPercent = 100 * (1 - os.freemem() / os.totalmem());
  const metrics = [
    metric('active_users', activeUsers.size),
    metric('cpu_usage', cpuPercent, 'gauge', '%'),
    metric('memory_usage', usedMemoryPercent, 'gauge', '%'),
    metric('pizzas_sold', purchases.sold, 'sum'),
    metric('pizza_creation_failures', purchases.failures, 'sum'),
    metric('pizza_revenue_cents', purchases.revenueCents, 'sum'),
    metric('pizza_creation_latency', purchases.latencyMs, 'gauge', 'ms'),
  ];
  for (const [method, count] of Object.entries(counts)) metrics.push(metric('http_requests', count, 'sum', '1', { method }));
  for (const [outcome, count] of Object.entries(attempts)) metrics.push(metric('auth_attempts', count, 'sum', '1', { outcome }));
  for (const [endpoint, ms] of endpointDurations) metrics.push(metric('http_endpoint_latency', ms, 'gauge', 'ms', { endpoint }));
  return metrics;
}

async function sendMetrics() {
  if (sending || !settings.endpointUrl || !settings.accountId || !settings.apiKey) return;
  sending = true;
  try {
    const auth = Buffer.from(`${settings.accountId}:${settings.apiKey}`).toString('base64');
    const response = await fetch(settings.endpointUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Basic ${auth}` },
      body: JSON.stringify({ resourceMetrics: [{ scopeMetrics: [{ metrics: buildMetrics() }] }] }),
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) console.error(`Grafana metrics HTTP ${response.status}: ${(await response.text()).slice(0, 300)}`);
  } catch (error) {
    console.error('Grafana metrics upload failed:', error.message);
  } finally {
    sending = false;
  }
}

function startReporting() {
  if (settings.endpointUrl && settings.accountId && settings.apiKey) {
    const timer = setInterval(sendMetrics, 10000);
    timer.unref();
  } else {
    console.log('Grafana metrics disabled: missing configuration');
  }
}

module.exports = { requestTracker, pizzaPurchase, startReporting };
