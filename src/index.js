import http from 'node:http';
import os from 'node:os';
import fs from 'node:fs';
import { execSync } from 'node:child_process';
import { loadConfig, saveConfig, CONFIG_PATH } from './configStore.js';
import { createHeartbeatWorker } from './heartbeat.js';
import { verifySignedPairRequest, signPairRequestForTesting } from './security.js';
import { createControlChannel } from './controlChannel.js';

const PORT = Number(process.env.AGENT_PORT || 8787);
const HOST = process.env.AGENT_HOST || '127.0.0.1';
const AGENT_PAIR_SECRET = process.env.AGENT_PAIR_SECRET || '';
const ALLOW_INSECURE_PAIR = process.env.ALLOW_INSECURE_PAIR === '1';

let config = await loadConfig();
const heartbeat = createHeartbeatWorker({ getConfig: () => config });
const controlChannel = createControlChannel({
  getConfig: () => config,
  onStatusRequest: () => getStatus(),
  onPermissionsUpdate: async (permissions) => {
    config = await saveConfig({
      ...config,
      permissions: {
        ...config.permissions,
        ...(permissions || {}),
      },
    });
  },
});
heartbeat.start();
controlChannel.start();

function safeJson(res, status, payload) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 1_000_000) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function getStatus() {
  return {
    ok: true,
    agent: 'tatvalabz-agent',
    version: '0.1.0',
    ts: new Date().toISOString(),
    platform: process.platform,
    arch: process.arch,
    hostname: os.hostname(),
    configPath: CONFIG_PATH,
    paired: config.paired,
    backendUrl: config.backendUrl,
    deviceName: config.deviceName,
    permissions: config.permissions,
    controlChannel: controlChannel.getState(),
    securePairingEnabled: Boolean(AGENT_PAIR_SECRET),
  };
}

function safeExec(cmd) {
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
}

function listSerialPorts() {
  if (process.platform === 'darwin') {
    try {
      const entries = fs.readdirSync('/dev');
      return entries
        .filter((name) => name.startsWith('tty.') || name.startsWith('cu.'))
        .map((name) => `/dev/${name}`);
    } catch {
      return [];
    }
  }
  if (process.platform !== 'linux') return [];
  try {
    return fs.readdirSync('/dev')
      .filter((name) => (
        name.startsWith('ttyUSB') ||
        name.startsWith('ttyACM') ||
        name.startsWith('ttyS') ||
        name.startsWith('ttyAMA')
      ))
      .map((name) => `/dev/${name}`);
  } catch {
    return [];
  }
}

function listUsbDevices() {
  if (process.platform === 'darwin') {
    const output = safeExec('system_profiler SPUSBDataType -json');
    if (!output) return [];
    try {
      const payload = JSON.parse(output);
      const items = payload?.SPUSBDataType || [];
      const results = [];
      const walk = (nodes) => {
        if (!Array.isArray(nodes)) return;
        nodes.forEach((node) => {
          const name = node?._name || node?.name;
          const vendor = node?.manufacturer || node?.vendor_name || '';
          const product = node?.product_id || '';
          if (name) {
            const line = [name, vendor, product].filter(Boolean).join(' · ');
            results.push(line);
          }
          if (Array.isArray(node?._items)) walk(node._items);
        });
      };
      walk(items);
      return results;
    } catch {
      return [];
    }
  }
  const output = safeExec('lsusb');
  if (!output) return [];
  return output.split('\n').filter(Boolean);
}

function listNetworkInterfaces() {
  const entries = os.networkInterfaces();
  const result = [];
  Object.entries(entries).forEach(([name, infos]) => {
    (infos || []).forEach((info) => {
      result.push({
        name,
        address: info.address,
        family: info.family,
        mac: info.mac,
        internal: info.internal,
      });
    });
  });
  return result;
}

function getDeviceSnapshot() {
  return {
    ok: true,
    ts: new Date().toISOString(),
    platform: process.platform,
    arch: process.arch,
    hostname: os.hostname(),
    serial: listSerialPorts(),
    usb: listUsbDevices(),
    network: listNetworkInterfaces(),
  };
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || `${HOST}:${PORT}`}`);

    if (req.method === 'GET' && url.pathname === '/health') {
      return safeJson(res, 200, getStatus());
    }

    if (req.method === 'GET' && url.pathname === '/status') {
      return safeJson(res, 200, getStatus());
    }

    if (req.method === 'GET' && url.pathname === '/devices') {
      return safeJson(res, 200, getDeviceSnapshot());
    }

    if (req.method === 'POST' && url.pathname === '/pair') {
      const body = await parseBody(req);
      if (!body.pairingCode || !body.backendUrl) {
        return safeJson(res, 400, { ok: false, error: 'pairingCode and backendUrl are required' });
      }
      if (!ALLOW_INSECURE_PAIR) {
        return safeJson(res, 403, {
          ok: false,
          error: 'Insecure pairing disabled. Use /pair/signed with AGENT_PAIR_SECRET.',
        });
      }

      config = await saveConfig({
        ...config,
        paired: true,
        pairingCode: String(body.pairingCode),
        backendUrl: String(body.backendUrl),
        deviceName: body.deviceName ? String(body.deviceName) : config.deviceName,
      });
      heartbeat.start();
      controlChannel.start();
      return safeJson(res, 200, { ok: true, message: 'Agent paired', status: getStatus() });
    }

    if (req.method === 'POST' && url.pathname === '/pair/signed') {
      const body = await parseBody(req);
      const verdict = verifySignedPairRequest({
        secret: AGENT_PAIR_SECRET,
        pairingCode: body.pairingCode,
        backendUrl: body.backendUrl,
        expiresAt: body.expiresAt,
        nonce: body.nonce,
        signature: body.signature,
      });
      if (!verdict.ok) {
        return safeJson(res, 401, { ok: false, error: verdict.error });
      }

      config = await saveConfig({
        ...config,
        paired: true,
        pairingCode: String(body.pairingCode),
        backendUrl: String(body.backendUrl),
        deviceName: body.deviceName ? String(body.deviceName) : config.deviceName,
      });
      heartbeat.start();
      controlChannel.start();
      return safeJson(res, 200, { ok: true, message: 'Agent paired (signed)', status: getStatus() });
    }

    if (req.method === 'POST' && url.pathname === '/pair/sign-test') {
      const body = await parseBody(req);
      if (!AGENT_PAIR_SECRET) {
        return safeJson(res, 400, { ok: false, error: 'AGENT_PAIR_SECRET missing' });
      }
      const expiresAt = body.expiresAt || new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const nonce = body.nonce || String(Math.random()).slice(2);
      const signature = signPairRequestForTesting({
        secret: AGENT_PAIR_SECRET,
        pairingCode: String(body.pairingCode || 'demo-pair'),
        backendUrl: String(body.backendUrl || 'https://example.com'),
        expiresAt,
        nonce,
      });
      return safeJson(res, 200, {
        ok: true,
        signedRequest: {
          pairingCode: String(body.pairingCode || 'demo-pair'),
          backendUrl: String(body.backendUrl || 'https://example.com'),
          expiresAt,
          nonce,
          signature,
          deviceName: String(body.deviceName || config.deviceName),
        },
      });
    }

    if (req.method === 'POST' && url.pathname === '/unpair') {
      config = await saveConfig({
        ...config,
        paired: false,
        pairingCode: null,
        backendUrl: null,
      });
      heartbeat.start();
      controlChannel.stop();
      return safeJson(res, 200, { ok: true, message: 'Agent unpaired', status: getStatus() });
    }

    if (req.method === 'POST' && url.pathname === '/permissions') {
      const body = await parseBody(req);
      config = await saveConfig({
        ...config,
        permissions: {
          ...config.permissions,
          ...(body.permissions || {}),
        },
      });
      return safeJson(res, 200, { ok: true, message: 'Permissions updated', permissions: config.permissions });
    }

    if (req.method === 'POST' && url.pathname === '/config') {
      const body = await parseBody(req);
      config = await saveConfig({ ...config, ...body });
      heartbeat.start();
      controlChannel.start();
      return safeJson(res, 200, { ok: true, message: 'Config updated', status: getStatus() });
    }

    return safeJson(res, 404, { ok: false, error: 'Not found' });
  } catch (err) {
    return safeJson(res, 500, { ok: false, error: err?.message || String(err) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[agent] running on http://${HOST}:${PORT}`);
  console.log(`[agent] config file: ${CONFIG_PATH}`);
});

function shutdown(signal) {
  console.log(`[agent] received ${signal}, shutting down...`);
  heartbeat.stop();
  controlChannel.stop();
  server.close(() => process.exit(0));
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
