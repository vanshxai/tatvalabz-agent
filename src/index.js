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
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': process.env.AGENT_CORS_ORIGIN || '*',
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
  });
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
      const flatDevices = [];
      const internalDevices = [];
      const externalDevices = [];
      const controllers = [];
      const walk = (nodes, container) => {
        if (!Array.isArray(nodes)) return;
        nodes.forEach((node) => {
          const name = node?._name || node?.name || '';
          const vendor = node?.manufacturer || node?.vendor_name || '';
          const product = node?.product_id || '';
          const serial = node?.serial_num || '';
          const location = node?.location_id || '';
          const speed = node?.speed || '';
          const builtIn = String(node?.built_in || '').toLowerCase() === 'yes';
          const isInternal = builtIn || vendor.toLowerCase().includes('apple');
          const entry = {
            name,
            vendor,
            product,
            serial,
            location,
            speed,
            internal: isInternal,
          };
          if (name) {
            const line = [name, vendor, product].filter(Boolean).join(' · ');
            results.push(line);
            flatDevices.push(entry);
            if (isInternal) internalDevices.push(entry);
            else externalDevices.push(entry);
          }
          const children = node?._items;
          if (Array.isArray(children)) {
            const containerNode = {
              name,
              vendor,
              product,
              serial,
              location,
              speed,
              internal: isInternal,
              devices: [],
            };
            if (container) container.devices.push(containerNode);
            else if (name) controllers.push(containerNode);
            walk(children, containerNode);
          }
        });
      };
      walk(items, null);
      return {
        flat: results,
        controllers,
        internal: internalDevices,
        external: externalDevices,
      };
    } catch {
      return [];
    }
  }
  const output = safeExec('lsusb');
  if (!output) return [];
  return output.split('\n').filter(Boolean);
}

function parseSystemProfiler(section) {
  const output = safeExec(`system_profiler ${section} -json`);
  if (!output) return [];
  try {
    const payload = JSON.parse(output);
    return payload?.[section] || [];
  } catch {
    return [];
  }
}

function listWifiDetails() {
  if (process.platform !== 'darwin') return [];
  const results = [];
  const items = parseSystemProfiler('SPAirPortDataType');
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    nodes.forEach((node) => {
      const current = node?.spairport_current_network_information;
      if (current?.spairport_network_name) {
        results.push({
          name: current.spairport_network_name,
          rssi: current.spairport_signal_noise || current.spairport_signal_rssi,
          noise: current.spairport_signal_noise,
          txRate: current.spairport_transmit_rate,
          channel: current.spairport_channel,
          security: current.spairport_security_mode,
        });
      }
      if (Array.isArray(node?._items)) walk(node._items);
    });
  };
  walk(items);

  if (results.length > 0) return results;

  // Fallback: airport -I (more reliable across macOS versions)
  const airportCmd = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I';
  const airportOut = safeExec(airportCmd);
  if (airportOut) {
    const lines = airportOut.split('\n').map((l) => l.trim());
    const getVal = (key) => {
      const line = lines.find((l) => l.startsWith(`${key}:`));
      return line ? line.split(':').slice(1).join(':').trim() : '';
    };
    const ssid = getVal('SSID');
    if (ssid) {
      return [{
        name: ssid,
        rssi: getVal('agrCtlRSSI'),
        noise: getVal('agrCtlNoise'),
        txRate: getVal('lastTxRate'),
        channel: getVal('channel'),
        security: '',
      }];
    }
  }

  // Fallback: networksetup (SSID only)
  const nsOut = safeExec('networksetup -getairportnetwork en0');
  if (nsOut && nsOut.includes(':')) {
    const ssid = nsOut.split(':').slice(1).join(':').trim();
    if (ssid) return [{ name: ssid }];
  }

  return [];
}

function listPowerDetails() {
  if (process.platform !== 'darwin') return [];
  const items = parseSystemProfiler('SPPowerDataType');
  const results = [];
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    nodes.forEach((node) => {
      if (node?._name || node?.name) {
        results.push({
          name: node._name || node.name,
          state: node?.spbattery_state || node?.charger_connected || node?.ac_charger_information,
          charging: node?.spbattery_is_charging,
          charge: node?.sppower_battery_charge || node?.battery_charge,
          health: node?.sppower_battery_health,
          wattage: node?.sppower_wattage,
        });
      }
      if (Array.isArray(node?._items)) walk(node._items);
    });
  };
  walk(items);
  return results;
}

function listBluetoothDevices() {
  if (process.platform !== 'darwin') return [];
  const items = parseSystemProfiler('SPBluetoothDataType');
  const results = [];
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    nodes.forEach((node) => {
      if (node?._name && node?.device_connected !== undefined) {
        results.push({
          name: node._name,
          address: node?.device_address,
          connected: node?.device_connected,
          type: node?.device_type,
          manufacturer: node?.device_manufacturer,
        });
      }
      if (Array.isArray(node?._items)) walk(node._items);
    });
  };
  walk(items);
  return results;
}

function listAudioDevices() {
  if (process.platform !== 'darwin') return [];
  const items = parseSystemProfiler('SPAudioDataType');
  const results = [];
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    nodes.forEach((node) => {
      if (node?._name) {
        results.push({
          name: node._name,
          output: node?.coreaudio_device_output,
          input: node?.coreaudio_device_input,
          transport: node?.coreaudio_device_transport,
        });
      }
      if (Array.isArray(node?._items)) walk(node._items);
    });
  };
  walk(items);
  return results;
}

function listDisplays() {
  if (process.platform !== 'darwin') return [];
  const items = parseSystemProfiler('SPDisplaysDataType');
  const results = [];
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    nodes.forEach((node) => {
      if (node?._name && node?.spdisplays_resolution) {
        results.push({
          name: node._name,
          resolution: node?.spdisplays_resolution,
          refresh: node?.spdisplays_refresh_rate,
          connection: node?.spdisplays_connection_type,
        });
      }
      if (Array.isArray(node?._items)) walk(node._items);
    });
  };
  walk(items);
  return results;
}

function listStorage() {
  if (process.platform !== 'darwin') return [];
  const items = parseSystemProfiler('SPStorageDataType');
  const results = [];
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    nodes.forEach((node) => {
      if (node?._name && node?.size) {
        results.push({
          name: node._name,
          size: node?.size,
          type: node?.type,
          mount: node?.mount_point,
        });
      }
      if (Array.isArray(node?._items)) walk(node._items);
    });
  };
  walk(items);
  return results;
}

function listCameras() {
  if (process.platform !== 'darwin') return [];
  const items = parseSystemProfiler('SPCameraDataType');
  const results = [];
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    nodes.forEach((node) => {
      if (node?._name) {
        results.push({
          name: node._name,
          model: node?.model_id || node?.model,
        });
      }
      if (Array.isArray(node?._items)) walk(node._items);
    });
  };
  walk(items);
  return results;
}

function listMidiDevices() {
  if (process.platform !== 'darwin') return [];
  const items = parseSystemProfiler('SPMIDIDataType');
  const results = [];
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    nodes.forEach((node) => {
      if (node?._name) {
        results.push({
          name: node._name,
          manufacturer: node?.manufacturer,
          transport: node?.transport,
        });
      }
      if (Array.isArray(node?._items)) walk(node._items);
    });
  };
  walk(items);
  return results;
}

function listThunderbolt() {
  if (process.platform !== 'darwin') return [];
  const items = parseSystemProfiler('SPThunderboltDataType');
  const results = [];
  const walk = (nodes) => {
    if (!Array.isArray(nodes)) return;
    nodes.forEach((node) => {
      if (node?._name) {
        results.push({
          name: node._name,
          vendor: node?.vendor_name || node?.manufacturer,
          device: node?.device_name,
        });
      }
      if (Array.isArray(node?._items)) walk(node._items);
    });
  };
  walk(items);
  return results;
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
  const usbDetails = listUsbDevices();
  const usbFlat = Array.isArray(usbDetails) ? usbDetails : (usbDetails?.flat || []);
  return {
    ok: true,
    ts: new Date().toISOString(),
    platform: process.platform,
    arch: process.arch,
    hostname: os.hostname(),
    serial: listSerialPorts(),
    usb: usbFlat,
    usbDetails: Array.isArray(usbDetails) ? null : usbDetails,
    network: listNetworkInterfaces(),
    wifi: listWifiDetails(),
    power: listPowerDetails(),
    bluetooth: listBluetoothDevices(),
    audio: listAudioDevices(),
    displays: listDisplays(),
    storage: listStorage(),
    cameras: listCameras(),
    midi: listMidiDevices(),
    thunderbolt: listThunderbolt(),
  };
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || `${HOST}:${PORT}`}`);
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'access-control-allow-origin': process.env.AGENT_CORS_ORIGIN || '*',
        'access-control-allow-headers': 'content-type',
        'access-control-allow-methods': 'GET,POST,OPTIONS',
      });
      return res.end();
    }

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
