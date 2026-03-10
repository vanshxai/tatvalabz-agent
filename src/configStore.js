import { promises as fs } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const APP_DIR = path.resolve(
  process.env.TATVALABZ_AGENT_HOME || path.join(process.cwd(), '.agent-state')
);
const CONFIG_PATH = path.join(APP_DIR, 'config.json');

const DEFAULT_CONFIG = {
  version: 1,
  paired: false,
  pairingCode: null,
  backendUrl: null,
  deviceName: os.hostname(),
  permissions: {
    network: false,
    usb: false,
    serial: false,
    gpu: false,
    fileSystem: false,
  },
  heartbeatIntervalMs: 10000,
};

export async function loadConfig() {
  try {
    const raw = await fs.readFile(CONFIG_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return mergeConfig(parsed);
  } catch {
    await ensureDir();
    await saveConfig(DEFAULT_CONFIG);
    return { ...DEFAULT_CONFIG };
  }
}

export async function saveConfig(config) {
  await ensureDir();
  const normalized = mergeConfig(config);
  await fs.writeFile(CONFIG_PATH, JSON.stringify(normalized, null, 2), 'utf8');
  return normalized;
}

function mergeConfig(config) {
  return {
    ...DEFAULT_CONFIG,
    ...config,
    permissions: {
      ...DEFAULT_CONFIG.permissions,
      ...(config?.permissions || {}),
    },
  };
}

async function ensureDir() {
  await fs.mkdir(APP_DIR, { recursive: true });
}

export { CONFIG_PATH };
