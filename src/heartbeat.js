function nowIso() {
  return new Date().toISOString();
}

export function createHeartbeatWorker({ getConfig }) {
  let timer = null;

  const tick = async () => {
    const cfg = getConfig();
    if (!cfg.paired || !cfg.backendUrl || !cfg.pairingCode) return;

    const payload = {
      paired: cfg.paired,
      pairingCode: cfg.pairingCode,
      deviceName: cfg.deviceName,
      ts: nowIso(),
      permissions: cfg.permissions,
      platform: process.platform,
      arch: process.arch,
      uptimeSec: Math.round(process.uptime()),
      memoryRssMb: Math.round(process.memoryUsage().rss / (1024 * 1024)),
    };

    const endpoint = `${String(cfg.backendUrl).replace(/\/$/, '')}/api/agent/heartbeat`;

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        console.warn(`[agent] heartbeat rejected ${res.status} @ ${nowIso()}`);
        return;
      }
      console.log(`[agent] heartbeat ok @ ${nowIso()}`);
    } catch (err) {
      console.warn(`[agent] heartbeat failed @ ${nowIso()} :: ${err?.message || err}`);
    }
  };

  const start = () => {
    stop();
    const interval = Math.max(2000, Number(getConfig().heartbeatIntervalMs) || 10000);
    timer = setInterval(tick, interval);
    console.log(`[agent] heartbeat worker started (${interval}ms)`);
    void tick();
  };

  const stop = () => {
    if (!timer) return;
    clearInterval(timer);
    timer = null;
  };

  return { start, stop };
}
