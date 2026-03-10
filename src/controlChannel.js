function toWsUrl(baseHttpUrl) {
  const u = new URL(String(baseHttpUrl));
  const proto = u.protocol === 'https:' ? 'wss:' : 'ws:';
  u.protocol = proto;
  u.pathname = '/api/agent/ws';
  u.search = '';
  return u.toString();
}

export function createControlChannel({ getConfig, onStatusRequest, onPermissionsUpdate }) {
  let ws = null;
  let reconnectTimer = null;
  let stopped = false;
  let reconnectAttempt = 0;
  let state = {
    connected: false,
    lastConnectedAt: null,
    lastMessageAt: null,
    lastError: null,
  };

  const setState = (partial) => {
    state = { ...state, ...partial };
  };

  const getState = () => ({ ...state });

  const clearReconnect = () => {
    if (!reconnectTimer) return;
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  };

  const sendJson = (payload) => {
    if (!ws || ws.readyState !== 1) return false;
    ws.send(JSON.stringify(payload));
    return true;
  };

  const handleCommand = async (message) => {
    const base = {
      ts: new Date().toISOString(),
      requestId: message?.requestId || null,
      type: 'ack',
    };

    switch (message?.type) {
      case 'ping':
        sendJson({ ...base, event: 'pong', ok: true });
        return;
      case 'get_status':
        sendJson({ ...base, event: 'status', ok: true, status: onStatusRequest() });
        return;
      case 'update_permissions': {
        const permissions = message?.permissions || {};
        await onPermissionsUpdate(permissions);
        sendJson({ ...base, event: 'permissions_updated', ok: true });
        return;
      }
      default:
        sendJson({ ...base, event: 'unsupported_command', ok: false, command: message?.type || 'unknown' });
    }
  };

  const scheduleReconnect = () => {
    if (stopped || reconnectTimer) return;
    const delay = Math.min(30000, 1000 * Math.pow(2, reconnectAttempt));
    reconnectAttempt += 1;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      void connect();
    }, delay);
  };

  const connect = async () => {
    clearReconnect();

    const cfg = getConfig();
    if (!cfg?.paired || !cfg?.backendUrl || !cfg?.pairingCode) return;

    try {
      const endpoint = new URL(toWsUrl(cfg.backendUrl));
      endpoint.searchParams.set('pairingCode', String(cfg.pairingCode));
      endpoint.searchParams.set('deviceName', String(cfg.deviceName || 'agent-device'));

      if (typeof WebSocket === 'undefined') {
        throw new Error('Global WebSocket is not available in this Node runtime');
      }

      ws = new WebSocket(endpoint.toString());

      ws.onopen = () => {
        reconnectAttempt = 0;
        setState({ connected: true, lastConnectedAt: new Date().toISOString(), lastError: null });
        sendJson({ type: 'hello', ts: new Date().toISOString(), platform: process.platform, arch: process.arch });
      };

      ws.onmessage = (event) => {
        setState({ lastMessageAt: new Date().toISOString() });
        try {
          const parsed = JSON.parse(String(event.data || '{}'));
          void handleCommand(parsed);
        } catch {
          sendJson({ type: 'ack', ok: false, event: 'invalid_json' });
        }
      };

      ws.onerror = () => {
        setState({ lastError: 'websocket error' });
      };

      ws.onclose = () => {
        setState({ connected: false });
        scheduleReconnect();
      };
    } catch (err) {
      setState({ connected: false, lastError: err?.message || String(err) });
      scheduleReconnect();
    }
  };

  const start = () => {
    stopped = false;
    void connect();
  };

  const stop = () => {
    stopped = true;
    clearReconnect();
    if (ws) {
      try {
        ws.close();
      } catch {
        // ignore close failures
      }
      ws = null;
    }
    setState({ connected: false });
  };

  return { start, stop, getState };
}
