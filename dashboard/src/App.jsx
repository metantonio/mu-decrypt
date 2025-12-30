import React, { useState, useEffect, useRef } from 'react';
import './App.css';

function App() {
  const [view, setView] = useState('packets');
  const [packets, setPackets] = useState([]);
  const [activeClients, setActiveClients] = useState([]);
  const [selectedClientId, setSelectedClientId] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [injectHex, setInjectHex] = useState('');
  const [injectTarget, setInjectTarget] = useState('s');
  const [broadcastMode, setBroadcastMode] = useState(true);
  const [redirectionStatus, setRedirectionStatus] = useState({ domain: null, status: 'none', mode: 'hosts' });
  const [memoryStats, setMemoryStats] = useState({ hp: 0, max_hp: 0, mp: 0, max_mp: 0, level: 0, connected: false });

  const [scanResults, setScanResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);

  const ws = useRef(null);
  const packetListRef = useRef(null);

  useEffect(() => {
    connectWS();
    const interval = setInterval(pollStatus, 3000);
    return () => {
      if (ws.current) ws.current.close();
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    if (packetListRef.current && view === 'packets') {
      packetListRef.current.scrollTop = packetListRef.current.scrollHeight;
    }
  }, [packets, selectedClientId, view]);

  const connectWS = () => {
    ws.current = new WebSocket('ws://localhost:8000/ws');

    ws.current.onopen = () => {
      setIsConnected(true);
      console.log('Connected to Backend');
      pollStatus();
    };

    ws.current.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'client_connected') {
        setActiveClients(prev => {
          if (!prev.includes(message.client_id)) {
            const newList = [...prev, message.client_id];
            if (!selectedClientId) setSelectedClientId(message.client_id);
            return newList;
          }
          return prev;
        });
      } else if (message.type === 'client_disconnected') {
        setActiveClients(prev => {
          const newList = prev.filter(id => id !== message.client_id);
          if (selectedClientId === message.client_id) {
            setSelectedClientId(newList.length > 0 ? newList[0] : null);
          }
          return newList;
        });
      } else if (message.type === 'packet') {
        setPackets(prev => [...prev.slice(-499), message.data]);
        setActiveClients(prev => {
          if (!prev.includes(message.data.client_id)) {
            if (!selectedClientId) setSelectedClientId(message.data.client_id);
            return [...prev, message.data.client_id];
          }
        });
      } else if (message.type === 'memory') {
        setMemoryStats(message.data);
      }
    };

    ws.current.onclose = () => {
      setIsConnected(false);
      setTimeout(connectWS, 3000);
    };
  };

  const pollStatus = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/status');
      const data = await res.json();
      if (data.redirection) {
        setRedirectionStatus(data.redirection);
      }
    } catch (e) { }
  };

  const startScan = async () => {
    setIsScanning(true);
    try {
      const res = await fetch('http://localhost:8000/api/scan');
      const data = await res.json();
      setScanResults(data);
    } catch (e) {
      console.error(e);
    }
    setIsScanning(false);
  };

  const applyRedirect = async (domain) => {
    try {
      const res = await fetch('http://localhost:8000/api/redirect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();
      pollStatus();
      if (data.status === 'warning') {
        alert("⚠️ " + data.message);
      } else {
        alert("✅ " + data.message);
      }
    } catch (e) {
      alert("❌ Error al aplicar redirección");
    }
  };

  const sendInjection = () => {
    if (!injectHex || !ws.current) return;
    ws.current.send(JSON.stringify({
      command: 'inject',
      target: injectTarget,
      client_id: broadcastMode ? null : selectedClientId,
      hex: injectHex
    }));
    setInjectHex('');
  };

  const filteredPackets = packets.filter(p => !selectedClientId || p.client_id === selectedClientId);

  return (
    <div className="dashboard">
      <header>
        <div className="brand">Mu-Decrypt Engine <span style={{ fontSize: '0.8rem', opacity: 0.6 }}>v2.3</span></div>
        <nav className="view-selector">
          <button className={view === 'packets' ? 'active' : ''} onClick={() => setView('packets')}>Paquetes</button>
          <button className={view === 'scanner' ? 'active' : ''} onClick={() => setView('scanner')}>Escáner</button>
        </nav>

        <div className="header-status">
          {redirectionStatus.domain && (
            <div className={`redirection-badge ${redirectionStatus.status}`}>
              {redirectionStatus.status === 'success' ? '✓' : '⚠️'} {redirectionStatus.domain}
            </div>
          )}
          <div className={`dot ${isConnected ? 'connected' : ''}`}></div>
          <span style={{ fontSize: '0.85rem' }}>{isConnected ? 'Conectado' : 'Sin Señal'}</span>
        </div>
      </header>

      <div className="sidebar">
        <h3>Intercepción</h3>
        <div className="client-selector">
          {activeClients.length === 0 ? (
            <div style={{ padding: '1rem', textAlign: 'center', background: 'rgba(0,0,0,0.1)', borderRadius: '8px' }}>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', margin: 0 }}>
                Esperando tráfico...
              </p>
              {!redirectionStatus.domain && (
                <p style={{ fontSize: '0.7rem', color: 'var(--primary)', marginTop: '0.5rem', fontWeight: 600 }}>
                  TIP: Usa el Escáner para activar la redirección
                </p>
              )}
            </div>
          ) : (
            activeClients.map(id => (
              <div
                key={id}
                className={`client-tab ${selectedClientId === id ? 'active' : ''}`}
                onClick={() => {
                  setSelectedClientId(id);
                  setBroadcastMode(false);
                }}
              >
                {id}
              </div>
            ))
          )}
        </div>

        {memoryStats.connected && (
          <div className="memory-hud" style={{ marginTop: '2rem' }}>
            <h3>Estado del Personaje</h3>
            <div className="stat-bar-container">
              <label>HP: {memoryStats.hp} / {memoryStats.max_hp}</label>
              <div className="stat-bar hp" style={{ width: `${(memoryStats.hp / memoryStats.max_hp) * 100 || 0}%` }}></div>
            </div>
            <div className="stat-bar-container" style={{ marginTop: '0.8rem' }}>
              <label>MP: {memoryStats.mp} / {memoryStats.max_mp}</label>
              <div className="stat-bar mp" style={{ width: `${(memoryStats.mp / memoryStats.max_mp) * 100 || 0}%` }}></div>
            </div>
            <div style={{ marginTop: '0.8rem', fontSize: '0.9rem', color: 'var(--accent)' }}>
              Nivel: <span style={{ fontWeight: 700 }}>{memoryStats.level}</span>
            </div>
          </div>
        )}

        <h3 style={{ marginTop: '2rem' }}>Inyección Manual</h3>
        <div style={{ padding: '0.5rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', fontSize: '0.8rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input type="checkbox" checked={broadcastMode} onChange={() => setBroadcastMode(!broadcastMode)} />
            Modo Broadcast
          </label>
        </div>

        <div style={{ marginTop: '1rem' }}>
          <div className="input-group">
            <button className={injectTarget === 's' ? 'primary' : 'secondary'} onClick={() => setInjectTarget('s')}>Al Servidor</button>
            <button className={injectTarget === 'c' ? 'primary' : 'secondary'} onClick={() => setInjectTarget('c')}>Al Cliente</button>
          </div>
        </div>

        <div className="input-group">
          <input
            type="text"
            placeholder="Payload HEX"
            value={injectHex}
            onChange={(e) => setInjectHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
          />
          <button onClick={sendInjection} className="action-button">Enviar</button>
        </div>

        <div style={{ marginTop: 'auto', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', opacity: 0.6 }}>
            <span>Paquetes: {packets.length}</span>
            <span>Clientes: {activeClients.length}</span>
          </div>
        </div>
      </div>

      <div className="main-content">
        {view === 'packets' ? (
          <div className="packet-list" ref={packetListRef}>
            {activeClients.length === 0 ? (
              <div className="empty-state">
                <div style={{ textAlign: 'center', maxWidth: '400px' }}>
                  <h2 style={{ color: 'var(--text-main)', marginBottom: '1rem' }}>Listo para Interceptar</h2>
                  <p>Si el juego ya está abierto y no ves paquetes:</p>
                  <ol style={{ textAlign: 'left', fontSize: '0.9rem', color: 'var(--text-dim)', lineHeight: 1.6 }}>
                    <li>Ve a la pestaña <strong>Escáner</strong>.</li>
                    <li>Busca el dominio del servidor (ej: <code>connect.mu.com</code>).</li>
                    <li>Pulsa <strong>Force Local</strong>.</li>
                    <li>Reinicia el juego (Launcher).</li>
                    <li style={{ color: 'var(--primary)', fontWeight: 'bold' }}>Si nada de eso funciona: Activa el <strong>Modo Transparente</strong> lanzando el script con <code>--transparent</code>.</li>
                  </ol>
                </div>
              </div>
            ) : filteredPackets.length === 0 ? (
              <div className="empty-state">No hay paquetes para {selectedClientId}</div>
            ) : (
              filteredPackets.map((p, i) => (
                <div key={i} className={`packet-item ${p.direction.includes('SERVER') ? 'server' : 'client'}`}>
                  <div className="packet-header">
                    <span style={{ fontWeight: 700 }}>{p.opcode_name}</span>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <span className="packet-badge">Type: {p.packet_type}</span>
                      <span className="packet-badge">Op: {p.opcode}</span>
                    </div>
                  </div>
                  <div className="packet-hex">{p.hex}</div>
                </div>
              ))
            )}
          </div>
        ) : (
          <div className="scanner-view">
            <div className="scanner-header">
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <h2 style={{ margin: 0 }}>Detective de Procesos</h2>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', margin: '4px 0 0 0' }}>Identifica puertos y dominios de conexión</p>
              </div>
              <button onClick={startScan} disabled={isScanning} style={{ padding: '0.6rem 1.5rem' }}>
                {isScanning ? 'Buscando...' : 'Escanear Ahora'}
              </button>
            </div>

            <div className="scan-results">
              {scanResults.length === 0 ? (
                <div className="empty-state">Pulsa "Escanear Ahora" con el juego abierto</div>
              ) : (
                scanResults.map((p, i) => (
                  <div key={i} className="process-card">
                    <div className="process-title">
                      <strong>{p.name}</strong> <span style={{ opacity: 0.5 }}>PID: {p.pid}</span>
                    </div>
                    <div className="process-detail" style={{ marginBottom: '1rem' }}>{p.exe}</div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                      <div className="suggestion-section">
                        <h4>Dominios Detectados:</h4>
                        <div className="suggestion-tags">
                          {p.discovered_domains.concat(p.config_hints).map((d, j) => (
                            <div key={j} className="suggestion-tag" onClick={() => applyRedirect(d)}>
                              {d} <span>(Force Local)</span>
                            </div>
                          ))}
                          {p.discovered_domains.length + p.config_hints.length === 0 && (
                            <span style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>No se hallaron dominios.</span>
                          )}
                        </div>
                      </div>

                      <div className="connection-section">
                        <h4>Conexiones IPs:</h4>
                        <ul style={{ fontSize: '0.85rem', color: 'var(--accent)', margin: '0.5rem 0', paddingLeft: '1.2rem' }}>
                          {p.remote_addresses.map((addr, k) => (
                            <li key={k} style={addr.includes('CONNECTSERVER') ? { color: 'var(--primary)', fontWeight: 'bold' } : {}}>
                              {addr}
                            </li>
                          ))}
                          {p.remote_addresses.length === 0 && <li>Ninguna conexión activa.</li>}
                        </ul>
                      </div>
                    </div>

                    {p.remote_addresses.some(a => a.includes('CONNECTSERVER')) && (
                      <div style={{
                        background: 'rgba(79, 70, 229, 0.1)',
                        border: '1px solid var(--primary)',
                        padding: '1rem',
                        borderRadius: '12px',
                        fontSize: '0.85rem',
                        marginTop: '1rem',
                        color: 'white',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '1rem'
                      }}>
                        <span style={{ fontSize: '1.5rem' }}>💡</span>
                        <div>
                          <strong>¡ConnectServer detectado!</strong> Redirigir el dominio que ves a la izquierda es fundamental para capturar el tráfico del GameServer más adelante.
                        </div>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
