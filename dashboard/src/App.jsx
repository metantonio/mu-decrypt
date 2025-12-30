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

  const [scanResults, setScanResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);

  const ws = useRef(null);
  const packetListRef = useRef(null);

  useEffect(() => {
    connectWS();
    return () => {
      if (ws.current) ws.current.close();
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
          return prev;
        });
      }
    };

    ws.current.onclose = () => {
      setIsConnected(false);
      setTimeout(connectWS, 3000);
    };
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
      alert(data.message);
    } catch (e) {
      alert("Error al aplicar redirección");
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
        <div className="brand">Mu-Decrypt Engine <span style={{ fontSize: '0.8rem', opacity: 0.6 }}>v2.2</span></div>
        <nav className="view-selector">
          <button className={view === 'packets' ? 'active' : ''} onClick={() => setView('packets')}>Paquetes</button>
          <button className={view === 'scanner' ? 'active' : ''} onClick={() => setView('scanner')}>Escáner</button>
        </nav>
        <div className="status-indicator">
          <div className={`dot ${isConnected ? 'connected' : ''}`}></div>
          {isConnected ? 'Sistema en línea' : 'Desconectado'}
        </div>
      </header>

      <div className="sidebar">
        <h3>Clientes Activos</h3>
        <div className="client-selector">
          {activeClients.length === 0 ? (
            <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', textAlign: 'center', padding: '1rem' }}>
              Sin conexiones activas.<br />Abre el juego para interceptar.
            </p>
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

        <h3 style={{ marginTop: '2rem' }}>Inyección Manual</h3>
        <div style={{ padding: '0.5rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', fontSize: '0.8rem' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input type="checkbox" checked={broadcastMode} onChange={() => setBroadcastMode(!broadcastMode)} />
            Modo Broadcast (Enviar a todos)
          </label>
          <p style={{ margin: '0.5rem 0 0', color: 'var(--text-dim)' }}>
            Target: <strong>{broadcastMode ? "TODOS" : (selectedClientId || "Ninguno")}</strong>
          </p>
        </div>

        <div style={{ marginTop: '1rem' }}>
          <label style={{ fontSize: '0.8rem', marginBottom: '0.4rem', display: 'block' }}>Destino:</label>
          <div className="input-group">
            <button className={injectTarget === 's' ? 'primary' : 'secondary'} onClick={() => setInjectTarget('s')}>Servidor</button>
            <button className={injectTarget === 'c' ? 'primary' : 'secondary'} onClick={() => setInjectTarget('c')}>Cliente</button>
          </div>
        </div>

        <div className="input-group">
          <input
            type="text"
            placeholder="Payload HEX (ej: C1040001)"
            value={injectHex}
            onChange={(e) => setInjectHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
          />
          <button onClick={sendInjection} className="action-button">Inyectar</button>
        </div>

        <div style={{ marginTop: 'auto', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem', marginBottom: '4px' }}>
            <span style={{ color: 'var(--text-dim)' }}>Paquetes:</span>
            <span>{packets.length}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
            <span style={{ color: 'var(--text-dim)' }}>Conexiones:</span>
            <span>{activeClients.length}</span>
          </div>
        </div>
      </div>

      <div className="main-content">
        {view === 'packets' ? (
          <div className="packet-list" ref={packetListRef}>
            {activeClients.length === 0 ? (
              <div className="empty-state">
                <div style={{ textAlign: 'center' }}>
                  <p>Esperando primer paquete...</p>
                  <p style={{ fontSize: '0.8rem', opacity: 0.7 }}>Si el juego ya está abierto, intenta reconectar.</p>
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
                      <span className="packet-badge">Size: {p.size}</span>
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
              <h2>Detective de Procesos</h2>
              <button onClick={startScan} disabled={isScanning}>
                {isScanning ? 'Escaneando...' : 'Iniciar Escaneo'}
              </button>
            </div>

            <div className="scan-results">
              {scanResults.length === 0 ? (
                <div className="empty-state">Busca `main.exe` para identificar dominios de conexión</div>
              ) : (
                scanResults.map((p, i) => (
                  <div key={i} className="process-card">
                    <div className="process-title">
                      <strong>{p.name}</strong> <span>(PID: {p.pid})</span>
                    </div>
                    <div className="process-detail">{p.exe}</div>

                    <div className="suggestion-section">
                      <h4>Dominios para Redirección (hosts):</h4>
                      <div className="suggestion-tags">
                        {p.discovered_domains.concat(p.config_hints).map((d, j) => (
                          <div key={j} className="suggestion-tag" onClick={() => applyRedirect(d)}>
                            {d} <span>(Force Local)</span>
                          </div>
                        ))}
                        {p.discovered_domains.length + p.config_hints.length === 0 && (
                          <span style={{ color: 'var(--text-dim)', fontSize: '0.8rem' }}>Usa el dominio del juego si lo conoces.</span>
                        )}
                      </div>
                    </div>

                    <div className="connection-section">
                      <h4>Rutas IP detectadas (Establecidas):</h4>
                      <ul style={{ fontSize: '0.85rem', color: 'var(--accent)', margin: '0.5rem 0' }}>
                        {p.remote_addresses.map((addr, k) => <li key={k}>{addr}</li>)}
                        {p.remote_addresses.length === 0 && <li>Sin conexiones externas visibles.</li>}
                      </ul>
                    </div>
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
