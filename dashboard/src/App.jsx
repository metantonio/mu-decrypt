import React, { useState, useEffect, useRef } from 'react';
import './App.css';

function App() {
  const [packets, setPackets] = useState([]);
  const [activeClients, setActiveClients] = useState([]);
  const [selectedClientId, setSelectedClientId] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [injectHex, setInjectHex] = useState('');
  const [injectTarget, setInjectTarget] = useState('s');
  const ws = useRef(null);
  const packetListRef = useRef(null);

  useEffect(() => {
    connectWS();
    return () => {
      if (ws.current) ws.current.close();
    };
  }, []);

  useEffect(() => {
    if (packetListRef.current) {
      packetListRef.current.scrollTop = packetListRef.current.scrollHeight;
    }
  }, [packets, selectedClientId]);

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

        // Auto-add client if not explicitly notified (safety)
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

  const sendInjection = () => {
    if (!injectHex || !ws.current || !selectedClientId) return;
    ws.current.send(JSON.stringify({
      command: 'inject',
      target: injectTarget,
      client_id: selectedClientId,
      hex: injectHex
    }));
    setInjectHex('');
  };

  const filteredPackets = packets.filter(p => !selectedClientId || p.client_id === selectedClientId);

  return (
    <div className="dashboard">
      <header>
        <div className="brand">Mu-Decrypt Engine <span style={{ fontSize: '0.8rem', opacity: 0.6 }}>v2.0 (Multi-Client)</span></div>
        <div className="status-indicator">
          <div className={`dot ${isConnected ? 'connected' : ''}`}></div>
          {isConnected ? 'Sistema en línea' : 'Desconectado'}
        </div>
      </header>

      <div className="sidebar">
        <h3>Clientes Activos</h3>
        <div className="client-selector">
          {activeClients.length === 0 ? (
            <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>Esperando conexiones...</p>
          ) : (
            activeClients.map(id => (
              <div
                key={id}
                className={`client-tab ${selectedClientId === id ? 'active' : ''}`}
                onClick={() => setSelectedClientId(id)}
              >
                {id}
              </div>
            ))
          )}
        </div>

        <h3 style={{ marginTop: '2rem' }}>Control de Inyección</h3>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
          Destino: <strong>{selectedClientId || 'Nadie seleccionado'}</strong>
        </p>

        <div style={{ marginTop: '1rem' }}>
          <label style={{ fontSize: '0.8rem' }}>Canal:</label>
          <div className="input-group">
            <button
              className={injectTarget === 's' ? 'primary' : 'secondary'}
              onClick={() => setInjectTarget('s')}
            >Servidor</button>
            <button
              className={injectTarget === 'c' ? 'primary' : 'secondary'}
              onClick={() => setInjectTarget('c')}
            >Cliente</button>
          </div>
        </div>

        <div className="input-group">
          <input
            type="text"
            placeholder="Payload Hexadecimal"
            value={injectHex}
            disabled={!selectedClientId}
            onChange={(e) => setInjectHex(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
          />
          <button onClick={sendInjection} disabled={!selectedClientId}>Enviar</button>
        </div>

        <div style={{ marginTop: 'auto', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '1rem' }}>
          <h4>Estadísticas Globales</h4>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
            <span>Total Paquetes:</span>
            <span>{packets.length}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
            <span>Clientes:</span>
            <span>{activeClients.length}</span>
          </div>
        </div>
      </div>

      <div className="main-content">
        <div className="packet-list" ref={packetListRef}>
          {!selectedClientId ? (
            <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-dim)' }}>
              Selecciona un cliente para ver el tráfico
            </div>
          ) : filteredPackets.length === 0 ? (
            <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-dim)' }}>
              No hay paquetes para {selectedClientId}
            </div>
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
      </div>
    </div>
  );
}

export default App;
