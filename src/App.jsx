import React, { useState } from 'react';
import Calculator from './components/Stealth/Calculator';
import AdminPanel from './components/Auth/AdminPanel';
import NetForge from './components/NetForge';
import './App.css';

function App() {
  const [mode, setMode] = useState('calculator'); // calculator, admin, netforge

  const handleUnlock = () => {
    setMode('admin');
  };

  const handleLogin = () => {
    setMode('netforge');
  };

  return (
    <div className="App">
      {mode === 'calculator' && <Calculator onUnlock={handleUnlock} />}
      {mode === 'admin' && <AdminPanel onLogin={handleLogin} />}
      {mode === 'netforge' && <NetForge />}
    </div>
  );
}

export default App;
