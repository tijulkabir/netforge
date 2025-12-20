import React, { useState, useEffect } from 'react';
import './AdminPanel.css';
import { Lock, User, Key, Database, ChevronRight } from 'lucide-react';

const AdminPanel = ({ onLogin }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [isRegistering, setIsRegistering] = useState(false);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        const output = localStorage.getItem('netforge_creds');
        if (!output) {
            setIsRegistering(true);
        }
    }, []);

    const handleSubmit = (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        setTimeout(() => {
            const stored = localStorage.getItem('netforge_creds');

            if (isRegistering) {
                if (username.length < 3 || password.length < 3) {
                    setError('Credentials too weak.');
                    setLoading(false);
                    return;
                }
                localStorage.setItem('netforge_creds', JSON.stringify({ username, password }));
                // Auto login after reg
                onLogin();
            } else {
                if (!stored) {
                    setError('Database corruption. Resetting...');
                    setIsRegistering(true);
                    setLoading(false);
                    return;
                }
                const creds = JSON.parse(stored);
                if (username === creds.username && password === creds.password) {
                    onLogin();
                } else {
                    setError('ACCESS DENIED');
                }
            }
            setLoading(false);
        }, 800); // Fake delay for "industry grade" feel
    };

    return (
        <div className="auth-container">
            <div className="auth-box">
                <div className="auth-header">
                    <Database className="auth-icon" size={48} />
                    <h1>{isRegistering ? 'SYSTEM INITIALIZATION' : 'SECURE LOGIN'}</h1>
                    <p>{isRegistering ? 'Create Root Access Credentials' : 'Authentication Required'}</p>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="input-group">
                        <User className="input-icon" />
                        <input
                            type="text"
                            placeholder="IDENTITY"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            autoFocus
                        />
                    </div>
                    <div className="input-group">
                        <Key className="input-icon" />
                        <input
                            type="password"
                            placeholder="ACCESS KEY"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                        />
                    </div>

                    {error && <div className="error-msg">{error}</div>}

                    <button type="submit" disabled={loading} className={loading ? 'loading' : ''}>
                        {loading ? 'VERIFYING...' : (isRegistering ? 'INITIALIZE SYSTEM' : 'AUTHENTICATE')}
                        {!loading && <ChevronRight size={16} />}
                    </button>
                </form>

                <div className="auth-footer">
                    <Lock size={12} /> ENCRYPTED CONNECTION ESTABLISHED
                </div>
            </div>
        </div>
    );
};

export default AdminPanel;
