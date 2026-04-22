import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../services/api';

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user,    setUser]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [token,   setToken]   = useState(() => localStorage.getItem('cl_token'));

  useEffect(() => {
    if (token) {
      api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      api.get('/api/me')
        .then(r => setUser(r.data))
        .catch(() => { localStorage.removeItem('cl_token'); setToken(null); })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, [token]);

  const login = async (username, password) => {
    const { data } = await api.post('/api/login', { username, password });
    localStorage.setItem('cl_token', data.token);
    api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
    setToken(data.token); setUser(data.user);
    return data;
  };

  const register = async (payload) => {
    const { data } = await api.post('/api/register', payload);
    localStorage.setItem('cl_token', data.token);
    api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
    setToken(data.token); setUser(data.user);
    return data;
  };

  const logout = async () => {
    try { await api.post('/api/logout'); } catch {}
    localStorage.removeItem('cl_token');
    delete api.defaults.headers.common['Authorization'];
    setToken(null); setUser(null);
    ['cl_priv_encrypt','cl_priv_sign','cl_priv_ecdh'].forEach(k => sessionStorage.removeItem(k));
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout }}>
      {!loading && children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
