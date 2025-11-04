// src/context/AuthContext.jsx
import { createContext, useContext, useState, useEffect } from "react";
import api from "../api/client";

const AuthContext = createContext();
export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Valida token no carregamento da aplicação
  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      setLoading(false);
      return;
    }

    api.post("/auth/validate")
      .then(res => {
        if (res.data.valid) {
          // Salva username, email e se MFA está habilitado
          setUser({
            username: res.data.username,
            email: res.data.email,
            mfaEnabled: res.data.mfaEnabled || false
          });
        } else {
          localStorage.removeItem("token");
        }
      })
      .catch(() => localStorage.removeItem("token"))
      .finally(() => setLoading(false));
  }, []);

  // Login principal
  const loginUser = async (credentials) => {
    const res = await api.post("/auth/login", credentials);
    const { token, username, email, mfaEnabled } = res.data;

    localStorage.setItem("token", token);
    setUser({ username, email, mfaEnabled: mfaEnabled || false });

    return res.data;
  };

  // Logout
  const logout = () => {
    localStorage.removeItem("token");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, setUser, login: loginUser, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
};
