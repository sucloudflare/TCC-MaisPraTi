// src/pages/Login.jsx
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { login, verifyMfa } from "../api/auth";
import Toast from "../components/Toast";
import LoadingSpinner from "../components/LoadingSpinner";
import { motion, AnimatePresence } from "framer-motion";
import { Lock, Mail, Smartphone, Shield, Zap } from "lucide-react";

export default function Login() {
  const [usernameOrEmail, setUsernameOrEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState({ show: false, message: "", type: "danger" });
  const [loginData, setLoginData] = useState(null);

  const navigate = useNavigate();
  const authContext = useAuth();
  const setUser = authContext?.setUser;
  const user = authContext?.user;

  useEffect(() => {
    if (user) navigate("/dashboard");
  }, [user, navigate]);

  const showToast = (msg, type = "danger") => {
    setToast({ show: true, message: msg, type });
    setTimeout(() => setToast({ show: false, message: "", type: "danger" }), 4000);
  };

  const finalizeLogin = (data) => {
    const { token, username, email } = data;
    localStorage.setItem("token", token);
    setUser && setUser({ username, email });
    showToast("Login bem-sucedido!", "success");
    setTimeout(() => navigate("/dashboard"), 600);
  };

  const handleLogin = async () => {
    if (!usernameOrEmail || !password) return showToast("Preencha todos os campos", "warning");
    setLoading(true);
    try {
      const res = await login({ usernameOrEmail, password });
      if (res.data.mfaRequired) {
        setLoginData(res.data);
        setMfaRequired(true);
        setPassword("");
        showToast("Digite o código MFA de 6 dígitos", "info");
        return;
      }
      finalizeLogin(res.data);
    } catch (err) {
      showToast(err.response?.data?.error || "Credenciais inválidas");
    } finally {
      setLoading(false);
    }
  };

  const handleMfa = async () => {
    if (!mfaCode || mfaCode.length !== 6) return showToast("Código deve ter 6 dígitos", "warning");
    if (!loginData) return showToast("Erro interno. Tente novamente.");
    setLoading(true);
    try {
      const username = loginData.username || loginData.email;
      const res = await verifyMfa(username, mfaCode);
      finalizeLogin(res.data);
    } catch (err) {
      showToast(err.response?.data?.error || "Código MFA inválido");
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    mfaRequired ? handleMfa() : handleLogin();
  };

  if (loading) return <LoadingSpinner text="Autenticando..." />;

  return (
    <>
      {/* Toast */}
      <AnimatePresence>
        {toast.show && (
          <motion.div
            initial={{ x: 100, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 100, opacity: 0 }}
            className="position-fixed top-0 end-0 p-3"
            style={{ zIndex: 9999 }}
          >
            <div
              className={`alert alert-${toast.type} d-flex align-items-center gap-3 rounded-3 shadow-lg border-0`}
              style={{
                background:
                  toast.type === "success"
                    ? "#22c55e"
                    : toast.type === "danger"
                    ? "#ef4444"
                    : toast.type === "warning"
                    ? "#f59e0b"
                    : "#3b82f6",
                color: "#fff",
                fontWeight: 600,
              }}
            >
              <Zap size={20} />
              <div className="flex-grow-1">{toast.message}</div>
              <button className="btn-close btn-close-white" onClick={() => setToast({ show: false })}></button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Fundo + Card */}
      <div
        className="min-vh-100 d-flex align-items-center justify-content-center p-4"
        style={{ backgroundColor: "#0f172a", color: "#ffffff" }}
      >
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          className="w-100"
          style={{ maxWidth: "420px" }}
        >
          <div
            className="card shadow-lg border border-black"
            style={{
              backgroundColor: "#1e293b",
              borderRadius: "1.5rem",
              padding: "2rem",
              color: "#ffffff",
            }}
          >
            {/* Logo + Título */}
            <div className="text-center mb-4">
              <motion.div
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", stiffness: 300 }}
                className="d-inline-flex align-items-center justify-content-center p-3 rounded-circle mb-3"
                style={{ background: "#0ea5e9", width: "80px", height: "80px" }}
              >
                <Shield size={40} style={{ color: "#0f172a" }} />
              </motion.div>
              <h2 className="fw-bold mb-2" style={{ color: "#0ea5e9" }}>BugBounty TCC</h2>
              <p style={{ color: "#cbd5e1" }}>Login seguro com MFA</p>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="mt-3">
              <div className="mb-3">
                <label className="form-label fw-semibold">Usuário ou Email</label>
                <input
                  type="text"
                  value={usernameOrEmail}
                  onChange={(e) => setUsernameOrEmail(e.target.value)}
                  disabled={loading || mfaRequired}
                  className="form-control"
                  placeholder="usuario ou email@dominio.com"
                  style={{
                    borderRadius: "0.75rem",
                    border: "1px solid #0ea5e9",
                    backgroundColor: "#0f172a",
                    color: "#ffffff",
                    padding: "0.75rem 1rem",
                    boxShadow: "0 0 8px #0ea5e9",
                  }}
                />
              </div>

              {!mfaRequired && (
                <div className="mb-3">
                  <label className="form-label fw-semibold">Senha</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={loading}
                    className="form-control"
                    placeholder="••••••••"
                    style={{
                      borderRadius: "0.75rem",
                      border: "1px solid #0ea5e9",
                      backgroundColor: "#0f172a",
                      color: "#ffffff",
                      padding: "0.75rem 1rem",
                      boxShadow: "0 0 8px #0ea5e9",
                    }}
                  />
                </div>
              )}

              {mfaRequired && (
                <div className="mb-3 text-center">
                  <label className="form-label fw-semibold">
                    <Smartphone size={18} /> Código MFA
                  </label>
                  <input
                    type="text"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    maxLength={6}
                    autoFocus
                    className="form-control text-center fw-bold"
                    style={{
                      letterSpacing: "0.5rem",
                      fontSize: "1.5rem",
                      borderRadius: "0.75rem",
                      border: "1px solid #0ea5e9",
                      padding: "0.5rem",
                      backgroundColor: "#0f172a",
                      color: "#ffffff",
                      boxShadow: "0 0 8px #0ea5e9",
                    }}
                  />
                  <small className="d-block mt-1" style={{ color: "#cbd5e1" }}>Abra seu app autenticador</small>
                </div>
              )}

              <motion.button
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                type="submit"
                disabled={loading}
                className="btn w-100 fw-bold"
                style={{
                  backgroundColor: "#0ea5e9",
                  border: "none",
                  borderRadius: "1rem",
                  height: "52px",
                  color: "#0f172a",
                  marginTop: "1rem",
                }}
              >
                {loading ? "Processando..." : mfaRequired ? "Verificar MFA" : "Entrar"}
              </motion.button>

              {!mfaRequired && (
                <div className="d-flex justify-content-between mt-3 small">
                  <button className="btn btn-link text-info p-0" onClick={() => navigate("/forgot-password")}>Esqueci a senha</button>
                  <button className="btn btn-link text-info p-0" onClick={() => navigate("/register")}>Criar conta</button>
                </div>
              )}
            </form>

            <div className="text-center mt-4 small" style={{ color: "#94a3b8" }}>
              © 2025 BugBounty TCC. Todos os direitos reservados.
            </div>
          </div>
        </motion.div>
      </div>
    </>
  );
}
