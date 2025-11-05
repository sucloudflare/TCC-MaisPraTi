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
              className={`alert alert-${toast.type} alert-dismissible fade show shadow-lg d-flex align-items-center gap-3 rounded-4 border-0`}
              style={{
                background:
                  toast.type === "success"
                    ? "#38bdf8"
                    : toast.type === "danger"
                    ? "#60a5fa"
                    : toast.type === "warning"
                    ? "#93c5fd"
                    : "#3b82f6",
                color: "white",
              }}
            >
              <Zap size={20} />
              <div className="flex-grow-1 fw-semibold">{toast.message}</div>
              <button className="btn-close btn-close-white" onClick={() => setToast({ show: false })}></button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Fundo + Card */}
      <div
        className="min-vh-100 d-flex align-items-center justify-content-center p-4"
        style={{
          background: "#ffffff", // Fundo branco
          color: "#007bff",      // Azul nos textos
        }}
      >
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          className="w-100"
          style={{ maxWidth: "420px" }}
        >
          <div
            className="card border-0 shadow-lg"
            style={{
              backgroundColor: "#f8f9fa",
              borderRadius: "1.5rem",
              padding: "2rem",
            }}
          >
            <div className="card-body text-center">
              {/* Logo + Título */}
              <motion.div
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", stiffness: 300 }}
                className="d-inline-flex align-items-center justify-content-center p-3 rounded-circle mb-4"
                style={{
                  background: "#dbeafe", // azul claro suave
                  width: "80px",
                  height: "80px",
                  margin: "0 auto",
                }}
              >
                <Shield size={40} style={{ color: "#007bff" }} />
              </motion.div>
              <h2 className="fw-bold mb-2" style={{ color: "#007bff" }}>BugBounty TCC</h2>
              <p style={{ color: "#555555" }}>Login seguro com MFA</p>

              {/* Form */}
              <form onSubmit={handleSubmit} className="mt-4">
                {/* Usuário/Email */}
                <div className="mb-3 text-start">
                  <label className="form-label fw-medium mb-1" style={{ color: "#007bff" }}>Usuário ou Email</label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="usuario ou email@dominio.com"
                    value={usernameOrEmail}
                    onChange={(e) => setUsernameOrEmail(e.target.value)}
                    disabled={loading || mfaRequired}
                    required
                    style={{
                      borderRadius: "0.75rem",
                      border: "1px solid #007bff",
                      backgroundColor: "#ffffff",
                      color: "#007bff",
                      padding: "0.75rem 1rem",
                      fontSize: "1rem",
                      outline: "none",
                    }}
                    onFocus={(e) => e.target.style.boxShadow = "0 0 8px rgba(0,123,255,0.4)"}
                    onBlur={(e) => e.target.style.boxShadow = "none"}
                  />
                </div>

                {/* Senha */}
                {!mfaRequired && (
                  <div className="mb-3 text-start">
                    <label className="form-label fw-medium mb-1" style={{ color: "#007bff" }}>Senha</label>
                    <input
                      type="password"
                      className="form-control"
                      placeholder="••••••••"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={loading}
                      required
                      style={{
                        borderRadius: "0.75rem",
                        border: "1px solid #007bff",
                        backgroundColor: "#ffffff",
                        color: "#007bff",
                        padding: "0.75rem 1rem",
                        fontSize: "1rem",
                        outline: "none",
                      }}
                      onFocus={(e) => e.target.style.boxShadow = "0 0 8px rgba(0,123,255,0.4)"}
                      onBlur={(e) => e.target.style.boxShadow = "none"}
                    />
                  </div>
                )}

                {/* MFA */}
                {mfaRequired && (
                  <div className="mb-3 text-center">
                    <label className="form-label fw-medium mb-2" style={{ color: "#007bff" }}>
                      <Smartphone size={18} style={{ color: "#007bff" }} /> Código MFA
                    </label>
                    <input
                      type="text"
                      className="form-control text-center fw-bold"
                      placeholder="______"
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      maxLength={6}
                      autoFocus
                      style={{
                        letterSpacing: "0.5rem",
                        fontSize: "1.5rem",
                        borderRadius: "0.75rem",
                        border: "1px solid #007bff",
                        padding: "0.5rem",
                        color: "#007bff",
                        backgroundColor: "#ffffff",
                        outline: "none",
                      }}
                      onFocus={(e) => e.target.style.boxShadow = "0 0 8px rgba(0,123,255,0.4)"}
                      onBlur={(e) => e.target.style.boxShadow = "none"}
                    />
                    <small style={{ color: "#555555", display: "block", marginTop: "0.5rem" }}>Abra seu app autenticador</small>
                  </div>
                )}

                {/* Botão */}
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  type="submit"
                  disabled={loading}
                  className="btn w-100 fw-bold"
                  style={{
                    backgroundColor: "#007bff",
                    border: "none",
                    borderRadius: "1rem",
                    height: "52px",
                    color: "#ffffff",
                    marginTop: "1rem",
                  }}
                >
                  {loading ? "Processando..." : mfaRequired ? "Verificar MFA" : "Entrar"}
                </motion.button>

                {/* Links */}
                {!mfaRequired && (
                  <div className="d-flex justify-content-between mt-3 text-sm">
                    <button
                      className="btn btn-link p-0 fw-medium"
                      onClick={() => navigate("/forgot-password")}
                      style={{ color: "#007bff" }}
                    >
                      Esqueci a senha
                    </button>
                    <button
                      className="btn btn-link p-0 fw-medium"
                      onClick={() => navigate("/register")}
                      style={{ color: "#007bff" }}
                    >
                      Criar conta
                    </button>
                  </div>
                )}
              </form>
            </div>
          </div>

          <div className="text-center mt-4 small" style={{ color: "#555555" }}>
            © 2025 BugBounty TCC. Todos os direitos reservados.
          </div>
        </motion.div>
      </div>
    </>
  );
}
