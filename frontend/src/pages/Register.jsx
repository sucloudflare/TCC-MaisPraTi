// src/pages/Register.jsx
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { register, verifyMfa } from "../api/auth";
import Toast from "../components/Toast";
import LoadingSpinner from "../components/LoadingSpinner";
import { motion, AnimatePresence } from "framer-motion";
import { Mail, Lock, User, Smartphone, Shield, CheckCircle } from "lucide-react";

export default function Register() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState({ show: false, message: "", type: "danger" });
  const [registerData, setRegisterData] = useState(null);

  const navigate = useNavigate();
  const authContext = useAuth();
  const user = authContext?.user;

  useEffect(() => {
    if (user) navigate("/dashboard");
  }, [user, navigate]);

  const showToast = (msg, type = "danger") => {
    setToast({ show: true, message: msg, type });
    setTimeout(() => setToast({ show: false, message: "", type: "danger" }), 4000);
  };

  const finalizeRegister = (data) => {
    const { token, username, email } = data;
    localStorage.setItem("token", token);
    authContext?.setUser({ username, email });
    showToast("Conta criada com sucesso!", "success");
    setTimeout(() => navigate("/dashboard"), 600);
  };

  const handleRegister = async () => {
    if (!username || !email || !password || !confirmPassword)
      return showToast("Preencha todos os campos", "warning");
    if (password !== confirmPassword) return showToast("As senhas não coincidem", "warning");
    if (password.length < 8) return showToast("A senha deve ter pelo menos 8 caracteres", "warning");

    setLoading(true);
    try {
      const res = await register({ username, email, password });
      if (res.data.mfaRequired) {
        setRegisterData(res.data);
        setMfaRequired(true);
        setPassword("");
        setConfirmPassword("");
        showToast("Digite o código MFA de 6 dígitos", "info");
        return;
      }
      finalizeRegister(res.data);
    } catch (err) {
      showToast(err.response?.data?.error || "Erro ao criar conta");
    } finally {
      setLoading(false);
    }
  };

  const handleMfa = async () => {
    if (!mfaCode || mfaCode.length !== 6) return showToast("Código deve ter 6 dígitos", "warning");
    if (!registerData) return showToast("Erro interno. Tente novamente.");
    setLoading(true);
    try {
      const res = await verifyMfa(registerData.username || registerData.email, mfaCode);
      finalizeRegister(res.data);
    } catch (err) {
      showToast(err.response?.data?.error || "Código MFA inválido");
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    mfaRequired ? handleMfa() : handleRegister();
  };

  if (loading) return <LoadingSpinner text="Criando conta..." />;

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
              className={`alert d-flex align-items-center gap-3 rounded-3 shadow-lg border-0`}
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
              <CheckCircle size={20} />
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
          style={{ maxWidth: "460px" }}
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
            <div className="text-center mb-5">
              <motion.div
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", stiffness: 300 }}
                className="d-inline-flex align-items-center justify-content-center p-3 rounded-circle mb-4"
                style={{ background: "#0ea5e9", width: "80px", height: "80px" }}
              >
                <Shield size={40} style={{ color: "#0f172a" }} />
              </motion.div>
              <h2 className="fw-bold mb-2" style={{ color: "#0ea5e9" }}>Criar Conta</h2>
              <p style={{ color: "#cbd5e1" }}>Cadastre-se com segurança e MFA</p>
            </div>

            <form onSubmit={handleSubmit}>
              {/* Usuário */}
              <div className="mb-3">
                <label className="form-label fw-semibold">Usuário</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={loading || mfaRequired}
                  className="form-control"
                  placeholder="seu_usuario"
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

              {/* Email */}
              <div className="mb-3">
                <label className="form-label fw-semibold">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={loading || mfaRequired}
                  className="form-control"
                  placeholder="seu@email.com"
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

              {/* Senha */}
              {!mfaRequired && (
                <>
                  <div className="mb-3">
                    <label className="form-label fw-semibold">Senha</label>
                    <input
                      type={showPassword ? "text" : "password"}
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

                  <div className="mb-3">
                    <label className="form-label fw-semibold">Confirmar Senha</label>
                    <input
                      type={showConfirmPassword ? "text" : "password"}
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
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
                </>
              )}

              {/* MFA */}
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
                      backgroundColor: "#0f172a",
                      color: "#ffffff",
                      padding: "0.5rem",
                      boxShadow: "0 0 8px #0ea5e9",
                    }}
                  />
                  <small className="d-block mt-2" style={{ color: "#cbd5e1" }}>Abra seu app autenticador</small>
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
                  backgroundColor: "#0ea5e9",
                  border: "none",
                  borderRadius: "1rem",
                  height: "52px",
                  color: "#0f172a",
                  marginTop: "1rem",
                }}
              >
                {loading ? "Processando..." : mfaRequired ? "Verificar MFA" : "Criar Conta"}
              </motion.button>

              {!mfaRequired && (
                <div className="text-center mt-3 small">
                  <p style={{ color: "#cbd5e1", margin: 0 }}>
                    Já tem conta?{' '}
                    <button
                      className="btn btn-link p-0"
                      onClick={() => navigate("/login")}
                      style={{ color: "#0ea5e9" }}
                    >
                      Faça login
                    </button>
                  </p>
                </div>
              )}
            </form>
          </div>

          {/* Footer */}
          <div className="text-center mt-4 small" style={{ color: "#94a3b8" }}>
            © 2025 BugBounty TCC. Todos os direitos reservados.
          </div>
        </motion.div>
      </div>
    </>
  );
}
