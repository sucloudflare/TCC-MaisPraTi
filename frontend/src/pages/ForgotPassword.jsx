// src/pages/ForgotPassword.jsx
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Toast from "../components/Toast";
import LoadingSpinner from "../components/LoadingSpinner";
import { motion, AnimatePresence } from "framer-motion";
import { Mail, ArrowLeft } from "lucide-react";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState({ show: false, message: "", type: "success" });
  const navigate = useNavigate();

  const showToast = (message, type = "success") => {
    setToast({ show: true, message, type });
    setTimeout(() => setToast({ show: false }), 4000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email) return showToast("Digite seu e-mail", "warning");
    setLoading(true);
    try {
      await new Promise(r => setTimeout(r, 1200)); // Simulação
      showToast(`Link de recuperação enviado para ${email}`, "success");
      setTimeout(() => navigate("/login"), 2000);
    } catch {
      showToast("Erro ao enviar e-mail", "danger");
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <LoadingSpinner text="Enviando link..." />;

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
              <Mail size={20} />
              <div className="flex-grow-1">{toast.message}</div>
              <button className="btn-close btn-close-white" onClick={() => setToast({ show: false })}></button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Fundo + Card */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="min-vh-100 d-flex align-items-center justify-content-center p-4"
        style={{ backgroundColor: "#0f172a" }}
      >
        <div
          className="card shadow-lg border-0"
          style={{
            maxWidth: "420px",
            width: "100%",
            borderRadius: "1.5rem",
            backgroundColor: "#1e293b",
            padding: "2rem",
            color: "#fff",
          }}
        >
          <div className="text-center mb-4">
            <Mail size={48} style={{ color: "#0ea5e9", marginBottom: "1rem" }} />
            <h3 className="fw-bold" style={{ color: "#0ea5e9" }}>Recuperar Senha</h3>
            <p style={{ color: "#cbd5e1" }}>Enviaremos um link para seu e-mail</p>
          </div>

          <form onSubmit={handleSubmit}>
            <div className="mb-4">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                placeholder="seu@email.com"
                className="form-control text-center fw-semibold"
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
              }}
            >
              {loading ? "Enviando..." : "Enviar Link"}
            </motion.button>
          </form>

          <div className="text-center mt-4">
            <Link to="/login" style={{ color: "#cbd5e1", textDecoration: "none" }} className="d-flex align-items-center justify-content-center gap-1">
              <ArrowLeft size={16} /> Voltar ao login
            </Link>
          </div>
        </div>
      </motion.div>
    </>
  );
}
