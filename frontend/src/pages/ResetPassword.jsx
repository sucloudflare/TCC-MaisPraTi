// src/pages/ResetPassword.jsx
import { useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { resetPassword } from "../api/auth";
import Toast from "../components/Toast";
import { motion, AnimatePresence } from "framer-motion";
import { Lock, CheckCircle } from "lucide-react";

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") || "";
  const [newPassword, setNewPassword] = useState("");
  const [toast, setToast] = useState({ show: false, message: "", type: "success" });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const showToast = (message, type = "success") => {
    setToast({ show: true, message, type });
    setTimeout(() => setToast({ show: false }), 4000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!token || !newPassword) return showToast("Token ou senha inválidos", "danger");
    setLoading(true);
    try {
      const res = await resetPassword(token, newPassword);
      showToast(res.data.message || "Senha redefinida com sucesso!", "success");
      setTimeout(() => navigate("/login"), 2000);
    } catch (err) {
      showToast(err?.response?.data?.error || "Erro ao redefinir", "danger");
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <Toast message="Redefinindo..." type="info" />;

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
                    : "#3b82f6",
                color: "#fff",
                fontWeight: 600,
              }}
            >
              {toast.type === "success" ? <CheckCircle /> : <Lock />}
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
            <Lock size={48} style={{ color: "#0ea5e9", marginBottom: "1rem" }} />
            <h3 className="fw-bold" style={{ color: "#0ea5e9" }}>Redefinir Senha</h3>
          </div>

          <form onSubmit={handleSubmit}>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              placeholder="Nova senha"
              className="form-control text-center fw-semibold mb-3"
              style={{
                borderRadius: "0.75rem",
                border: "1px solid #0ea5e9",
                backgroundColor: "#0f172a",
                color: "#ffffff",
                padding: "0.75rem 1rem",
                boxShadow: "0 0 8px #0ea5e9",
              }}
            />

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
              {loading ? "Redefinindo..." : "Confirmar"}
            </motion.button>
          </form>
        </div>
      </motion.div>
    </>
  );
}
