// src/pages/ResetPassword.jsx
import { useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { resetPassword } from "../api/auth";
import Toast from "../components/Toast";
import { motion } from "framer-motion";
import { Lock, CheckCircle } from "lucide-react";

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") || "";
  const [newPassword, setNewPassword] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!token || !newPassword) return setMessage("Token ou senha inválidos");
    setLoading(true);
    try {
      const res = await resetPassword(token, newPassword);
      setMessage(res.data.message || "Senha redefinida com sucesso!");
      setTimeout(() => navigate("/login"), 2000);
    } catch (err) {
      setMessage(err?.response?.data?.error || "Erro ao redefinir");
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="min-vh-100 d-flex align-items-center justify-content-center bg-light p-3"
    >
      <div className="card border-0 shadow-lg p-5" style={{ maxWidth: "420px", width: "100%", borderRadius: "1.5rem" }}>
        <div className="text-center mb-4">
          <Lock size={48} className="text-primary mb-3" />
          <h3 className="fw-bold">Redefinir Senha</h3>
        </div>

        {message && (
          <div className={`alert alert-${message.includes("sucesso") ? "success" : "danger"} d-flex align-items-center gap-2`}>
            {message.includes("sucesso") ? <CheckCircle /> : <AlertCircle />}
            {message}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <input
            type="password"
            className="form-control form-control-lg rounded-pill mb-3 text-center"
            placeholder="Nova senha"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            minLength={6}
          />
          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary btn-lg w-100 rounded-pill d-flex align-items-center justify-content-center gap-2"
          >
            {loading ? (
              <>
                <div className="spinner-border spinner-border-sm" role="status"></div> Redefinindo...
              </>
            ) : (
              <>
                <Lock size={18} /> Confirmar
              </>
            )}
          </button>
        </form>
      </div>
    </motion.div>
  );
}