// src/pages/ForgotPassword.jsx
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Toast from "../components/Toast";
import LoadingSpinner from "../components/LoadingSpinner";
import { motion } from "framer-motion";
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
      {toast.show && <Toast message={toast.message} type={toast.type} onClose={() => setToast({ show: false })} />}

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="min-vh-100 d-flex align-items-center justify-content-center bg-light p-3"
      >
        <div className="card border-0 shadow-lg" style={{ maxWidth: "420px", width: "100%", borderRadius: "1.5rem" }}>
          <div className="card-body p-5">
            <div className="text-center mb-4">
              <Mail size={48} className="text-warning mb-3" />
              <h3 className="fw-bold text-warning">Recuperar Senha</h3>
              <p className="text-muted">Enviaremos um link para seu e-mail</p>
            </div>

            <form onSubmit={handleSubmit}>
              <div className="mb-4">
                <input
                  type="email"
                  className="form-control form-control-lg rounded-pill text-center"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  placeholder="seu@email.com"
                />
              </div>

              <button
                type="submit"
                className="btn btn-warning btn-lg w-100 rounded-pill d-flex align-items-center justify-content-center gap-2 fw-bold"
              >
                <Mail size={20} /> Enviar Link
              </button>
            </form>

            <div className="text-center mt-4">
              <Link to="/login" className="text-decoration-none d-flex align-items-center justify-content-center gap-1 text-muted">
                <ArrowLeft size={16} /> Voltar ao login
              </Link>
            </div>
          </div>
        </div>
      </motion.div>
    </>
  );
}