import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { motion } from "framer-motion";
import { Trophy, AlertTriangle, Clock, BarChart, Shield, Target, Beaker } from "lucide-react";

export default function Dashboard() {
  const { user } = useAuth();
  const navigate = useNavigate();

  if (!user) {
    navigate("/login", { replace: true });
    return null;
  }

  const stats = [
    { label: "Labs Concluídos", value: "12/20", icon: Trophy, color: "#2563eb" },
    { label: "Vulneráveis", value: "47", icon: AlertTriangle, color: "#dc2626" },
    { label: "Tempo Total", value: "3h 24m", icon: Clock, color: "#2563eb" },
    { label: "Rank", value: "#42", icon: BarChart, color: "#2563eb" },
  ];

  const actions = [
    { to: "/labs", label: "Labs", icon: Beaker, bg: "bg-primary", text: "text-white" },
    { to: "/vulnerabilities", label: "Scanner", icon: Target, bg: "bg-success", text: "text-white" },
    { to: "/mfa/setup", label: "MFA", icon: Shield, bg: "bg-info", text: "text-white" },
  ];

  return (
    <div className="min-vh-100 bg-light">
      <div className="container py-5">
        {/* Header Limpo e Profissional */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="text-center mb-5"
        >
          <h1 className="display-5 fw-bold text-primary mb-2">
            Bem-vindo, <span className="text-primary">{user.username}</span>!
          </h1>
          <p className="lead text-muted">Pronto para caçar bugs com segurança e precisão?</p>
        </motion.div>

        {/* MFA Alert - Acessível e Discreto */}
        {!user.mfaEnabled && (
          <motion.div
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
            className="alert alert-warning d-flex justify-content-between align-items-center rounded-4 shadow-sm p-4 mb-5 border-0"
            role="alert"
          >
            <div className="d-flex align-items-center gap-3">
              <AlertTriangle size={24} className="text-warning" />
              <div>
                <strong>Segurança reforçada:</strong> Configure a autenticação de dois fatores (MFA)
              </div>
            </div>
            <Link
              to="/mfa/setup"
              className="btn btn-warning text-dark fw-semibold px-4 rounded-pill"
              style={{ minWidth: '120px' }}
            >
              Ativar MFA
            </Link>
          </motion.div>
        )}

        {/* Stats - Cards Brancos com Ícones e Cores Acessíveis */}
        <div className="row g-4 mb-5">
          {stats.map((stat, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.1, type: "spring", stiffness: 120 }}
              className="col-md-6 col-lg-3"
            >
              <div
                className="card h-100 border-0 shadow-sm rounded-4 text-center p-4 bg-white"
                style={{
                  transition: "transform 0.2s, box-shadow 0.2s",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = "translateY(-4px)";
                  e.currentTarget.style.boxShadow = "0 10px 25px rgba(0,0,0,0.1)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = "translateY(0)";
                  e.currentTarget.style.boxShadow = "0 4px 12px rgba(0,0,0,0.05)";
                }}
              >
                <div className="d-flex justify-content-center mb-3">
                  <div
                    className="p-3 rounded-circle d-flex align-items-center justify-content-center"
                    style={{
                      backgroundColor: stat.color === "#dc2626" ? "rgba(220, 38, 38, 0.1)" : "rgba(37, 99, 235, 0.1)",
                      color: stat.color,
                      width: "64px",
                      height: "64px",
                    }}
                  >
                    <stat.icon size={32} />
                  </div>
                </div>
                <h3 className="fw-bold fs-2 text-dark mb-1">{stat.value}</h3>
                <p className="text-muted small mb-0">{stat.label}</p>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Ações - Cards com Cores Bootstrap e Ícones Claros */}
        <div className="row g-4">
          {actions.map((action, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 + 0.3 }}
              className="col-md-6 col-lg-4"
            >
              <Link to={action.to} className="text-decoration-none h-100">
                <div
                  className={`card h-100 border-0 shadow-sm rounded-4 text-center p-5 d-flex flex-column justify-content-center align-items-center ${action.bg} ${action.text}`}
                  style={{
                    transition: "transform 0.2s, box-shadow 0.2s",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.transform = "translateY(-6px)";
                    e.currentTarget.style.boxShadow = "0 16px 32px rgba(0,0,0,0.15)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.transform = "translateY(0)";
                    e.currentTarget.style.boxShadow = "0 6px 16px rgba(0,0,0,0.1)";
                  }}
                >
                  <action.icon size={56} className="mb-3" />
                  <h5 className="fw-bold fs-4 mb-0">{action.label}</h5>
                </div>
              </Link>
            </motion.div>
          ))}
        </div>

        {/* Footer Decorativo (opcional) */}
        <div className="text-center mt-5 pt-4">
          <p className="text-muted small">
            Plataforma de Bug Bounty • Segurança • Aprendizado
          </p>
        </div>
      </div>
    </div>
  );
}