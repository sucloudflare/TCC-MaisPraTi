// src/pages/Dashboard.jsx
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
    { label: "Labs Concluídos", value: "12/20", icon: Trophy, color: "warning" },
    { label: "Vulneráveis", value: "47", icon: AlertTriangle, color: "danger" },
    { label: "Tempo Total", value: "3h 24m", icon: Clock, color: "info" },
    { label: "Rank", value: "#42", icon: BarChart, color: "success" },
  ];

  const actions = [
    { to: "/labs", label: "Labs", icon: Beaker, bg: "primary" },
    { to: "/vulnerabilities", label: "Scanner", icon: Target, bg: "secondary" },
    { to: "/mfa/setup", label: "MFA", icon: Shield, bg: "success" },
  ];

  return (
    <div className="container py-5">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="text-center mb-5">
        <h1 className="display-5 fw-bold">
          Bem-vindo, <span className="text-primary">{user.username}</span>!
        </h1>
        <p className="lead text-muted">Pronto para caçar bugs?</p>
      </motion.div>

      {!user.mfaEnabled && (
        <div className="alert alert-warning d-flex justify-content-between align-items-center rounded-3 shadow-sm">
          <div className="d-flex align-items-center gap-3">
            <AlertTriangle size={20} />
            <span>Configure MFA para maior segurança</span>
          </div>
          <Link to="/mfa/setup" className="btn btn-sm btn-outline-warning">Ativar</Link>
        </div>
      )}

      <div className="row g-4 mb-5">
        {stats.map((stat, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.1 }}
            className="col-md-3"
          >
            <div className="card h-100 border-0 shadow-sm text-center p-4 rounded-3">
              <stat.icon size={40} className={`text-${stat.color} mb-3`} />
              <h3 className="fw-bold">{stat.value}</h3>
              <p className="text-muted small">{stat.label}</p>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="row g-4">
        {actions.map((action, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="col-md-4"
          >
            <Link to={action.to} className="text-decoration-none">
              <div className={`card h-100 text-white text-center p-5 shadow-lg bg-${action.bg} rounded-3 transition-all hover-scale`}>
                <action.icon size={48} className="mb-3" />
                <h5 className="fw-bold">{action.label}</h5>
              </div>
            </Link>
          </motion.div>
        ))}
      </div>
    </div>
  );
}