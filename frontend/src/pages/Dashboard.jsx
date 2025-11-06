// src/pages/Dashboard.jsx
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { motion } from "framer-motion";
import {
  Trophy,
  AlertTriangle,
  Clock,
  BarChart,
  Shield,
  Target,
  Beaker,
  BookOpen,
} from "lucide-react";

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
    { to: "/labs", label: "Labs", icon: Beaker, bg: "#2563eb", text: "#ffffff" },
    { to: "/vulnerabilities", label: "Scanner", icon: Target, bg: "#10b981", text: "#ffffff" },
    { to: "/mfa/setup", label: "MFA", icon: Shield, bg: "#3b82f6", text: "#ffffff" },
  ];

  const tutorials = [
    {
      id: 1,
      label: "Scanner",
      color: "#f59e0b",
      icon: BookOpen,
      children: [
        { id: 11, label: "Escolher URL", color: "#f59e0b", desc: "Digite a URL para teste." },
        { id: 12, label: "Selecionar Tipo", color: "#f59e0b", desc: "Escolha teste SSRF, XXE, SQLi..." },
      ],
    },
    {
      id: 2,
      label: "Labs",
      color: "#2563eb",
      icon: Beaker,
      children: [
        { id: 21, label: "Iniciar Lab", color: "#2563eb", desc: "Clique para começar." },
        { id: 22, label: "Submissão", color: "#2563eb", desc: "Envie vulnerabilidades." },
      ],
    },
    {
      id: 3,
      label: "MFA",
      color: "#dc2626",
      icon: Shield,
      children: [
        { id: 31, label: "Ativar MFA", color: "#dc2626", desc: "Siga instruções para segurança." },
      ],
    },
  ];

  const [expanded, setExpanded] = useState({});

  const toggle = (id) => setExpanded(prev => ({ ...prev, [id]: !prev[id] }));

  function NodeCard({ node }) {
    const Icon = node.icon || BookOpen;
    return (
      <motion.div
        layout
        whileHover={{ scale: 1.05, boxShadow: `0 10px 25px ${node.color}66` }}
        style={{
          minWidth: 220,
          maxWidth: 260,
          cursor: "pointer",
          borderRadius: 12,
          padding: "16px",
          backgroundColor: "#f8f9fa",
          border: "1px solid #000",
          color: "#000",
          display: "flex",
          flexDirection: "column",
          gap: 6,
        }}
        onClick={() => toggle(node.id)}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Icon size={20} color={node.color} />
          <strong>{node.label}</strong>
        </div>
        {node.desc && <div style={{ fontSize: 13, color: "#6b7280", marginTop: 4 }}>{node.desc}</div>}
        {node.children && (
          <small style={{ marginTop: 6, color: "#374151" }}>
            {expanded[node.id] ? "Clique para fechar" : "Clique para expandir"}
          </small>
        )}
      </motion.div>
    );
  }

  function HorizontalTree({ nodes }) {
    return (
      <div style={{ display: "flex", gap: 24, overflowX: "auto", padding: 12 }}>
        {nodes.map(node => (
          <div key={node.id} style={{ display: "flex", flexDirection: "column", gap: 18 }}>
            <NodeCard node={node} />
            {node.children && expanded[node.id] && (
              <div style={{ display: "flex", gap: 18, marginTop: 12 }}>
                {node.children.map(child => <NodeCard key={child.id} node={child} />)}
              </div>
            )}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div style={{ minHeight: "100vh", backgroundColor: "#f1f3f5", padding: "40px 0" }}>
      <div className="container">
        <h1 className="mb-4 text-dark">Bem-vindo, {user.username}!</h1>

        {/* Stats */}
        <div className="row g-4 mb-5">
          {stats.map((s, i) => (
            <div key={i} className="col-md-6 col-lg-3">
              <div style={{
                borderRadius: 14,
                padding: "20px",
                backgroundColor: "#ffffff",
                border: "1px solid #000",
                textAlign: "center",
                boxShadow: "0 4px 12px rgba(0,0,0,0.1)",
              }}>
                <div style={{
                  width: 60,
                  height: 60,
                  borderRadius: 999,
                  backgroundColor: s.color + "33",
                  margin: "0 auto 10px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: s.color,
                }}>
                  <s.icon size={28} />
                </div>
                <h3 style={{ margin: 0, fontWeight: 700 }}>{s.value}</h3>
                <p style={{ margin: 0, color: "#6b7280" }}>{s.label}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Actions */}
        <div className="row g-4 mb-5">
          {actions.map((a, i) => (
            <div key={i} className="col-md-6 col-lg-4">
              <Link to={a.to} style={{ textDecoration: "none" }}>
                <div style={{
                  borderRadius: 14,
                  padding: "28px 0",
                  backgroundColor: a.bg,
                  color: a.text,
                  textAlign: "center",
                  boxShadow: "0 4px 15px rgba(0,0,0,0.15)",
                  transition: "transform 0.2s",
                }} className="d-flex flex-column align-items-center justify-content-center">
                  <a.icon size={40} className="mb-2" />
                  <h5>{a.label}</h5>
                </div>
              </Link>
            </div>
          ))}
        </div>

        {/* Tutoriais */}
        <h4 className="mb-3 text-dark">Tutoriais</h4>
        <HorizontalTree nodes={tutorials} />
      </div>
    </div>
  );
}
