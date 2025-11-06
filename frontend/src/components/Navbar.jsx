// src/components/Navbar.jsx
import { Link, useNavigate } from "react-router-dom";
import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { motion } from "framer-motion";
import { Shield, Target, Beaker, LogOut, Menu, X, User, Bell, Settings } from "lucide-react";

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [expanded, setExpanded] = useState(false);

  const navItems = [
    { to: "/dashboard", label: "Dashboard", icon: Shield },
    { to: "/vulnerabilities", label: "Scanner", icon: Target },
    { to: "/labs", label: "Labs", icon: Beaker },
  ];

  return (
    <motion.nav
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      className="navbar navbar-expand-lg sticky-top"
      style={{
        backgroundColor: "#f8f9fa", // fundo branco escuro suave
        borderBottom: "1px solid #000", // borda preta
        padding: "0.5rem 1rem",
        boxShadow: "0 4px 12px rgba(0,0,0,0.1)",
      }}
    >
      <div className="container-fluid d-flex align-items-center justify-content-between">

        {/* Logo */}
        <Link
          className="navbar-brand d-flex align-items-center gap-2 fw-bold"
          to="/dashboard"
          style={{ color: "#1e293b", fontSize: "1.25rem" }}
        >
          <Shield size={28} />
          BugBounty TCC
        </Link>

        {/* Mobile Toggle + Icons */}
        <div className="d-flex align-items-center gap-2 order-lg-2">
          <button
            className="btn btn-sm position-relative"
            style={{
              background: "#ffffff",
              border: "1px solid #000",
              borderRadius: "0.5rem",
              padding: "0.25rem 0.5rem",
              color: "#1e293b",
            }}
            title="Notificações"
          >
            <Bell size={18} />
            <span
              className="position-absolute top-0 start-100 translate-middle badge rounded-pill"
              style={{ background: "#ef4444", color: "#ffffff", fontSize: "0.65rem" }}
            >
              3
            </span>
          </button>

          <button
            className="navbar-toggler"
            onClick={() => setExpanded(!expanded)}
            style={{
              border: "1px solid #000",
              background: "#ffffff",
              borderRadius: "0.5rem",
              padding: "0.25rem 0.5rem",
            }}
          >
            {expanded ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>

        {/* Nav Links */}
        <div className={`collapse navbar-collapse ${expanded ? "show" : ""}`}>
          <ul className="navbar-nav me-auto mt-3 mt-lg-0">
            {navItems.map(({ to, label, icon: Icon }) => (
              <li key={to} className="nav-item">
                <Link
                  className="nav-link d-flex align-items-center gap-2"
                  to={to}
                  style={{
                    color: "#1e293b",
                    fontWeight: 500,
                    transition: "all 0.2s",
                    border: "1px solid #000",
                    borderRadius: "0.5rem",
                    padding: "0.25rem 0.5rem",
                    backgroundColor: "#ffffff",
                    margin: "2px 0",
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.backgroundColor = "#e5e7eb"}
                  onMouseLeave={(e) => e.currentTarget.style.backgroundColor = "#ffffff"}
                >
                  <Icon size={18} />
                  {label}
                </Link>
              </li>
            ))}
          </ul>

          {/* User Dropdown */}
          <div className="dropdown">
            <button
              className="btn d-flex align-items-center gap-2"
              data-bs-toggle="dropdown"
              style={{
                background: "#ffffff",
                color: "#1e293b",
                border: "1px solid #000",
                borderRadius: "0.5rem",
                padding: "0.25rem 0.75rem",
                fontWeight: 500,
                transition: "all 0.2s",
              }}
            >
              <User size={18} />
              <span className="d-none d-md-inline">{user?.username || user?.email}</span>
            </button>
            <ul
              className="dropdown-menu dropdown-menu-end"
              style={{
                background: "#f8f9fa",
                border: "1px solid #000",
                borderRadius: "0.75rem",
                minWidth: "180px",
                padding: "0.5rem 0",
              }}
            >
              <li>
                <Link className="dropdown-item d-flex align-items-center gap-2" to="/profile" style={{ borderBottom: "1px solid #000" }}>
                  <User size={16} /> Perfil
                </Link>
              </li>
              <li>
                <Link className="dropdown-item d-flex align-items-center gap-2" to="/settings" style={{ borderBottom: "1px solid #000" }}>
                  <Settings size={16} /> Configurações
                </Link>
              </li>
              <li>
                <button
                  onClick={logout}
                  className="dropdown-item text-danger d-flex align-items-center gap-2"
                  style={{ borderTop: "1px solid #000" }}
                >
                  <LogOut size={16} /> Sair
                </button>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </motion.nav>
  );
}
