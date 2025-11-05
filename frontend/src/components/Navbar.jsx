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
      className="navbar navbar-expand-lg sticky-top navbar-light"
      style={{
        background: "#ffffff",
        boxShadow: "0 8px 24px rgba(0,0,0,0.06)",
        padding: "0.5rem 1rem",
      }}
    >
      <div className="container-fluid d-flex align-items-center justify-content-between">

        {/* Logo */}
        <Link
          className="navbar-brand d-flex align-items-center gap-2 fw-bold"
          to="/dashboard"
          style={{
            color: "#3b82f6",
            fontSize: "1.25rem",
          }}
        >
          <Shield size={28} />
          BugBounty TCC
        </Link>

        {/* Mobile Toggle + Icons */}
        <div className="d-flex align-items-center gap-2 order-lg-2">

          <button
            className="btn btn-sm position-relative"
            style={{
              background: "#f1f5f9",
              border: "none",
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
              border: "none",
              background: "#f1f5f9",
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
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.color = "#3b82f6"}
                  onMouseLeave={(e) => e.currentTarget.style.color = "#1e293b"}
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
                background: "#f1f5f9",
                color: "#1e293b",
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
                background: "#ffffff",
                border: "1px solid #e2e8f0",
                borderRadius: "0.75rem",
                minWidth: "180px",
                padding: "0.5rem 0",
              }}
            >
              <li>
                <Link className="dropdown-item d-flex align-items-center gap-2" to="/profile">
                  <User size={16} /> Perfil
                </Link>
              </li>
              <li>
                <Link className="dropdown-item d-flex align-items-center gap-2" to="/settings">
                  <Settings size={16} /> Configurações
                </Link>
              </li>
              <li>
                <hr className="dropdown-divider" />
              </li>
              <li>
                <button
                  onClick={logout}
                  className="dropdown-item text-danger d-flex align-items-center gap-2"
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
