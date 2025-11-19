// src/components/Navbar.jsx
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { motion } from "framer-motion";
import { Shield, Target, Beaker, LogOut, Menu, X, User, Bell, Settings } from "lucide-react";
import { getReportCount } from "./HackerNotifications"; // ← IMPORTA CONTADOR

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [expanded, setExpanded] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [reportCount, setReportCount] = useState(0); // ← CONTADOR

  // Atualiza contador em tempo real
  useEffect(() => {
    const interval = setInterval(() => {
      setReportCount(getReportCount());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    setDropdownOpen(false);
    setExpanded(false);
  }, [location]);

  useEffect(() => {
    const handleClickOutside = () => setDropdownOpen(false);
    document.addEventListener("click", handleClickOutside);
    return () => document.removeEventListener("click", handleClickOutside);
  }, []);

  const navItems = [
    { to: "/dashboard", label: "Dashboard", icon: Shield },
    { to: "/vulnerabilities", label: "Scanner", icon: Target },
    { to: "/labs", label: "Labs", icon: Beaker },
  ];

  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login", { replace: true });
    } catch (err) {
      console.error("Erro ao fazer logout:", err);
    }
  };

  const sanitizeUsername = (str) => {
    if (!str) return "Usuário";
    return String(str).replace(/[<>&"']/g, "");
  };

  return (
    <motion.nav
      initial={{ y: -100 }}
      animate={{ y: 0 }}
      className="navbar navbar-expand-lg sticky-top"
      style={{
        backgroundColor: "#f8f9fa",
        borderBottom: "1px solid #000",
        padding: "0.5rem 1rem",
        boxShadow: "0 4px 12px rgba(0,0,0,0.1)",
        zIndex: 1050,
      }}
    >
      <div className="container-fluid d-flex align-items-center justify-content-between">

        <Link className="navbar-brand d-flex align-items-center gap-2 fw-bold" to="/dashboard" style={{ color: "#1e293b", fontSize: "1.25rem" }}>
          <Shield size={28} /> BugBounty TCC
        </Link>

        <div className="d-flex align-items-center gap-2 order-lg-2">
          {/* CONTADOR DE REPORTS NA NAVBAR */}
          <button
            className="btn btn-sm position-relative"
            style={{
              background: "#ffffff",
              border: "1px solid #000",
              borderRadius: "0.5rem",
              padding: "0.25rem 0.5rem",
              color: "#1e293b",
            }}
            title="Relatórios automáticos"
          >
            <Bell size={18} />
            <span
              className="position-absolute top-0 start-100 translate-middle badge rounded-pill"
              style={{
                background: reportCount > 0 ? "#ef4444" : "#6b7280",
                color: "#ffffff",
                fontSize: "0.65rem",
                minWidth: "1.4em",
              }}
            >
              {reportCount > 99 ? "99+" : reportCount}
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

          <div className="dropdown" style={{ position: "relative", zIndex: 1060 }}>
            <button
              className="btn d-flex align-items-center gap-2"
              onClick={(e) => { e.stopPropagation(); setDropdownOpen(!dropdownOpen); }}
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
              <span className="d-none d-md-inline">{sanitizeUsername(user?.username || user?.email)}</span>
            </button>

            {dropdownOpen && (
              <motion.ul
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="position-absolute end-0 mt-2 shadow-lg"
                style={{
                  background: "#f8f9fa",
                  border: "1px solid #000",
                  borderRadius: "0.75rem",
                  minWidth: "180px",
                  padding: "0.5rem 0",
                  listStyle: "none",
                  margin: 0,
                  zIndex: 1070,
                }}
              >
                <li><Link className="dropdown-item d-flex align-items-center gap-2" to="/profile" style={{ borderBottom: "1px solid #000" }} onClick={() => setDropdownOpen(false)}><User size={16} /> Perfil</Link></li>
                <li><Link className="dropdown-item d-flex align-items-center gap-2" to="/settings" style={{ borderBottom: "1px solid #000" }} onClick={() => setDropdownOpen(false)}><Settings size={16} /> Configurações</Link></li>
                <li><button onClick={handleLogout} className="dropdown-item text-danger d-flex align-items-center gap-2 w-100 text-start" style={{ borderTop: "1px solid #000", background: "none", border: "none" }}><LogOut size={16} /> Sair</button></li>
              </motion.ul>
            )}
          </div>
        </div>
      </div>
    </motion.nav>
  );
}