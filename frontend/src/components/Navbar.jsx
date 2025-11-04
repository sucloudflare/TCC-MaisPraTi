// src/components/Navbar.jsx
import { Link, useNavigate } from "react-router-dom";
import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import { motion } from "framer-motion";
import { Shield, Target, Beaker, LogOut, Menu, X, Moon, Sun, User, Bell, Settings } from "lucide-react";

export default function Navbar() {
  const { user, logout } = useAuth();
  const { darkMode, toggleDarkMode } = useTheme();
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
      className={`navbar navbar-expand-lg sticky-top ${darkMode ? 'navbar-dark bg-dark' : 'navbar-light bg-white shadow-sm'}`}
    >
      <div className="container-fluid">
        <Link className={`navbar-brand d-flex align-items-center gap-2 fw-bold ${darkMode ? 'text-white' : 'text-primary'}`} to="/dashboard">
          <Shield size={28} />
          BugBounty TCC
        </Link>

        <div className="d-flex align-items-center gap-2 order-lg-2">
          <button onClick={toggleDarkMode} className="btn btn-sm btn-outline-secondary" title="Alternar tema">
            {darkMode ? <Sun size={18} /> : <Moon size={18} />}
          </button>
          <button className="btn btn-sm btn-outline-secondary position-relative" title="Notificações">
            <Bell size={18} />
            <span className="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">3</span>
          </button>
          <button className="navbar-toggler" onClick={() => setExpanded(!expanded)}>
            {expanded ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>

        <div className={`collapse navbar-collapse ${expanded ? 'show' : ''}`}>
          <ul className="navbar-nav me-auto mt-2 mt-lg-0">
            {navItems.map(({ to, label, icon: Icon }) => (
              <li key={to} className="nav-item">
                <Link className={`nav-link d-flex align-items-center gap-2 ${darkMode ? 'text-white' : 'text-dark'}`} to={to}>
                  <Icon size={18} />
                  {label}
                </Link>
              </li>
            ))}
          </ul>

          <div className="dropdown">
            <button className={`btn dropdown-toggle d-flex align-items-center gap-2 ${darkMode ? 'btn-outline-light' : 'btn-outline-secondary'}`} data-bs-toggle="dropdown">
              <User size={18} />
              <span className="d-none d-md-inline">{user?.username || user?.email}</span>
            </button>
            <ul className={`dropdown-menu dropdown-menu-end ${darkMode ? 'bg-dark border-secondary' : ''}`}>
              <li><Link className="dropdown-item d-flex align-items-center gap-2" to="/profile"><User size={16} /> Perfil</Link></li>
              <li><Link className="dropdown-item d-flex align-items-center gap-2" to="/settings"><Settings size={16} /> Configurações</Link></li>
              <li><hr className="dropdown-divider" /></li>
              <li>
                <button onClick={logout} className="dropdown-item text-danger d-flex align-items-center gap-2">
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