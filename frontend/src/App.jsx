// src/App.jsx
import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./context/AuthContext";
import Navbar from "./components/Navbar";
import HackerNotifications from "./components/HackerNotifications"; 
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Vulnerabilities from "./pages/Vulnerabilities";
import AdvancedLabs from "./pages/AdvancedLabs";
import MFASetup from "./pages/MFASetup";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Register from "./pages/Register";
import Home from "./pages/Home";
import ProtectedRoute from "./components/ProtectedRoute";
import LoadingSpinner from "./components/LoadingSpinner";

export default function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingSpinner text="Carregando aplicativo..." />;
  }

  return (
    <>
      {/* Navbar + Notificações (apenas se logado) */}
      {user && (
        <>
          <Navbar />
          <HackerNotifications /> {/* ← NOTIFICAÇÕES AUTOMÁTICAS */}
        </>
      )}

      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={user ? <Navigate to="/dashboard" replace /> : <Login />} />
        <Route path="/register" element={user ? <Navigate to="/dashboard" replace /> : <Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />

        {/* Rotas Protegidas */}
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/labs" element={<AdvancedLabs />} />
          <Route path="/mfa/setup" element={<MFASetup />} />
        </Route>

        {/* 404 */}
        <Route path="*" element={<Navigate to={user ? "/dashboard" : "/"} replace />} />
      </Routes>
    </>
  );
}