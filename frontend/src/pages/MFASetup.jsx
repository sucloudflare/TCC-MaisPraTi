// src/pages/MFA.jsx
import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle, AlertCircle, Key, RefreshCw } from 'lucide-react';
import axios from '../api/axios';

export default function MFA() {
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });
  const [resendCountdown, setResendCountdown] = useState(30);
  const countdownRef = useRef(null);

  const showToast = (msg, type = 'success') => {
    setToast({ show: true, message: msg, type });
    setTimeout(() => setToast({ show: false, message: '', type: 'success' }), 4000);
  };

  useEffect(() => {
    if (resendCountdown > 0) {
      countdownRef.current = setInterval(() => setResendCountdown(prev => prev - 1), 1000);
    } else {
      clearInterval(countdownRef.current);
    }
    return () => clearInterval(countdownRef.current);
  }, [resendCountdown]);

  const handleSubmit = async () => {
    if (!code) return showToast('Digite o código MFA', 'warning');
    setLoading(true);
    try {
      // Ajuste a rota de validação MFA conforme seu backend
      const { data } = await axios.post('/auth/mfa/verify', { code });
      showToast('Código válido! Redirecionando...', 'success');
      setTimeout(() => window.location.href = '/dashboard', 1500);
    } catch (err) {
      showToast(err.response?.data?.message || 'Código inválido', 'danger');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    setResendCountdown(30);
    try {
      await axios.post('/auth/mfa/resend');
      showToast('Código reenviado!', 'success');
    } catch {
      showToast('Erro ao reenviar código', 'danger');
    }
  };

  return (
    <div className="container py-5" style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      {/* Toast */}
      <AnimatePresence>
        {toast.show && (
          <motion.div
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 300, opacity: 0 }}
            className="position-fixed top-0 end-0 p-3"
            style={{ zIndex: 1055 }}
          >
            <div
              className={`alert alert-${toast.type} alert-dismissible fade show d-flex align-items-center gap-2`}
              role="alert"
              style={{ borderRadius: '1rem', fontWeight: 500, border: '1px solid black', background: '#e9ecef' }}
            >
              {toast.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
              <div>{toast.message}</div>
              <button type="button" className="btn-close" onClick={() => setToast({ show: false })}></button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Card MFA */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="card p-4"
        style={{ borderRadius: '1.5rem', border: '1px solid black', background: '#e9ecef', maxWidth: '400px', width: '100%' }}
      >
        <div className="text-center mb-4">
          <h2 className="fw-bold d-flex align-items-center justify-content-center gap-2">
            <Key size={36} /> Autenticação MFA
          </h2>
          <p className="text-muted">Digite o código enviado para seu dispositivo</p>
        </div>

        <div className="mb-3">
          <div className="input-group" style={{ border: '1px solid black', borderRadius: '0.5rem', overflow: 'hidden', background: '#f8f9fa' }}>
            <span className="input-group-text" style={{ border: 'none', background: 'transparent' }}><Key size={18} /></span>
            <input
              type="text"
              className="form-control"
              placeholder="Código MFA"
              value={code}
              onChange={e => setCode(e.target.value)}
              style={{ border: 'none', background: 'transparent' }}
            />
          </div>
        </div>

        <div className="d-grid gap-2 mb-3">
          <button
            className="btn"
            onClick={handleSubmit}
            disabled={loading}
            style={{ border: '1px solid black', background: '#f8f9fa' }}
          >
            {loading ? 'Verificando...' : 'Enviar Código'}
          </button>
        </div>

        <div className="text-center text-muted">
          {resendCountdown > 0 ? (
            <span>Reenviar código em {resendCountdown}s</span>
          ) : (
            <button className="btn btn-link p-0" onClick={handleResend}><RefreshCw size={16} /> Reenviar código</button>
          )}
        </div>
      </motion.div>
    </div>
  );
}
