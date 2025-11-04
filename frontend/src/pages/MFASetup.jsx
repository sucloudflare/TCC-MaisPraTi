// src/pages/MFASetup.jsx
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { setupMfa } from "../api/auth";

// CORREÇÃO: Importação nomeada (qrcode.react v1+ usa export named)
import { QRCodeCanvas } from "qrcode.react";

import Toast from "../components/Toast";
import LoadingSpinner from "../components/LoadingSpinner";
import { motion } from "framer-motion";
import { Shield, Copy, Check } from "lucide-react";

export default function MFASetup() {
  const [qrCodeUrl, setQrCodeUrl] = useState("");
  const [secret, setSecret] = useState("");
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState({ show: false, message: "", type: "info" });
  const [copied, setCopied] = useState(false);

  const { user } = useAuth();
  const navigate = useNavigate();

  const showToast = (msg, type = "info") => {
    setToast({ show: true, message: msg, type });
    setTimeout(() => setToast({ show: false, message: "", type: "info" }), 4000);
  };

  const handleSetup = async () => {
    if (!user?.username) return showToast("Usuário não encontrado", "danger");
    setLoading(true);
    try {
      const res = await setupMfa(user.username);
      setQrCodeUrl(res.data.otpAuthUrl);
      setSecret(res.data.secret);
      showToast("QR Code gerado! Escaneie com seu app.", "success");
    } catch (err) {
      showToast(err.response?.data?.error || "Erro ao configurar MFA", "danger");
    } finally {
      setLoading(false);
    }
  };

  const copySecret = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      showToast("Falha ao copiar", "danger");
    }
  };

  if (loading) return <LoadingSpinner text="Gerando QR Code..." />;

  return (
    <>
      {toast.show && <Toast message={toast.message} type={toast.type} onClose={() => setToast({ show: false })} />}

      <div className="container py-5">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="row justify-content-center"
        >
          <div className="col-lg-6">
            <div className="card border-0 shadow-lg rounded-3 overflow-hidden">
              <div
                className="card-header bg-gradient text-white text-center py-4"
                style={{
                  background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
                }}
              >
                <Shield size={36} className="mb-2" />
                <h3 className="fw-bold mb-0">Configurar Autenticação de Dois Fatores</h3>
              </div>

              <div className="card-body p-5 text-center">
                {!qrCodeUrl ? (
                  <motion.div initial={{ scale: 0.9 }} animate={{ scale: 1 }}>
                    <p className="text-muted mb-4">Proteja sua conta com MFA</p>
                    <button
                      onClick={handleSetup}
                      className="btn btn-primary btn-lg rounded-pill px-5 d-flex align-items-center gap-2 mx-auto"
                    >
                      <Shield size={20} /> Iniciar Configuração
                    </button>
                  </motion.div>
                ) : (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ type: "spring" }}
                  >
                    <div className="bg-white p-4 rounded-3 shadow-sm d-inline-block mb-4">
                      <QRCodeCanvas
                        value={qrCodeUrl}
                        size={220}
                        level="H"
                        includeMargin
                        className="rounded"
                      />
                    </div>

                    <div className="bg-light p-3 rounded-3 mb-4">
                      <p className="small text-muted mb-2">
                        <strong>Chave secreta (backup):</strong>
                      </p>
                      <div className="d-flex align-items-center gap-2 justify-content-center">
                        <code className="bg-white px-3 py-2 rounded font-monospace text-break">
                          {secret}
                        </code>
                        <button
                          onClick={copySecret}
                          className="btn btn-sm btn-outline-secondary"
                          title="Copiar chave"
                        >
                          {copied ? (
                            <Check size={16} className="text-success" />
                          ) : (
                            <Copy size={16} />
                          )}
                        </button>
                      </div>
                    </div>

                    <button
                      onClick={() => navigate("/dashboard")}
                      className="btn btn-success btn-lg rounded-pill px-5 d-flex align-items-center gap-2 mx-auto"
                    >
                      <Check size={20} /> Concluído
                    </button>
                  </motion.div>
                )}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </>
  );
}