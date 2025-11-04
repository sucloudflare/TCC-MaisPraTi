// src/pages/Login.jsx
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext"; // Certifique-se de que está configurado
import { login, verifyMfa } from "../api/auth"; // Certifique-se de que existem
import Toast from "../components/Toast"; // Certifique-se de que existe
import LoadingSpinner from "../components/LoadingSpinner"; // Certifique-se de que existe

export default function Login() {
  const [usernameOrEmail, setUsernameOrEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState({ show: false, message: "", type: "danger" });
  const [loginData, setLoginData] = useState(null);

  const navigate = useNavigate();
  const authContext = useAuth();
  const setUser = authContext?.setUser;
  const user = authContext?.user;

  useEffect(() => {
    if (user) navigate("/dashboard");
  }, [user, navigate]);

  const showToast = (msg, type = "danger") => {
    setToast({ show: true, message: msg, type });
    setTimeout(() => setToast({ show: false, message: "", type: "danger" }), 4000);
  };

  const finalizeLogin = (data) => {
    const { token, username, email } = data;
    localStorage.setItem("token", token);
    setUser && setUser({ username, email });
    showToast("Login bem-sucedido!", "success");
    setTimeout(() => navigate("/dashboard"), 600);
  };

  const handleLogin = async () => {
    if (!usernameOrEmail || !password) return showToast("Preencha todos os campos", "warning");
    setLoading(true);
    try {
      const res = await login({ usernameOrEmail, password });
      if (res.data.mfaRequired) {
        setLoginData(res.data);
        setMfaRequired(true);
        setPassword("");
        showToast("Digite o código MFA de 6 dígitos", "info");
        return;
      }
      finalizeLogin(res.data);
    } catch (err) {
      showToast(err.response?.data?.error || "Credenciais inválidas");
    } finally {
      setLoading(false);
    }
  };

  const handleMfa = async () => {
    if (!mfaCode || mfaCode.length !== 6) return showToast("Código deve ter 6 dígitos", "warning");
    if (!loginData) return showToast("Erro interno. Tente novamente.");
    setLoading(true);
    try {
      const username = loginData.username || loginData.email;
      const res = await verifyMfa(username, mfaCode);
      finalizeLogin(res.data);
    } catch (err) {
      showToast(err.response?.data?.error || "Código MFA inválido");
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    mfaRequired ? handleMfa() : handleLogin();
  };

  if (loading) return <LoadingSpinner text="Autenticando..." />;

  return (
    <>
      {toast.show && <Toast message={toast.message} type={toast.type} onClose={() => setToast({ show: false })} />}

      <div
        className="min-vh-100 d-flex align-items-center justify-content-center p-3"
        style={{ background: "linear-gradient(135deg, #4a3aff 0%, #7b2ff7 100%)" }}
      >
        <div className="card shadow-lg border-0" style={{ maxWidth: "420px", width: "100%", borderRadius: "1.5rem" }}>
          <div className="card-body p-5">
            <div className="text-center mb-4">
              <h2 className="fw-bold text-primary">BugBounty TCC</h2>
              <p className="text-muted">Login seguro com MFA</p>
            </div>

            <form onSubmit={handleSubmit}>
              <div className="mb-3">
                <input
                  type="text"
                  className="form-control form-control-lg rounded-pill"
                  placeholder="Usuário ou e-mail"
                  value={usernameOrEmail}
                  onChange={(e) => setUsernameOrEmail(e.target.value)}
                  disabled={loading || mfaRequired}
                  required
                />
              </div>

              {!mfaRequired && (
                <div className="mb-3">
                  <input
                    type="password"
                    className="form-control form-control-lg rounded-pill"
                    placeholder="Senha"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={loading}
                    required
                  />
                </div>
              )}

              {mfaRequired && (
                <div className="mb-3 text-center">
                  <input
                    type="text"
                    className="form-control form-control-lg text-center rounded-pill"
                    placeholder="______"
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    maxLength={6}
                    autoFocus
                    style={{ letterSpacing: "0.5rem", fontSize: "1.5rem", fontWeight: "bold" }}
                  />
                  <small className="text-muted d-block mt-2">Abra seu app autenticador</small>
                </div>
              )}

              <button
                type="submit"
                className="btn btn-primary btn-lg w-100 rounded-pill fw-bold d-flex align-items-center justify-content-center gap-2"
                disabled={loading}
              >
                {loading ? (
                  <>
                    <div className="spinner-border spinner-border-sm" role="status"></div>
                    Processando...
                  </>
                ) : mfaRequired ? "Verificar MFA" : "Entrar"}
              </button>
            </form>

            {!mfaRequired && (
              <div className="d-flex justify-content-between mt-4">
                <button className="btn btn-link text-primary p-0" onClick={() => navigate("/forgot-password")}>
                  Esqueci a senha
                </button>
                <button className="btn btn-link text-primary p-0" onClick={() => navigate("/register")}>
                  Criar conta
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
