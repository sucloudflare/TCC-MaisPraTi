import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { register, login, verifyMfa } from "../api/auth";
import { useAuth } from "../context/AuthContext";
import Toast from "../components/Toast";
import LoadingSpinner from "../components/LoadingSpinner";

export default function Register() {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [loginData, setLoginData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState({ show: false, message: "", type: "" });

  const navigate = useNavigate();
  const { setUser } = useAuth();

  const showToast = (msg, type = "success") => {
    setToast({ show: true, message: msg, type });
    setTimeout(() => setToast({ show: false }), 4000);
  };

  const finalizeLogin = (data) => {
    const { token, username, email } = data;
    localStorage.setItem("token", token);
    setUser({ username, email });
    showToast("Login bem-sucedido!", "success");
    setTimeout(() => navigate("/dashboard"), 500);
  };

  const handleMfa = async () => {
    if (!mfaCode || mfaCode.length !== 6) return showToast("Código deve ter 6 dígitos", "warning");
    if (!loginData) return showToast("Erro interno. Tente novamente.");

    setLoading(true);
    try {
      const usernameOrEmail = loginData.username || loginData.email;
      const res = await verifyMfa(usernameOrEmail, mfaCode);
      finalizeLogin(res.data);
    } catch (err) {
      showToast(err.response?.data?.error || "Código MFA inválido", "danger");
    } finally {
      setLoading(false);
    }
  };

  const handleLoginAfterRegister = async () => {
    setLoading(true);
    try {
      const res = await login({ usernameOrEmail: username, password });

      if (res.data.mfaRequired) {
        setLoginData(res.data);
        setMfaRequired(true);
        setPassword(""); // Limpa senha
        showToast("Digite o código MFA de 6 dígitos", "info");
        return;
      }

      finalizeLogin(res.data);
    } catch (err) {
      showToast(err.response?.data?.error || "Erro ao logar automaticamente", "danger");
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !email || !password) return showToast("Preencha todos os campos", "warning");

    setLoading(true);
    try {
      await register({ username, email, password });
      showToast("Registrado com sucesso! Tentando login...", "success");

      // Tenta logar automaticamente
      await handleLoginAfterRegister();
    } catch (err) {
      showToast(err.response?.data?.error || "Erro ao registrar", "danger");
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <LoadingSpinner text={mfaRequired ? "Verificando MFA..." : "Processando..." } />;

  return (
    <>
      {toast.show && <Toast message={toast.message} type={toast.type} onClose={() => setToast({ show: false })} />}

      <div className="min-vh-100 d-flex align-items-center justify-content-center bg-light p-3">
        <form onSubmit={mfaRequired ? handleMfa : handleSubmit} className="card p-5 shadow-lg border-0" style={{ maxWidth: "420px", width: "100%", borderRadius: "1.5rem" }}>
          <h3 className="text-center mb-4 fw-bold text-primary">Criar Conta</h3>

          {!mfaRequired && (
            <>
              <input
                type="text"
                placeholder="Usuário"
                className="form-control form-control-lg rounded-pill mb-3"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
              <input
                type="email"
                placeholder="E-mail"
                className="form-control form-control-lg rounded-pill mb-3"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
              <input
                type="password"
                placeholder="Senha"
                className="form-control form-control-lg rounded-pill mb-4"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </>
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

          <button type="submit" className="btn btn-primary btn-lg w-100 rounded-pill fw-bold">
            {mfaRequired ? "Verificar MFA" : "Registrar"}
          </button>

          {!mfaRequired && (
            <p className="text-center mt-3 text-muted">
              Já tem conta? <a href="/login" className="text-primary fw-medium">Entrar</a>
            </p>
          )}
        </form>
      </div>
    </>
  );
}
