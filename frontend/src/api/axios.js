// src/api/axios.js
import axios from "axios";

// Cria instância base do Axios
const instance = axios.create({
  baseURL: "http://localhost:8080", // URL do backend
  headers: {
    "Content-Type": "application/json",
  },
});

// 🔐 Interceptor de requisição — adiciona o token JWT automaticamente
instance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token"); // token salvo no login
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// 🚨 Interceptor de resposta — trata erros globais (ex: 401, 403)
instance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const { status } = error.response;

      // Token inválido ou expirado → remove e redireciona para login
      if (status === 401 || status === 403) {
        console.warn("Sessão expirada ou acesso negado. Faça login novamente.");
        localStorage.removeItem("token");
        window.location.href = "/login";
      }

      // Erros do servidor
      if (status >= 500) {
        console.error("Erro no servidor:", error.response.data || error.message);
      }
    } else {
      console.error("Erro de rede:", error.message);
    }

    return Promise.reject(error);
  }
);

export default instance;
