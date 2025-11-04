import api from "../../api/client";  // <<<<< CORRIGIDO

// REGISTRO
export const register = (payload) => api.post("/auth/register", payload);
export const login = (payload) => api.post("/auth/login", payload);
export const forgotPassword = (email) =>
  api.post("/auth/forgot-password", null, { params: { email } });
export const resetPassword = (token, newPassword) =>
  api.post("/auth/reset-password", null, { params: { token, newPassword } });
export const setupMfa = (username) =>
  api.post("/auth/mfa/setup", null, { params: { username } });
export const verifyMfa = (username, code) =>
  api.post("/auth/mfa/verify", null, { params: { username, code } });

export default {
  register,
  login,
  forgotPassword,
  resetPassword,
  setupMfa,
  verifyMfa,
};
