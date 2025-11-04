import api from "./client";

// AUTH
export const register = (data) => api.post("/auth/register", data);
export const login = (data) => api.post("/auth/login", data);
export const forgotPassword = (email) => api.post("/auth/forgot-password", { email });
export const resetPassword = (token, password) =>
  api.post("/auth/reset-password", { token, password });

// MFA
export const setupMfa = (username) => api.post(`/auth/mfa/setup?username=${username}`);
export const verifyMfa = (username, code) =>
  api.post(`/auth/mfa/verify?username=${username}&code=${code}`);
