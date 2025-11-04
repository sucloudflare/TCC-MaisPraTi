// src/api/auth.js
import axios from "axios";

const API_BASE = "http://localhost:8080";

// ================= LOGIN =================
export async function login({ usernameOrEmail, password }) {
  return axios.post(`${API_BASE}/auth/login`, { usernameOrEmail, password });
}

// ================= REGISTER =================
export async function register({ username, email, password }) {
  return axios.post(`${API_BASE}/auth/register`, { username, email, password });
}

// ================= MFA =================
export async function setupMfa(username) {
  return axios.post(`${API_BASE}/auth/mfa/setup`, null, { params: { username } });
}

export async function verifyMfa(username, code) {
  return axios.post(`${API_BASE}/auth/mfa/verify`, null, { params: { username, code } });
}

// ================= VALIDATE TOKEN =================
export async function validateToken(token) {
  return axios.post(`${API_BASE}/auth/validate`, null, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

// ================= FORGOT / RESET PASSWORD =================
export async function forgotPassword(email) {
  return axios.post(`${API_BASE}/auth/forgot-password`, null, { params: { email } });
}

export async function resetPassword(token, newPassword) {
  return axios.post(`${API_BASE}/auth/reset-password`, null, { params: { token, newPassword } });
}
