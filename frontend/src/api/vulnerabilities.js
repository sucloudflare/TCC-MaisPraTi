// src/api/vulnerabilities.js
import axios from './axios'; // Axios já configurado com baseURL

// ---------------- Jobs ----------------
export const getJobs = async (filter = {}) => {
  // GET /jobs, você pode adicionar query params se precisar filtrar
  return await axios.get('/jobs', { params: filter });
};

export const testVulnerability = async (targetUrl, vulnerabilityType) => {
  return await axios.post('/vulnerabilities/test', { targetUrl, vulnerabilityType });
};

export const testBatch = async (requests) => {
  // requests: [{ targetUrl, vulnerabilityType }]
  return await axios.post('/vulnerabilities/test/batch', requests);
};

export const exportReport = async (jobId) => {
  return await axios.get(`/jobs/${jobId}`, { responseType: 'blob' });
};

// Opcional: cancelar job
export const cancelJob = async (jobId) => {
  return await axios.put(`/jobs/${jobId}/status`, { status: 'CANCELLED' });
};
