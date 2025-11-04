// src/api/vulnerabilities.js
import api from "./client";

export const testVulnerability = (targetUrl, vulnerabilityType, payload = "") =>
  api.post("/vulnerabilities/test", { targetUrl, vulnerabilityType, payload });

export const testBatch = (requests) => api.post("/vulnerabilities/test/batch", requests);

export const getVulnerabilities = (filters = {}) =>
  api.get("/vulnerabilities", { params: filters });

export const getVulnerabilitiesByJob = (jobId) =>
  api.get(`/vulnerabilities/job/${jobId}`);

export const exportReport = (jobId) =>
  api.get(`/vulnerabilities/export/${jobId}`, { responseType: "blob" });