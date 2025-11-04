// src/api/labs.js
import api from "./client";

export const getCompletedLabs = () => api.get("/labs/completed");
export const markLabCompleted = (labId) => api.post(`/labs/completed/${labId}`);