// src/api/axios.js
import axios from 'axios';

const instance = axios.create({
  baseURL: 'http://localhost:8080', // coloque aqui a URL do seu backend
  headers: {
    'Content-Type': 'application/json',
  },
});

export default instance;
