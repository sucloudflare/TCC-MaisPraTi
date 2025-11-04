import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import App from './App';
import 'bootstrap/dist/css/bootstrap.min.css';

// Captura o elemento #root do HTML
const root = document.getElementById('root');

if (!root) {
  document.body.innerHTML = '<h1 style="color:red;text-align:center;margin-top:50px">ERRO: #root não encontrado!</h1>';
  throw new Error('#root não encontrado no HTML');
}

// Renderiza o app
ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <ThemeProvider>
          <App />
        </ThemeProvider>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);
