// src/main.jsx (ou index.js)
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';  // Importe aqui
import { AuthProvider } from './context/AuthContext';  // Seu provider
import { ThemeProvider } from './context/ThemeContext';  // Se tiver
import App from './App';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    {/* Router NO TOPO - envolve TUDO */}
    <BrowserRouter>
      {/* Providers DEPOIS do Router */}
      <AuthProvider>
        <ThemeProvider>  {/* Se existir */}
          <App />
        </ThemeProvider>
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);