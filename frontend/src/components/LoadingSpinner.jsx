// src/components/LoadingSpinner.jsx
import { motion } from "framer-motion";

export default function LoadingSpinner({ size = "3rem", text = "Carregando..." }) {
  return (
    <div className="d-flex flex-column justify-content-center align-items-center py-5">
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
        className="spinner-border text-primary"
        style={{ width: size, height: size }}
        role="status"
      >
        <span className="visually-hidden">{text}</span>
      </motion.div>
      <p className="mt-3 text-muted fw-medium">{text}</p>
    </div>
  );
}