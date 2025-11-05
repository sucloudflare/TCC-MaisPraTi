import { useEffect } from "react";
import { motion } from "framer-motion";
import { CheckCircle, AlertTriangle, Info, XCircle } from "lucide-react";

const icons = {
  success: { icon: CheckCircle, color: "#00c851" },
  danger: { icon: XCircle, color: "#ff4444" },
  warning: { icon: AlertTriangle, color: "#ffbb33" },
  info: { icon: Info, color: "#33b5e5" },
};

export default function Toast({ message, type = "success", onClose, autoClose = true }) {
  const { icon: Icon, color } = icons[type] || icons.info;

  useEffect(() => {
    if (!autoClose) return;
    const timer = setTimeout(() => {
      onClose && onClose();
    }, 4000);
    return () => clearTimeout(timer);
  }, [autoClose, onClose]);

  return (
    <motion.div
      initial={{ x: 300, opacity: 0, scale: 0.9 }}
      animate={{ x: 0, opacity: 1, scale: 1 }}
      exit={{ x: 300, opacity: 0, scale: 0.9 }}
      transition={{ type: "spring", stiffness: 250, damping: 25 }}
      className={`shadow-lg d-flex align-items-center gap-3 p-3 rounded-4 position-fixed top-0 end-0 m-3`}
      style={{
        background: "rgba(255, 255, 255, 0.15)",
        backdropFilter: "blur(12px)",
        color: "white",
        borderLeft: `5px solid ${color}`,
        minWidth: "320px",
        maxWidth: "400px",
        zIndex: 2000,
      }}
      role="alert"
    >
      <Icon size={28} style={{ color }} />
      <div className="flex-grow-1 fw-semibold">{message}</div>
      {onClose && (
        <button
          type="button"
          className="btn btn-sm text-white opacity-75"
          onClick={onClose}
          aria-label="Fechar"
          style={{ fontSize: "1.2rem", lineHeight: "1rem" }}
        >
          ×
        </button>
      )}
    </motion.div>
  );
}
