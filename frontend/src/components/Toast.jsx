import { useEffect } from "react";
import { motion } from "framer-motion";
import { CheckCircle, AlertCircle, Info } from "lucide-react";

const icons = {
  success: CheckCircle,
  danger: AlertCircle,
  warning: AlertCircle,
  info: Info,
};

export default function Toast({ message, type = "success", onClose, autoClose = true }) {
  const Icon = icons[type] || CheckCircle;

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
      transition={{ type: "spring", stiffness: 300, damping: 30 }}
      className={`alert alert-${type} alert-dismissible fade show shadow-lg d-flex align-items-center gap-3 rounded-3`}
      role="alert"
      style={{ maxWidth: "380px" }}
    >
      <Icon size={20} />
      <div className="flex-grow-1">{message}</div>
      {onClose && (
        <button type="button" className="btn-close btn-close-white" onClick={onClose} aria-label="Fechar"></button>
      )}
    </motion.div>
  );
}
