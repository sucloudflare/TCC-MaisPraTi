// src/components/EmptyState.jsx
import { Search, AlertCircle } from "lucide-react";
import { motion } from "framer-motion";

export default function EmptyState({ title, description, actionText, onAction, icon: Icon = Search }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="text-center py-5"
    >
      <Icon size={64} className="text-muted mb-3" />
      <h3 className="h5 fw-semibold text-dark">{title}</h3>
      <p className="text-muted mb-4">{description}</p>
      {actionText && onAction && (
        <button onClick={onAction} className="btn btn-primary d-flex align-items-center gap-2 mx-auto">
          {actionText}
        </button>
      )}
    </motion.div>
  );
}