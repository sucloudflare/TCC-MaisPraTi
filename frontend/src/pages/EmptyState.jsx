// src/components/EmptyState.jsx
export default function EmptyState({ title, description, actionText, onAction }) {
  return (
    <div className="text-center py-5">
      <i className="bi bi-file-earmark-text display-1 text-muted"></i>
      <h3 className="mt-3 h5 fw-semibold text-dark">{title}</h3>
      <p className="text-muted mb-4">{description}</p>
      <button onClick={onAction} className="btn btn-primary">
        {actionText}
      </button>
    </div>
  );
}