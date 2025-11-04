import { motion } from "framer-motion";
import { AlertTriangle, CheckCircle, ExternalLink, Clock } from "lucide-react";

export default function VulnCard({ vuln }) {
  const severityConfig = {
    Critical: { color: "bg-red-100 text-red-800 border-red-300", icon: AlertTriangle },
    High: { color: "bg-orange-100 text-orange-800 border-orange-300", icon: AlertTriangle },
    Medium: { color: "bg-yellow-100 text-yellow-800 border-yellow-300", icon: AlertTriangle },
    Low: { color: "bg-green-100 text-green-800 border-green-300", icon: CheckCircle },
  };

  const config = severityConfig[vuln.severity] || severityConfig.Medium;
  const Icon = config.icon;

  return (
    <motion.div
      whileHover={{ y: -8, boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.25)" }}
      className="bg-white rounded-3xl shadow-xl border overflow-hidden h-100"
      style={{ borderColor: config.color.split(' ')[2] }}
    >
      <div className="p-5">
        <div className="d-flex justify-content-between align-items-start mb-3">
          <h5 className="fw-bold text-dark mb-0">{vuln.vulnerabilityType}</h5>
          <span className={`px-3 py-1 rounded-full text-xs font-bold d-flex align-items-center gap-1 ${config.color}`}>
            <Icon size={14} />
            {vuln.severity}
          </span>
        </div>

        <div className="small text-muted mb-3">
          <div className="d-flex align-items-center gap-2 mb-1">
            <ExternalLink size={14} />
            <code className="bg-light px-2 py-1 rounded text-break">{vuln.targetUrl}</code>
          </div>
          <div className="d-flex align-items-center gap-2">
            <Clock size={14} />
            {new Date(vuln.createdAt).toLocaleString()}
          </div>
        </div>

        <div className="pt-3 border-top">
          <div className="d-flex justify-content-between align-items-center">
            <span className={`fw-bold ${vuln.result === 'VULNERABLE' ? 'text-danger' : 'text-success'}`}>
              {vuln.result}
            </span>
            {vuln.responseDetails && (
              <details className="cursor-pointer">
                <summary className="text-primary small fw-medium">Detalhes</summary>
                <pre className="mt-2 p-3 bg-light rounded small text-wrap" style={{ maxHeight: '150px', overflow: 'auto' }}>
                  {vuln.responseDetails}
                </pre>
              </details>
            )}
          </div>
        </div>
      </div>
    </motion.div>
  );
}