// src/pages/Home.jsx
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Zap, Beaker, Target } from "lucide-react";

export default function Home() {
  return (
    <div className="min-vh-100 d-flex align-items-center justify-content-center bg-gradient text-white p-3" style={{ background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)" }}>
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center"
      >
        <Shield size={72} className="mb-4" />
        <h1 className="display-4 fw-bold mb-3">BugBounty TCC</h1>
        <p className="lead mb-5">Pratique vulnerabilidades em um ambiente seguro e gamificado</p>

        <div className="row g-4 justify-content-center">
          {[
            { icon: Zap, text: "Scanner em tempo real" },
            { icon: Beaker, text: "Labs interativos" },
            { icon: Target, text: "Rankings e conquistas" },
          ].map((item, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.2 }}
              className="col-md-3"
            >
              <div className="bg-white bg-opacity-10 p-4 rounded-3 backdrop-blur">
                <item.icon size={36} className="mb-2" />
                <p className="mb-0">{item.text}</p>
              </div>
            </motion.div>
          ))}
        </div>

        <Link to="/login" className="btn btn-light btn-lg mt-5 rounded-pill px-5 fw-bold d-flex align-items-center gap-2 mx-auto">
          Começar Agora
        </Link>
      </motion.div>
    </div>
  );
}