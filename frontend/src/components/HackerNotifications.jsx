// src/components/HackerNotifications.jsx
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertTriangle, CheckCircle, Zap } from "lucide-react";

const HACKER_NAMES = [
  "Pwnie", "Zer0Day", "lcamtuf", "s1ren", "st4ck", "phrack", "0xdea", "m4lware",
  "r00t", "hackerone", "bugcrowd", "synack", "intigriti", "yeswehack", "hacker101",
  "portswigger", "burp", "zaproxy", "sqlmap", "nikto", "nmap", "metasploit", "cobalt",
  "john", "hashcat", "medusa", "hydra", "crunch", "cewl", "dirb", "gobuster",
  "feroxbuster", "ffuf", "nuclei", "xray", "jaeger", "wpscan", "joomla", "drupal",
  "magento", "shopify", "wordpress", "joomscan", "droopescan", "cmsmap", "whatweb",
  "wappalyzer", "builtwith", "shodan", "censys", "fofa", "zoomeye", "onyphe", "recon",
  "amass", "subfinder", "assetfinder", "findomain", "chaos", "github", "gitlab", "bitbucket"
];

let globalReportCount = 0;
let setGlobalCount = () => {};

export const getReportCount = () => globalReportCount;

export default function HackerNotifications() {
  const [notifications, setNotifications] = useState([]);
  const [, forceUpdate] = useState({});

  useEffect(() => {
    setGlobalCount = () => forceUpdate({});
  }, []);

  useEffect(() => {
    let timeout;

    const showNewBatch = () => {
      const newBatch = Array.from({ length: 3 }, () => {
        const name = HACKER_NAMES[Math.floor(Math.random() * HACKER_NAMES.length)];
        const vuln = ["XSS", "SQLi", "RCE", "SSRF", "IDOR", "LFI", "Open Redirect", "CSRF"][Math.floor(Math.random() * 8)];
        const target = ["api.banco.com", "login.app.br", "admin.panel", "checkout.site", "api.vip"][Math.floor(Math.random() * 5)];
        const reward = ["R$ 500", "R$ 1.200", "R$ 3.000", "R$ 750", "R$ 2.500"][Math.floor(Math.random() * 5)];
        globalReportCount++;
        return { id: `${Date.now()}-${Math.random()}`, name, vuln, target, reward };
      });

      setNotifications(newBatch);
      setGlobalCount(); // Atualiza navbar

      // Remove após 4 segundos
      timeout = setTimeout(() => {
        setNotifications([]);
      }, 8000);
    };

    // Primeira leva imediata
    showNewBatch();

    // Nova leva a cada 30 segundos
    const interval = setInterval(showNewBatch, 30000);

    return () => {
      clearInterval(interval);
      clearTimeout(timeout);
    };
  }, []);

  return (
    <div className="position-fixed end-0 p-3" style={{ top: "80px", zIndex: 1090, maxWidth: "380px" }}>
      <AnimatePresence>
        {notifications.map((notif, i) => (
          <motion.div
            key={notif.id}
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 300, opacity: 0 }}
            transition={{ delay: i * 0.1 }}
            className="alert alert-success d-flex align-items-start gap-3 mb-3 shadow-lg"
            style={{
              borderRadius: "1rem",
              border: "1px solid #000",
              background: "#f8fff8",
              fontSize: "0.9rem",
              fontWeight: 500,
            }}
          >
            <div className="flex-shrink-0">
              {i === 0 ? <Zap size={20} color="#16a34a" /> :
               i === 1 ? <CheckCircle size={20} color="#16a34a" /> :
                         <AlertTriangle size={20} color="#ca8a04" />}
            </div>
            <div>
              <strong className="text-success">{notif.name}</strong> reportou uma falha crítica!
              <div className="small text-muted mt-1">
                <code>{notif.vuln}</code> em <code>{notif.target}</code>
              </div>
              <div className="mt-1">
                <span className="badge bg-warning text-dark small">
                  Recompensa: {notif.reward}
                </span>
                <span className="text-success small ms-2">→ Reportado automaticamente</span>
              </div>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}