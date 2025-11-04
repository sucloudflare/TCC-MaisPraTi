// src/pages/Vulnerabilities.jsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { testVulnerability, testBatch, getVulnerabilities, exportReport } from '../api/vulnerabilities';
import { AlertCircle, CheckCircle, Download, Search, Filter, Clock, Link, RefreshCw, History, Zap, XCircle, Play, Pause } from 'lucide-react';

const vulnTypes = [
  { id: 'xxe', name: 'XXE OOB', severity: 'Critical', color: 'danger', icon: '🔓' },
  { id: 'ssrf', name: 'SSRF DNS', severity: 'High', color: 'warning', icon: '🌐' },
  { id: 'template', name: 'Template Inj.', severity: 'High', color: 'warning', icon: '⚙️' },
  { id: 'smuggling', name: 'HTTP Smuggling', severity: 'Medium', color: 'secondary', icon: '🔗' },
];

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [filter, setFilter] = useState({ search: '', severity: '' });
  const [testUrl, setTestUrl] = useState('');
  const [selectedType, setSelectedType] = useState(vulnTypes[0].id);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('single');
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });
  const [urlHistory, setUrlHistory] = useState([]);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [refreshCountdown, setRefreshCountdown] = useState(5);
  const intervalRef = useRef(null);
  const countdownRef = useRef(null);

  const showToast = (msg, type = 'success') => {
    setToast({ show: true, message: msg, type });
    setTimeout(() => setToast({ show: false, message: '', type: 'success' }), 4000);
  };

  useEffect(() => {
    const saved = localStorage.getItem(' bounty_url_history');
    if (saved) setUrlHistory(JSON.parse(saved));
  }, []);

  const saveToHistory = (url) => {
    const unique = [...new Set([url, ...urlHistory])].slice(0, 15);
    setUrlHistory(unique);
    localStorage.setItem('bounty_url_history', JSON.stringify(unique));
  };

  const loadVulns = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await getVulnerabilities(filter);
      setVulns(data);
    } catch {
      showToast('Erro ao carregar vulnerabilidades', 'danger');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { loadVulns(); }, [loadVulns]);

  // Auto-refresh com contador
  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(loadVulns, 5000);
      countdownRef.current = setInterval(() => {
        setRefreshCountdown(prev => prev <= 1 ? 5 : prev - 1);
      }, 1000);
    } else {
      clearInterval(intervalRef.current);
      clearInterval(countdownRef.current);
      setRefreshCountdown(5);
    }
    return () => {
      clearInterval(intervalRef.current);
      clearInterval(countdownRef.current);
    };
  }, [autoRefresh, loadVulns]);

  const testSingle = async () => {
    if (!/^https?:\/\//i.test(testUrl)) return showToast('URL inválida. Use http:// ou https://', 'warning');
    setLoading(true);
    try {
      const { data } = await testVulnerability(testUrl, selectedType);
      showToast(`Vulnerável! Severidade: ${data.severity}`, data.severity === 'Critical' ? 'danger' : 'success');
      saveToHistory(testUrl);
      loadVulns();
    } catch (err) {
      showToast(err.response?.data?.responseDetails || 'Erro no teste', 'danger');
    } finally {
      setLoading(false);
    }
  };

  const testBatch = async () => {
    const urls = testUrl.split('\n').map(u => u.trim()).filter(Boolean);
    if (urls.length === 0) return showToast('Adicione pelo menos uma URL', 'warning');
    if (urls.length > 50) return showToast('Máximo 50 URLs por lote', 'warning');
    setLoading(true);
    try {
      const requests = urls.map(url => ({ targetUrl: url, vulnerabilityType: selectedType }));
      const { data } = await testBatch(requests);
      showToast(`Lote iniciado! Job #${data.jobId} (${urls.length} URLs)`, 'success');
      loadVulns();
    } catch (err) {
      showToast(err.response?.data?.error || 'Erro no lote', 'danger');
    } finally {
      setLoading(false);
    }
  };

  const downloadPdf = async (jobId) => {
    try {
      const { data } = await exportReport(jobId);
      const url = window.URL.createObjectURL(new Blob([data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `relatorio_vuln_${jobId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      showToast('Relatório baixado!', 'success');
    } catch {
      showToast('Erro ao baixar PDF', 'danger');
    }
  };

  return (
    <div className="container py-5">
      {/* Toast Animado */}
      <AnimatePresence>
        {toast.show && (
          <motion.div
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 300, opacity: 0 }}
            className="position-fixed top-0 end-0 p-3"
            style={{ zIndex: 1055 }}
          >
            <div className={`alert alert-${toast.type} alert-dismissible fade show shadow-lg d-flex align-items-center gap-2`} role="alert">
              {toast.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
              <div>{toast.message}</div>
              <button type="button" className="btn-close" onClick={() => setToast({ show: false })}></button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-5"
      >
        <h1 className="display-5 fw-bold text-primary d-flex align-items-center justify-content-center gap-2">
          <Zap size={36} /> Scanner de Vulnerabilidades
        </h1>
        <p className="lead text-muted">Teste XXE, SSRF, Template Injection e mais em tempo real</p>
      </motion.div>

      <div className="row g-4">
        <div className="col-lg-11 mx-auto">
          {/* Card de Configuração */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="card shadow-lg border-0 overflow-hidden"
            style={{ borderRadius: '1.5rem' }}
          >
            <div className="card-header bg-gradient text-white" style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
              <div className="d-flex justify-content-between align-items-center">
                <h5 className="mb-0 fw-bold d-flex align-items-center gap-2">
                  <Filter size={20} /> Configurar Teste
                </h5>
                <div className="form-check form-switch">
                  <input
                    className="form-check-input"
                    type="checkbox"
                    checked={autoRefresh}
                    onChange={(e) => setAutoRefresh(e.target.checked)}
                    id="autoRefresh"
                  />
                  <label className="form-check-label text-white" htmlFor="autoRefresh">
                    Auto-refresh {autoRefresh && <span className="badge bg-light text-dark ms-1">{refreshCountdown}s</span>}
                  </label>
                </div>
              </div>
            </div>

            <div className="card-body p-4">
              {/* Filtros */}
              <div className="row g-3 mb-4">
                <div className="col-md-8">
                  <div className="input-group">
                    <span className="input-group-text bg-light border-end-0">
                      <Search size={18} />
                    </span>
                    <input
                      type="text"
                      className="form-control border-start-0"
                      placeholder="Buscar por URL ou tipo..."
                      value={filter.search}
                      onChange={e => setFilter({ ...filter, search: e.target.value })}
                    />
                  </div>
                </div>
                <div className="col-md-4">
                  <select
                    className="form-select"
                    value={filter.severity}
                    onChange={e => setFilter({ ...filter, severity: e.target.value })}
                  >
                    <option value="">Todas as severidades</option>
                    {['Critical', 'High', 'Medium', 'Low'].map(s => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Tabs */}
              <ul className="nav nav-pills mb-4 border-bottom">
                <li className="nav-item">
                  <button
                    className={`nav-link d-flex align-items-center gap-2 ${activeTab === 'single' ? 'active' : ''}`}
                    onClick={() => setActiveTab('single')}
                  >
                    <Play size={16} /> Teste Único
                  </button>
                </li>
                <li className="nav-item">
                  <button
                    className={`nav-link d-flex align-items-center gap-2 ${activeTab === 'batch' ? 'active' : ''}`}
                    onClick={() => setActiveTab('batch')}
                  >
                    <RefreshCw size={16} /> Lote
                  </button>
                </li>
              </ul>

              {/* Input com Histórico */}
              <div className="mb-4">
                <div className="input-group">
                  {activeTab === 'batch' ? (
                    <textarea
                      className="form-control"
                      rows={5}
                      value={testUrl}
                      onChange={e => setTestUrl(e.target.value)}
                      placeholder="Cole uma URL por linha (máx. 50)..."
                      style={{ resize: 'none', fontFamily: 'monospace' }}
                    />
                  ) : (
                    <input
                      type="url"
                      className="form-control"
                      value={testUrl}
                      onChange={e => setTestUrl(e.target.value)}
                      placeholder="https://alvo.com/vuln"
                    />
                  )}
                  <button
                    className="btn btn-outline-secondary dropdown-toggle"
                    type="button"
                    data-bs-toggle="dropdown"
                    aria-label="Histórico de URLs"
                  >
                    <History size={18} />
                  </button>
                  <ul className="dropdown-menu dropdown-menu-end shadow-sm" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                    {urlHistory.length === 0 ? (
                      <li><span className="dropdown-item text-muted">Nenhum histórico</span></li>
                    ) : (
                      urlHistory.map((url, i) => (
                        <li key={i}>
                          <button
                            className="dropdown-item d-flex justify-content-between align-items-center"
                            onClick={() => setTestUrl(url)}
                          >
                            <code className="text-truncate d-inline-block" style={{ maxWidth: '200px' }}>{url}</code>
                            <XCircle size={14} className="text-danger opacity-50" onClick={(e) => {
                              e.stopPropagation();
                              const filtered = urlHistory.filter((_, idx) => idx !== i);
                              setUrlHistory(filtered);
                              localStorage.setItem('bounty_url_history', JSON.stringify(filtered));
                            }} />
                          </button>
                        </li>
                      ))
                    )}
                  </ul>
                </div>
              </div>

              {/* Ações */}
              {activeTab === 'single' ? (
                <div className="row g-3 align-items-center">
                  <div className="col-md-8">
                    <select
                      className="form-select form-select-lg"
                      value={selectedType}
                      onChange={e => setSelectedType(e.target.value)}
                    >
                      {vulnTypes.map(t => (
                        <option key={t.id} value={t.id}>
                          {t.icon} {t.name} ({t.severity})
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="col-md-4">
                    <button
                      onClick={testSingle}
                      disabled={loading || !testUrl}
                      className="btn btn-primary w-100 btn-lg d-flex align-items-center justify-content-center gap-2"
                    >
                      {loading ? (
                        <>
                          <div className="spinner-border spinner-border-sm" role="status"></div>
                          Testando...
                        </>
                      ) : (
                        <>
                          <Zap size={18} /> Iniciar Teste
                        </>
                      )}
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={testBatch}
                  disabled={loading}
                  className="btn btn-success w-100 btn-lg d-flex align-items-center justify-content-center gap-2"
                >
                  {loading ? (
                    <>
                      <div className="spinner-border spinner-border-sm" role="status"></div>
                      Processando lote...
                    </>
                  ) : (
                    <>
                      <RefreshCw size={18} /> Testar Todas
                    </>
                  )}
                </button>
              )}
            </div>
          </motion.div>

          {/* Resultados */}
          <div className="mt-5">
            {loading && vulns.length === 0 ? (
              <div className="text-center py-5">
                <div className="spinner-border text-primary" style={{ width: '4rem', height: '4rem' }} role="status">
                  <span className="visually-hidden">Carregando...</span>
                </div>
                <p className="mt-3 text-muted fw-semibold">Carregando vulnerabilidades...</p>
              </div>
            ) : vulns.length === 0 ? (
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="text-center py-5"
              >
                <div className="display-1 text-muted mb-3">Search</div>
                <h3 className="h5 fw-semibold">Nenhum resultado encontrado</h3>
                <p className="text-muted">Inicie um teste para ver os resultados aqui.</p>
              </motion.div>
            ) : (
              <div className="row g-4">
                {vulns.map((v, i) => (
                  <motion.div
                    key={v.id}
                    layout
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className="col-md-6 col-lg-4"
                  >
                    <VulnCard vuln={v} onDownload={() => downloadPdf(v.jobId)} />
                  </motion.div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Card de Vulnerabilidade (com animação, detalhes expansíveis, ícones)
function VulnCard({ vuln, onDownload }) {
  const config = {
    Critical: { color: 'danger', icon: '🚨', bg: 'bg-danger-subtle' },
    High: { color: 'warning', icon: '⚠️', bg: 'bg-warning-subtle' },
    Medium: { color: 'secondary', icon: '⚡', bg: 'bg-secondary-subtle' },
    Low: { color: 'success', icon: '✅', bg: 'bg-success-subtle' },
  }[vuln.severity] || config.Medium;

  return (
    <motion.div
      whileHover={{ y: -8, scale: 1.02 }}
      className="card h-100 shadow-sm border-0 overflow-hidden position-relative"
      style={{
        borderLeft: `5px solid var(--bs-${config.color})`,
        borderRadius: '1rem',
        transition: 'all 0.3s ease'
      }}
    >
      <div className={`position-absolute top-0 end-0 m-2 ${config.bg} rounded-pill px-2 py-1 text-xs fw-bold`}>
        {config.icon} {vuln.severity}
      </div>
      <div className="card-body p-4">
        <h6 className="card-title fw-bold mb-3 d-flex align-items-center gap-2">
          {vulnTypes.find(t => t.id === vuln.vulnerabilityType)?.icon || '🔍'} {vuln.vulnerabilityType}
        </h6>

        <div className="small text-muted mb-3">
          <div className="d-flex align-items-center gap-2 mb-2">
            <Link size={14} />
            <code className="bg-light px-2 py-1 rounded text-break text-truncate d-block" style={{ maxWidth: '100%' }}>
              {vuln.targetUrl}
            </code>
          </div>
          <div className="d-flex align-items-center gap-2">
            <Clock size={14} />
            {new Date(vuln.createdAt).toLocaleString('pt-BR', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: 'short' })}
          </div>
        </div>

        <div className="pt-3 border-top">
          <div className="d-flex justify-content-between align-items-center">
            <span className={`fw-bold fs-5 ${vuln.result === 'VULNERABLE' ? 'text-danger' : 'text-success'}`}>
              {vuln.result === 'VULNERABLE' ? 'Vulnerável' : 'Seguro'}
            </span>
            <div className="d-flex gap-1">
              {vuln.jobId && (
                <button
                  onClick={onDownload}
                  className="btn btn-sm btn-outline-primary d-flex align-items-center gap-1"
                  title="Baixar relatório"
                >
                  <Download size={16} /> PDF
                </button>
              )}
              {vuln.responseDetails && (
                <details className="dropdown">
                  <summary className="btn btn-sm btn-outline-secondary">Detalhes</summary>
                  <div className="dropdown-menu show p-3" style={{ maxWidth: '320px', position: 'absolute', right: 0 }}>
                    <pre className="small mb-0 bg-light p-3 rounded" style={{ maxHeight: '200px', overflow: 'auto', fontSize: '0.75rem' }}>
                      {vuln.responseDetails}
                    </pre>
                  </div>
                </details>
              )}
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}