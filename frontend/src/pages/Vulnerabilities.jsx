// src/pages/Vulnerabilities.jsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from '../api/axios'; // seu axios configurado com baseURL
import { AlertCircle, CheckCircle, Download, Search, Filter, RefreshCw, History, Zap, XCircle, Play } from 'lucide-react';

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

  // Carrega histórico de URLs
  useEffect(() => {
    const saved = localStorage.getItem('bounty_url_history');
    if (saved) setUrlHistory(JSON.parse(saved));
  }, []);

  const saveToHistory = (url) => {
    const unique = [...new Set([url, ...urlHistory])].slice(0, 15);
    setUrlHistory(unique);
    localStorage.setItem('bounty_url_history', JSON.stringify(unique));
  };

  // Carrega jobs do backend
  const loadVulns = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await axios.get('/jobs'); // endpoint existente
      let results = data || [];
      // Filtra por search e severity
      if (filter.search) {
        results = results.filter(r => r.targetUrl.toLowerCase().includes(filter.search.toLowerCase()));
      }
      if (filter.severity) {
        results = results.filter(r => r.severity === filter.severity);
      }
      setVulns(results);
    } catch (err) {
      showToast('Erro ao carregar vulnerabilidades', 'danger');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { loadVulns(); }, [loadVulns]);

  // Auto-refresh
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

  // Teste único
  const testSingle = async () => {
    if (!/^https?:\/\//i.test(testUrl)) return showToast('URL inválida. Use http:// ou https://', 'warning');
    setLoading(true);
    try {
      const { data } = await axios.post('/vulnerabilities/test', {
        targetUrl: testUrl,
        vulnerabilityType: selectedType,
      });
      showToast(`Vulnerável! Severidade: ${data.severity}`, data.severity === 'Critical' ? 'danger' : 'success');
      saveToHistory(testUrl);
      loadVulns();
    } catch (err) {
      showToast(err.response?.data?.responseDetails || 'Erro no teste', 'danger');
    } finally {
      setLoading(false);
    }
  };

  // Teste em lote
  const testBatchUrls = async () => {
    const urls = testUrl.split('\n').map(u => u.trim()).filter(Boolean);
    if (urls.length === 0) return showToast('Adicione pelo menos uma URL', 'warning');
    if (urls.length > 50) return showToast('Máximo 50 URLs por lote', 'warning');
    setLoading(true);
    try {
      const requests = urls.map(url => ({ targetUrl: url, vulnerabilityType: selectedType }));
      const { data } = await axios.post('/vulnerabilities/test/batch', requests);
      showToast(`Lote iniciado! Job #${data.jobId} (${urls.length} URLs)`, 'success');
      loadVulns();
    } catch (err) {
      showToast(err.response?.data?.error || 'Erro no lote', 'danger');
    } finally {
      setLoading(false);
    }
  };

  // Download PDF do job
  const downloadPdf = async (jobId) => {
    try {
      const { data } = await axios.post(`/jobs/${jobId}/result`, {}, { responseType: 'blob' });
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
      {/* Toast */}
      <AnimatePresence>
        {toast.show && (
          <motion.div initial={{ x: 300, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 300, opacity: 0 }} className="position-fixed top-0 end-0 p-3" style={{ zIndex: 1055 }}>
            <div className={`alert alert-${toast.type} alert-dismissible fade show shadow-lg d-flex align-items-center gap-2`} role="alert">
              {toast.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
              <div>{toast.message}</div>
              <button type="button" className="btn-close" onClick={() => setToast({ show: false })}></button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="text-center mb-5">
        <h1 className="display-5 fw-bold text-primary d-flex align-items-center justify-content-center gap-2">
          <Zap size={36} /> Scanner de Vulnerabilidades
        </h1>
        <p className="lead text-muted">Teste XXE, SSRF, Template Injection e mais em tempo real</p>
      </motion.div>

      <div className="row g-4">
        <div className="col-lg-11 mx-auto">
          {/* Card de Configuração */}
          <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="card shadow-lg border-0 overflow-hidden" style={{ borderRadius: '1.5rem' }}>
            <div className="card-header bg-gradient text-white" style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
              <div className="d-flex justify-content-between align-items-center">
                <h5 className="mb-0 fw-bold d-flex align-items-center gap-2">
                  <Filter size={20} /> Configurar Teste
                </h5>
                <div className="form-check form-switch">
                  <input className="form-check-input" type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} id="autoRefresh" />
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
                    <span className="input-group-text bg-light border-end-0"><Search size={18} /></span>
                    <input type="text" className="form-control border-start-0" placeholder="Buscar por URL ou tipo..." value={filter.search} onChange={e => setFilter({ ...filter, search: e.target.value })} />
                  </div>
                </div>
                <div className="col-md-4">
                  <select className="form-select" value={filter.severity} onChange={e => setFilter({ ...filter, severity: e.target.value })}>
                    <option value="">Todas as severidades</option>
                    {['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
              </div>

              {/* Tabs */}
              <ul className="nav nav-pills mb-4 border-bottom">
                <li className="nav-item">
                  <button className={`nav-link d-flex align-items-center gap-2 ${activeTab === 'single' ? 'active' : ''}`} onClick={() => setActiveTab('single')}>
                    <Play size={16} /> Teste Único
                  </button>
                </li>
                <li className="nav-item">
                  <button className={`nav-link d-flex align-items-center gap-2 ${activeTab === 'batch' ? 'active' : ''}`} onClick={() => setActiveTab('batch')}>
                    <RefreshCw size={16} /> Lote
                  </button>
                </li>
              </ul>

              {/* Input com Histórico */}
              <div className="mb-4">
                <div className="input-group">
                  {activeTab === 'batch' ? (
                    <textarea className="form-control" rows={5} value={testUrl} onChange={e => setTestUrl(e.target.value)} placeholder="Cole uma URL por linha (máx. 50)..." style={{ resize: 'none', fontFamily: 'monospace' }} />
                  ) : (
                    <input type="url" className="form-control" value={testUrl} onChange={e => setTestUrl(e.target.value)} placeholder="https://alvo.com/vuln" />
                  )}
                  <button className="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-label="Histórico de URLs">
                    <History size={18} />
                  </button>
                  <ul className="dropdown-menu dropdown-menu-end shadow-sm" style={{ maxHeight: '300px', overflowY: 'auto' }}>
                    {urlHistory.length === 0 ? (
                      <li><span className="dropdown-item text-muted">Nenhum histórico</span></li>
                    ) : (
                      urlHistory.map((url, i) => (
                        <li key={i}>
                          <button className="dropdown-item d-flex justify-content-between align-items-center" onClick={() => setTestUrl(url)}>
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
                    <select className="form-select form-select-lg" value={selectedType} onChange={e => setSelectedType(e.target.value)}>
                      {vulnTypes.map(t => <option key={t.id} value={t.id}>{t.icon} {t.name} ({t.severity})</option>)}
                    </select>
                  </div>
                  <div className="col-md-4 d-grid">
                    <button className="btn btn-primary btn-lg" onClick={testSingle} disabled={loading}>
                      {loading ? 'Testando...' : <><Play size={16} /> Testar</>}
                    </button>
                  </div>
                </div>
              ) : (
                <div className="d-grid">
                  <button className="btn btn-warning btn-lg" onClick={testBatchUrls} disabled={loading}>
                    {loading ? 'Processando lote...' : <><RefreshCw size={16} /> Iniciar Lote</>}
                  </button>
                </div>
              )}
            </div>
          </motion.div>
        </div>
      </div>

      {/* Lista de Vulnerabilidades */}
      <div className="row mt-5 g-4">
        {loading ? (
          <div className="text-center text-muted fw-bold">Carregando vulnerabilidades...</div>
        ) : (
          vulns.map(v => (
            <motion.div key={v.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="col-lg-6">
              <div className={`card shadow-sm border-start border-4 border-${v.severity === 'Critical' ? 'danger' : v.severity === 'High' ? 'warning' : 'secondary'}`}>
                <div className="card-body">
                  <h5 className="card-title text-truncate">{v.targetUrl}</h5>
                  <p className="card-text mb-1"><strong>Tipo:</strong> {v.vulnerabilityType}</p>
                  <p className="card-text mb-1"><strong>Severidade:</strong> {v.severity}</p>
                  <p className="card-text"><strong>Status:</strong> {v.status || 'Pendente'}</p>
                  {v.jobId && (
                    <button className="btn btn-sm btn-outline-primary" onClick={() => downloadPdf(v.jobId)}>
                      <Download size={14} /> PDF
                    </button>
                  )}
                </div>
              </div>
            </motion.div>
          ))
        )}
      </div>
    </div>
  );
}
