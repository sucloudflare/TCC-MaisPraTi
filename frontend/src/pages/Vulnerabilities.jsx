// src/pages/Vulnerabilities.jsx
import { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from '../api/axios';
import { AlertCircle, CheckCircle, Download, Search, Filter, RefreshCw, History, Zap, XCircle, Play } from 'lucide-react';

// --- Somente vulnerabilidades reais / CVEs ---
const vulnTypes = [
  { id: 'Log4Shell (CVE-2021-44228)', name: 'Log4Shell (CVE-2021-44228)', severity: 'Critical', icon: '🔥' },
  { id: 'PrintNightmare (CVE-2021-34527)', name: 'PrintNightmare (CVE-2021-34527)', severity: 'Critical', icon: '🖨️' },
  { id: 'Exchange ProxyLogon (CVE-2021-26855)', name: 'Exchange ProxyLogon (CVE-2021-26855)', severity: 'Critical', icon: '✉️' },
  { id: 'CVE-2023-23397', name: 'CVE-2023-23397', severity: 'Critical', icon: '🔥' },
  { id: 'BlueKeep (CVE-2019-0708)', name: 'BlueKeep (CVE-2019-0708)', severity: 'Critical', icon: '🧊' },
  { id: 'EternalBlue (CVE-2017-0144)', name: 'EternalBlue (CVE-2017-0144)', severity: 'Critical', icon: '💣' },
  { id: 'Zerologon (CVE-2020-1472)', name: 'Zerologon (CVE-2020-1472)', severity: 'Critical', icon: '🔐' },
  { id: 'Apache Struts2 RCE (CVE-2017-5638)', name: 'Apache Struts2 RCE (CVE-2017-5638)', severity: 'High', icon: '⚠️' },
  { id: 'Double Kill (CVE-2018-8174)', name: 'Double Kill (CVE-2018-8174)', severity: 'High', icon: '⚠️' },
  { id: 'Pulse Secure VPN RCE (CVE-2019-11510)', name: 'Pulse Secure VPN RCE (CVE-2019-11510)', severity: 'High', icon: '🔓' },
  { id: 'Confluence OGNL Injection (CVE-2022-26134)', name: 'Confluence OGNL Injection (CVE-2022-26134)', severity: 'High', icon: '📌' },
  { id: 'Spring4Shell (CVE-2022-22965)', name: 'Spring4Shell (CVE-2022-22965)', severity: 'Critical', icon: '🌱' },
  { id: 'Microsoft Exchange SSRF (CVE-2021-31207)', name: 'Microsoft Exchange SSRF (CVE-2021-31207)', severity: 'High', icon: '✉️' },
  { id: 'Citrix ADC / Gateway (CVE-2019-19781)', name: 'Citrix ADC/Gateway (CVE-2019-19781)', severity: 'Critical', icon: '🔑' },
  { id: 'SolarWinds Supply Chain', name: 'SolarWinds Supply Chain', severity: 'Critical', icon: '🔗' },
  { id: 'Log4j2 JNDI LDAP Injection', name: 'Log4j2 JNDI LDAP Injection', severity: 'Critical', icon: '🪪' },
  { id: 'OpenSSL Heartbleed (CVE-2014-0160)', name: 'Heartbleed (CVE-2014-0160)', severity: 'High', icon: '💔' },
  { id: 'Shellshock (CVE-2014-6271)', name: 'Shellshock (CVE-2014-6271)', severity: 'High', icon: '🐚' },
  { id: 'Drupalgeddon (CVE-2018-7600)', name: 'Drupalgeddon (CVE-2018-7600)', severity: 'High', icon: '🌐' },
  { id: 'Grafana Auth Bypass (CVE-2021-43798)', name: 'Grafana Auth Bypass (CVE-2021-43798)', severity: 'High', icon: '📈' },
  { id: 'F5 BIG-IP iControl REST (CVE-2020-5902)', name: 'F5 BIG-IP iControl REST (CVE-2020-5902)', severity: 'Critical', icon: '🛡️' },
  { id: 'VMware vCenter RCE', name: 'VMware vCenter RCE', severity: 'Critical', icon: '🖥️' },
  { id: 'Adobe ColdFusion RCE', name: 'Adobe ColdFusion RCE', severity: 'High', icon: '📄' },
  { id: 'Fortinet SSL-VPN (CVE-2018-13379)', name: 'Fortinet SSL-VPN (CVE-2018-13379)', severity: 'High', icon: '🔒' },
  { id: 'SambaCry (CVE-2017-7494)', name: 'SambaCry (CVE-2017-7494)', severity: 'High', icon: '🗃️' },
  { id: 'Juniper ScreenOS (CVE-2015-7755)', name: 'Juniper ScreenOS (CVE-2015-7755)', severity: 'High', icon: '📡' },
  { id: 'RCE via deserialization (Java)', name: 'RCE via deserialization (Java)', severity: 'Critical', icon: '☠️' },
  { id: 'OAuth Token Forgery', name: 'OAuth Token Forgery', severity: 'High', icon: '🔑' },
  { id: 'Cross-Site Scripting (XSS)', name: 'Cross-Site Scripting (XSS)', severity: 'Medium', icon: '⚠️' },
  { id: 'SQL Injection', name: 'SQL Injection', severity: 'Critical', icon: '🧭' },
];

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [filter, setFilter] = useState({ search: '', severity: '' });
  const [testUrl, setTestUrl] = useState('');
  const [selectedType, setSelectedType] = useState(vulnTypes[0].id);
  const [loading, setLoading] = useState(false);
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
    const saved = localStorage.getItem('bounty_url_history');
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
      const { data } = await axios.get('/jobs');
      let results = data || [];
      if (filter.search) results = results.filter(r => r.targetUrl.toLowerCase().includes(filter.search.toLowerCase()));
      if (filter.severity) results = results.filter(r => r.severity === filter.severity);
      setVulns(results);
    } catch (err) {
      showToast('Erro ao carregar vulnerabilidades', 'danger');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { loadVulns(); }, [loadVulns]);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(loadVulns, 5000);
      countdownRef.current = setInterval(() => setRefreshCountdown(prev => prev <= 1 ? 5 : prev - 1), 1000);
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

  // 🔹 Corrigido endpoint POST
  const testSingle = async () => {
    if (!/^https?:\/\//i.test(testUrl)) return showToast('URL inválida. Use http:// ou https://', 'warning');
    setLoading(true);
    try {
      const { data } = await axios.post('/jobs/test', { targetUrl: testUrl, vulnerabilityType: selectedType });
      showToast(`Vulnerável! Severidade: ${data.severity}`, data.severity === 'Critical' ? 'danger' : 'success');
      saveToHistory(testUrl);
      loadVulns();
    } catch (err) {
      showToast(err.response?.data?.responseDetails || 'Erro no teste', 'danger');
    } finally {
      setLoading(false);
    }
  };

  // 🔹 Corrigido download PDF
  const downloadPdf = async (jobId) => {
    try {
      const { data } = await axios.post(`/jobs/${jobId}/report`, {}, { responseType: 'blob' });
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
    <div className="container py-5" style={{ background: '#ffffffff', minHeight: '100vh' }}>
      {/* Toast */}
      <AnimatePresence>
        {toast.show && (
          <motion.div initial={{ x: 300, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 300, opacity: 0 }} className="position-fixed top-0 end-0 p-3" style={{ zIndex: 1055 }}>
            <div className={`alert alert-${toast.type} alert-dismissible fade show d-flex align-items-center gap-2`} role="alert" style={{ borderRadius: '1rem', fontWeight: 500, border: '1px solid black', background: '#e9ecef' }}>
              {toast.type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
              <div>{toast.message}</div>
              <button type="button" className="btn-close" onClick={() => setToast({ show: false })}></button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="text-center mb-5">
        <h1 className="display-5 fw-bold d-flex align-items-center justify-content-center gap-2">
          <Zap size={36} /> Scanner de Vulnerabilidades
        </h1>
        <p className="lead text-muted">Teste vulnerabilidades reais em tempo real</p>
      </motion.div>

      {/* Card de Teste */}
      <div className="row g-4">
        <div className="col-lg-11 mx-auto">
          <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="card" style={{ borderRadius: '1.5rem', border: '1px solid black', background: '#e9ecef' }}>
            <div className="card-header d-flex justify-content-between align-items-center" style={{ borderBottom: '1px solid black', background: '#e9ecef' }}>
              <h5 className="mb-0 fw-bold d-flex align-items-center gap-2">
                <Filter size={20} /> Configurar Teste
              </h5>
              <div className="form-check form-switch">
                <input className="form-check-input" type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} id="autoRefresh" />
                <label className="form-check-label" htmlFor="autoRefresh">
                  Auto-refresh {autoRefresh && <span className="badge bg-light text-dark ms-1">{refreshCountdown}s</span>}
                </label>
              </div>
            </div>

            <div className="card-body p-4">
              <div className="row g-3 mb-4">
                <div className="col-md-8">
                  <div className="input-group" style={{ border: '1px solid black', borderRadius: '0.5rem', overflow: 'hidden', background: '#f8f9fa' }}>
                    <span className="input-group-text" style={{ border: 'none', background: 'transparent' }}><Search size={18} /></span>
                    <input type="text" className="form-control" placeholder="Buscar por URL..." value={filter.search} onChange={e => setFilter({ ...filter, search: e.target.value })} style={{ border: 'none', background: 'transparent' }} />
                  </div>
                </div>
                <div className="col-md-4">
                  <select className="form-select" value={filter.severity} onChange={e => setFilter({ ...filter, severity: e.target.value })} style={{ border: '1px solid black', background: '#f8f9fa' }}>
                    <option value="">Todas as severidades</option>
                    {['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
              </div>

              <div className="input-group mb-4" style={{ border: '1px solid black', borderRadius: '0.5rem', background: '#ffffffff' }}>
                <input type="url" className="form-control" value={testUrl} onChange={e => setTestUrl(e.target.value)} placeholder="https://alvo.com/vuln" style={{ border: 'none', background: 'transparent' }} />
              </div>

              <div className="row g-3 align-items-center">
                <div className="col-md-8">
                  <select className="form-select form-select-lg" value={selectedType} onChange={e => setSelectedType(e.target.value)} style={{ border: '1px solid black', background: '#f8f9fa' }}>
                    {vulnTypes.map(t => <option key={t.id} value={t.id}>{t.icon} {t.name} ({t.severity})</option>)}
                  </select>
                </div>
                <div className="col-md-4 d-grid">
                  <button className="btn" onClick={testSingle} disabled={loading} style={{ border: '1px solid black', background: '#f8f9fa' }}>
                    {loading ? 'Testando...' : <><Play size={16} /> Testar</>}
                  </button>
                </div>
              </div>
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
              <div className="card" style={{
                border: '1px solid black',
                borderRadius: '1rem',
                transition: 'all 0.3s',
                background: '#ffffffff',
              }}>
                <div className="card-body">
                  <h5 className="card-title text-truncate fw-bold">{v.targetUrl}</h5>
                  <p className="card-text mb-1"><strong>Tipo:</strong> {v.vulnerabilityType}</p>
                  <p className="card-text mb-1"><strong>Severidade:</strong> {v.severity}</p>
                  <p className="card-text"><strong>Status:</strong> {v.status || 'Pendente'}</p>
                  {v.jobId && (
                    <button className="btn" onClick={() => downloadPdf(v.jobId)} style={{ border: '1px solid black', background: '#ffffffff', marginTop: '0.5rem' }}>
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
