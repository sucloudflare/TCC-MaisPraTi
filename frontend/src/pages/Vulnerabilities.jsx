// src/pages/Vulnerabilities.jsx
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from '../api/axios';
import { 
  AlertCircle, 
  CheckCircle, 
  Download, 
  Search, 
  Filter, 
  RefreshCw, 
  History, 
  Zap, 
  XCircle, 
  Play, 
  Shield, 
  ShieldOff,
  AlertTriangle
} from 'lucide-react';

const vulnTypes = [
  { id: 'Log4Shell (CVE-2021-44228)', name: 'Log4Shell (CVE-2021-44228)', severity: 'Critical' },
  { id: 'PrintNightmare (CVE-2021-34527)', name: 'PrintNightmare (CVE-2021-34527)', severity: 'Critical' },
  { id: 'Exchange ProxyLogon (CVE-2021-26855)', name: 'Exchange ProxyLogon (CVE-2021-26855)', severity: 'Critical' },
  { id: 'CVE-2023-23397', name: 'CVE-2023-23397', severity: 'Critical' },
  { id: 'BlueKeep (CVE-2019-0708)', name: 'BlueKeep (CVE-2019-0708)', severity: 'Critical' },
  { id: 'EternalBlue (CVE-2017-0144)', name: 'EternalBlue (CVE-2017-0144)', severity: 'Critical' },
  { id: 'Zerologon (CVE-2020-1472)', name: 'Zerologon (CVE-2020-1472)', severity: 'Critical' },
  { id: 'Apache Struts2 RCE (CVE-2017-5638)', name: 'Apache Struts2 RCE (CVE-2017-5638)', severity: 'High' },
  { id: 'Double Kill (CVE-2018-8174)', name: 'Double Kill (CVE-2018-8174)', severity: 'High' },
  { id: 'Pulse Secure VPN RCE (CVE-2019-11510)', name: 'Pulse Secure VPN RCE (CVE-2019-11510)', severity: 'High' },
  { id: 'Confluence OGNL Injection (CVE-2022-26134)', name: 'Confluence OGNL Injection (CVE-2022-26134)', severity: 'High' },
  { id: 'Spring4Shell (CVE-2022-22965)', name: 'Spring4Shell (CVE-2022-22965)', severity: 'Critical' },
  { id: 'Microsoft Exchange SSRF (CVE-2021-31207)', name: 'Microsoft Exchange SSRF (CVE-2021-31207)', severity: 'High' },
  { id: 'Citrix ADC / Gateway (CVE-2019-19781)', name: 'Citrix ADC/Gateway (CVE-2019-19781)', severity: 'Critical' },
  { id: 'SolarWinds Supply Chain', name: 'SolarWinds Supply Chain', severity: 'Critical' },
  { id: 'Log4j2 JNDI LDAP Injection', name: 'Log4j2 JNDI LDAP Injection', severity: 'Critical' },
  { id: 'OpenSSL Heartbleed (CVE-2014-0160)', name: 'Heartbleed (CVE-2014-0160)', severity: 'High' },
  { id: 'Shellshock (CVE-2014-6271)', name: 'Shellshock (CVE-2014-6271)', severity: 'High' },
  { id: 'Drupalgeddon (CVE-2018-7600)', name: 'Drupalgeddon (CVE-2018-7600)', severity: 'High' },
  { id: 'Grafana Auth Bypass (CVE-2021-43798)', name: 'Grafana Auth Bypass (CVE-2021-43798)', severity: 'High' },
  { id: 'F5 BIG-IP iControl REST (CVE-2020-5902)', name: 'F5 BIG-IP iControl REST (CVE-2020-5902)', severity: 'Critical' },
  { id: 'VMware vCenter RCE', name: 'VMware vCenter RCE', severity: 'Critical' },
  { id: 'Adobe ColdFusion RCE', name: 'Adobe ColdFusion RCE', severity: 'High' },
  { id: 'Fortinet SSL-VPN (CVE-2018-13379)', name: 'Fortinet SSL-VPN (CVE-2018-13379)', severity: 'High' },
  { id: 'SambaCry (CVE-2017-7494)', name: 'SambaCry (CVE-2017-7494)', severity: 'High' },
  { id: 'Juniper ScreenOS (CVE-2015-7755)', name: 'Juniper ScreenOS (CVE-2015-7755)', severity: 'High' },
  { id: 'RCE via deserialization (Java)', name: 'RCE via deserialization (Java)', severity: 'Critical' },
  { id: 'OAuth Token Forgery', name: 'OAuth Token Forgery', severity: 'High' },
  { id: 'Cross-Site Scripting (XSS)', name: 'Cross-Site Scripting (XSS)', severity: 'Medium' },
  { id: 'SQL Injection', name: 'SQL Injection', severity: 'Critical' },
];

const getDifficultyColor = (d) => ({
  Critical: 'bg-danger text-white',
  High: 'bg-warning text-dark',
  Medium: 'bg-success text-white',
  Low: 'bg-secondary text-white'
})[d] || 'bg-secondary text-white';

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [filter, setFilter] = useState({ search: '', severity: 'All' });
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
    setTimeout(() => setToast({ show: false }), 4000);
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
      let results = Array.isArray(data) ? data : [];
      
      if (filter.search) {
        results = results.filter(r => 
          r.targetUrl?.toLowerCase().includes(filter.search.toLowerCase())
        );
      }
      
      if (filter.severity !== 'All') {
        results = results.filter(r => r.severity === filter.severity);
      }
      
      setVulns(results);
    } catch (err) {
      showToast('Erro ao carregar vulnerabilidades', 'danger');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { 
    loadVulns(); 
  }, [loadVulns]);

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
    if (!testUrl || !/^https?:\/\//i.test(testUrl)) {
      return showToast('URL inválida. Use http:// ou https://', 'danger');
    }

    setLoading(true);
    try {
      const { data } = await axios.post('/jobs/test', { 
        targetUrl: testUrl.trim(), 
        vulnerabilityType: selectedType 
      });

      const isVuln = data.result === 'VULNERABLE';
      const msg = isVuln 
        ? `VULNERÁVEL! ${data.severity || 'Critical'} - ${selectedType}`
        : `SEGURO contra ${selectedType}`;

      showToast(msg, isVuln ? 'danger' : 'success');
      saveToHistory(testUrl);
      loadVulns();
    } catch (err) {
      const msg = err.response?.data?.responseDetails || err.message || 'Erro no teste';
      showToast(`ERRO: ${msg}`, 'danger');
    } finally {
      setLoading(false);
    }
  };

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
    <div className="min-vh-100" style={{ background: '#f1f3f5' }}>
      <AnimatePresence>
        {toast.show && (
          <motion.div 
            initial={{ x: 300, opacity: 0 }} 
            animate={{ x: 0, opacity: 1 }} 
            exit={{ x: 300, opacity: 0 }} 
            className="position-fixed top-0 end-0 p-3" 
            style={{ zIndex: 1055 }}
          >
            <div 
              className={`alert alert-${toast.type} alert-dismissible fade show d-flex align-items-center gap-2 shadow-lg`} 
              role="alert" 
              style={{ 
                borderRadius: '1rem', 
                fontWeight: 600, 
                border: '1px solid black',
                background: toast.type === 'danger' ? '#ffe6e6' : '#e6f7e6',
                minWidth: '320px'
              }}
            >
              {toast.type === 'success' ? <CheckCircle size={20} /> : <AlertCircle size={20} />}
              <div>{toast.message}</div>
              <button 
                type="button" 
                className="btn-close" 
                onClick={() => setToast({ show: false })} 
                aria-label="Fechar"
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <header className="sticky-top" style={{ borderBottom: '1px solid black', background: '#e9ecef' }}>
        <div className="container py-4 d-flex justify-content-between align-items-center">
          <div>
            <h1 className="h4 fw-bold d-flex align-items-center gap-2">
              <Zap size={24} /> Scanner de Vulnerabilidades
            </h1>
            <p className="text-muted mb-0">Teste CVEs reais</p>
          </div>
          <div className="form-check form-switch">
            <input 
              className="form-check-input" 
              type="checkbox" 
              checked={autoRefresh} 
              onChange={e => setAutoRefresh(e.target.checked)} 
              id="autoRefresh"
            />
            <label className="form-check-label" htmlFor="autoRefresh">
              Auto {autoRefresh && <span className="badge bg-primary ms-1">{refreshCountdown}s</span>}
            </label>
          </div>
        </div>
      </header>

      <div className="container py-5">
        <div className="row g-4">
          <div className="col-lg-4">
            <motion.div 
              initial={{ opacity: 0, x: -20 }} 
              animate={{ opacity: 1, x: 0 }} 
              className="card" 
              style={{ borderRadius: '1rem', border: '1px solid black', background: '#e9ecef', position: 'sticky', top: '1rem' }}
            >
              <div className="card-header" style={{ background: '#e9ecef', borderBottom: '1px solid black' }}>
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <strong className="d-flex align-items-center gap-2">
                    <Filter size={18} /> Filtros
                  </strong>
                  <small className="text-muted">{vulns.length}</small>
                </div>
                <div className="input-group mb-3" style={{ border: '1px solid black', borderRadius: '0.5rem', background: '#f8f9fa' }}>
                  <span className="input-group-text" style={{ border: 'none', background: 'transparent' }}><Search size={16} /></span>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Buscar URL..."
                    value={filter.search}
                    onChange={e => setFilter({ ...filter, search: e.target.value })}
                    style={{ border: 'none', background: 'transparent' }}
                  />
                </div>
                <select 
                  className="form-select" 
                  value={filter.severity} 
                  onChange={e => setFilter({ ...filter, severity: e.target.value })}
                  style={{ border: '1px solid black', background: '#f8f9fa' }}
                >
                  <option value="All">Todas as severidades</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                </select>
              </div>
            </motion.div>
          </div>

          <div className="col-lg-8">
            <motion.div 
              initial={{ opacity: 0, x: 20 }} 
              animate={{ opacity: 1, x: 0 }} 
              className="card" 
              style={{ borderRadius: '1rem', border: '1px solid black', background: '#e9ecef' }}
            >
              <div className="card-header d-flex justify-content-between align-items-start flex-wrap gap-2" style={{ background: '#e9ecef', borderBottom: '1px solid black' }}>
                <div>
                  <h5 className="mb-1 d-flex align-items-center gap-2">
                    <Play size={20} /> Teste Rápido
                  </h5>
                  <p className="text-muted small mb-2">Selecione uma CVE e teste</p>
                </div>
                <div className="d-flex gap-2">
                  <button 
                    onClick={testSingle} 
                    disabled={loading || !testUrl}
                    className="btn d-flex align-items-center gap-1" 
                    style={{ border: '1px solid black', background: '#f8f9fa' }}
                  >
                    <Play size={16} /> {loading ? 'Testando...' : 'Testar'}
                  </button>
                </div>
              </div>

              <div className="card-body">
                <div className="row g-3">
                  <div className="col-12">
                    <input 
                      type="url" 
                      className="form-control" 
                      value={testUrl} 
                      onChange={e => setTestUrl(e.target.value)} 
                      placeholder="https://alvo.com" 
                      style={{ border: '1px solid black', background: '#f8f9fa' }}
                    />
                  </div>
                  <div className="col-12">
                    <select 
                      className="form-select" 
                      value={selectedType} 
                      onChange={e => setSelectedType(e.target.value)}
                      style={{ border: '1px solid black', background: '#f8f9fa' }}
                    >
                      {vulnTypes.map(t => (
                        <option key={t.id} value={t.id}>
                          {t.name} ({t.severity})
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="mt-4">
                  {loading && vulns.length === 0 ? (
                    <div className="text-center py-5">
                      <div className="spinner-border text-primary" role="status" />
                    </div>
                  ) : vulns.length === 0 ? (
                    <div className="text-center py-5 text-muted">
                      <History size={48} className="mb-3" />
                      <p>Nenhum job encontrado</p>
                    </div>
                  ) : (
                    <div className="row g-3">
                      {vulns.map(v => {
                        const isVuln = v.result === 'VULNERABLE';
                        const isError = v.result === 'ERROR';
                        return (
                          <motion.div 
                            key={v.id} 
                            whileHover={{ x: 4 }}
                            className="col-12"
                          >
                            <div 
                              className="p-3 rounded" 
                              style={{ 
                                border: '1px solid black', 
                                background: '#f8f9fa',
                                borderLeft: `4px solid ${isVuln ? '#dc3545' : isError ? '#fd7e14' : '#198754'}`
                              }}
                            >
                              <div className="d-flex justify-content-between align-items-center">
                                <div>
                                  <strong>{v.targetUrl}</strong>
                                  <span className="text-muted ms-2">— {v.vulnerabilityType}</span>
                                </div>
                                <div className="d-flex align-items-center gap-2">
                                  <span className={`badge rounded-pill ${getDifficultyColor(v.severity)}`}>
                                    {v.severity}
                                  </span>
                                  <span className="fw-bold" style={{ color: isVuln ? '#dc3545' : isError ? '#fd7e14' : '#198754' }}>
                                    {isVuln ? 'VULNERÁVEL' : isError ? 'ERRO' : 'SEGURO'}
                                  </span>
                                </div>
                              </div>
                              {v.responseDetails && (
                                <details className="mt-2">
                                  <summary className="text-muted small" style={{ cursor: 'pointer' }}>Detalhes</summary>
                                  <pre className="small mt-1 text-muted" style={{ whiteSpace: 'pre-wrap', fontSize: '0.8rem' }}>
                                    {v.responseDetails}
                                  </pre>
                                </details>
                              )}
                              {v.jobId && (
                                <button 
                                  onClick={() => downloadPdf(v.jobId)}
                                  className="btn btn-sm mt-2" 
                                  style={{ border: '1px solid black', background: '#f8f9fa' }}
                                >
                                  <Download size={14} /> Relatório
                                </button>
                              )}
                            </div>
                          </motion.div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
}