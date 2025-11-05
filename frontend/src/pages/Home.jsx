import React from 'react';
import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
import { useNavigate } from 'react-router-dom';

const Home = () => {
  const whiteText = { color: '#ffffff' };
  const navigate = useNavigate();

  const bannerStyle = (url) => ({
    backgroundImage: `url(${url})`,
    backgroundRepeat: "no-repeat",
    backgroundPosition: "center center",
    backgroundSize: "cover",
    width: "100%",
    minHeight: "300px",
    maxHeight: "400px",
    borderRadius: "12px",
    boxShadow: "0 8px 25px rgba(0,0,0,0.4)",
    marginBottom: "40px",
  });

  const btnLoginStyle = {
    backgroundColor: '#0a0e27',
    color: '#ffffff',
    border: '2px solid #1f2545',
    fontWeight: '600',
    fontSize: '1rem',
    padding: '12px 36px',
    borderRadius: '10px',
    backdropFilter: 'blur(4px)',
    transition: 'all 0.4s ease',
    boxShadow: '0 4px 15px rgba(0,0,0,0.3)',
  };

  const btnLoginHover = {
    backgroundColor: '#141a38',
    color: '#ffffff',
    border: '2px solid #00d4ff',
    boxShadow: '0 6px 20px rgba(0,0,0,0.5)',
    transform: 'translateY(-2px)',
  };

  const cardStyle = {
    backgroundColor: 'rgba(15,18,53,0.8)',
    border: '1px solid #1f2545',
    borderRadius: '12px',
    padding: '30px 20px',
    backdropFilter: 'blur(8px)',
    transition: 'all 0.3s ease',
    boxShadow: '0 8px 25px rgba(0,0,0,0.4)',
  };

  const cardHover = {
    transform: 'translateY(-5px)',
    boxShadow: '0 12px 30px rgba(0,0,0,0.6)',
    border: '1px solid #00d4ff',
  };

  return (
    <div style={{ backgroundColor: '#0a0e27', fontFamily: "'Inter', sans-serif'" }}>
      
      {/* Navegação */}
      <nav className="navbar navbar-expand-lg navbar-dark fixed-top py-3" style={{ backdropFilter: 'blur(10px)', backgroundColor: 'rgba(10,14,39,0.9)' }}>
        <div className="container">
          <a className="navbar-brand d-flex align-items-center" href="#" style={{ fontWeight: '700', fontSize: '24px', color: '#ffffff' }}>
            <i className="bi bi-hexagon-fill me-2"></i>
            BugBountyHub
          </a>
          <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span className="navbar-toggler-icon"></span>
          </button>
          <div className="collapse navbar-collapse" id="navbarNav">
            <ul className="navbar-nav ms-auto">
              <li className="nav-item"><a className="nav-link px-3" href="#home" style={whiteText}>Início</a></li>
              <li className="nav-item"><a className="nav-link px-3" href="#features" style={whiteText}>Recursos</a></li>
              <li className="nav-item"><a className="nav-link px-3" href="#bugbounty" style={whiteText}>Bug Bounty</a></li>
              <li className="nav-item"><a className="nav-link px-3" href="#contact" style={whiteText}>Contato</a></li>
            </ul>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="py-5" id="home" style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', background: 'linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%)' }}>
        <div className="container text-center text-lg-start">
          <div className="row align-items-center">
            <div className="col-lg-6">
              <h1 className="display-4 fw-bold mb-4" style={whiteText}>
                Bem-vindo ao <span style={{ color: '#00d4ff' }}>Bug Bounty Hub</span>
              </h1>
              <p className="lead mb-4" style={whiteText}>
                Aprenda, reporte e ganhe recompensas encontrando vulnerabilidades. Conectamos pesquisadores de segurança com empresas para melhorar a web.
              </p>
              <button
                className="btn"
                style={btnLoginStyle}
                onMouseOver={e => Object.assign(e.target.style, btnLoginHover)}
                onMouseOut={e => Object.assign(e.target.style, btnLoginStyle)}
                onClick={() => navigate('/login')}
              >
                Login
              </button>
            </div>
            <div className="col-lg-6 text-center mt-4 mt-lg-0">
              <i className="bi bi-shield-lock" style={{ fontSize: '150px', color: '#ffffff', opacity: 0.85 }}></i>
            </div>
          </div>
        </div>
      </section>

      {/* Seção Recursos */}
      <section className="py-5" id="features">
        <div className="container">
          <div className="text-center mb-5">
            <h2 className="fw-bold display-5" style={whiteText}>Recursos da Plataforma</h2>
            <p className="lead" style={whiteText}>Tudo que você precisa para participar de programas de bug bounty e aprimorar suas habilidades.</p>
          </div>
          <div className="row g-4">
            {[
              { icon: "bi-search", title: "Descoberta de Vulnerabilidades", desc: "Identifique e reporte vulnerabilidades em sites e apps." },
              { icon: "bi-cash-stack", title: "Ganhe Recompensas", desc: "Receba pagamentos por relatórios válidos." },
              { icon: "bi-people", title: "Aprendizado Comunitário", desc: "Participe de uma comunidade global de hackers éticos." },
              { icon: "bi-bug", title: "Relatórios Profissionais", desc: "Crie relatórios claros e profissionais." },
              { icon: "bi-lightning-charge", title: "Alerts Instantâneos", desc: "Receba notificações em tempo real." },
              { icon: "bi-shield-check", title: "Segurança Garantida", desc: "Proteja seus dados e atividades na plataforma." }
            ].map((card, i) => (
              <div className="col-md-4" key={i}>
                <div
                  className="card text-center h-100"
                  style={cardStyle}
                  onMouseOver={e => Object.assign(e.currentTarget.style, cardHover)}
                  onMouseOut={e => Object.assign(e.currentTarget.style, cardStyle)}
                >
                  <div className="mb-3">
                    <i className={`bi ${card.icon}`} style={{ fontSize: '40px', color: '#ffffff' }}></i>
                  </div>
                  <h5 className="fw-bold" style={whiteText}>{card.title}</h5>
                  <p style={whiteText}>{card.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Banner próximo ao footer */}
      <div style={bannerStyle('https://i.pinimg.com/1200x/57/59/71/5759711ee29e6c6e247ad2e43fada42e.jpg')}></div>

      {/* Seção Bug Bounty */}
      <section className="py-5" id="bugbounty" style={{ backgroundColor: '#0f1235' }}>
        <div className="container">
          <div className="text-center mb-5">
            <h2 className="display-5 fw-bold" style={whiteText}>Sobre Programas Bug Bounty</h2>
            <p className="lead" style={whiteText}>
              Programas Bug Bounty permitem que pesquisadores reportem vulnerabilidades e recebam recompensas de forma legal e ética.
            </p>
          </div>
          <div className="row g-4">
            <div className="col-md-6">
              <div style={cardStyle}>
                <h5 className="fw-bold" style={whiteText}>Por que Participar?</h5>
                <p style={whiteText}>Aprimore habilidades, construa reputação e ganhe dinheiro reportando falhas.</p>
              </div>
            </div>
            <div className="col-md-6">
              <div style={cardStyle}>
                <h5 className="fw-bold" style={whiteText}>Como Funciona</h5>
                <p style={whiteText}>Empresas definem escopos. Hackers reportam problemas. Relatórios válidos recebem recompensas.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Contato */}
      <section className="py-5" id="contact">
        <div className="container text-center">
          <h2 className="display-5 fw-bold mb-4" style={whiteText}>Contato</h2>
          <p className="lead mb-4" style={whiteText}>Dúvidas ou interesse em participar? Entre em contato!</p>
          <button
            className="btn"
            style={btnLoginStyle}
            onMouseOver={e => Object.assign(e.target.style, btnLoginHover)}
            onMouseOut={e => Object.assign(e.target.style, btnLoginStyle)}
            onClick={() => navigate('/login')}
          >
            Login
          </button>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-5" style={{ backgroundColor: '#0a0e27' }}>
        <div className="container text-center text-md-start">
          <div className="row">
            <div className="col-md-4 mb-4">
              <h5 className="fw-bold" style={whiteText}>BugBountyHub</h5>
              <p style={whiteText}>Conectando hackers éticos com empresas para uma web mais segura.</p>
            </div>
            <div className="col-md-4 mb-4">
              <h6 className="fw-bold" style={{ color: '#00d4ff' }}>Links Rápidos</h6>
              <ul className="list-unstyled">
                <li><a href="#home" style={whiteText} className="text-decoration-none">Início</a></li>
                <li><a href="#features" style={whiteText} className="text-decoration-none">Recursos</a></li>
                <li><a href="#bugbounty" style={whiteText} className="text-decoration-none">Bug Bounty</a></li>
                <li><a href="#contact" style={whiteText} className="text-decoration-none">Contato</a></li>
              </ul>
            </div>
            <div className="col-md-4 mb-4">
              <h6 className="fw-bold" style={{ color: '#00d4ff' }}>Redes Sociais</h6>
              <a href="#" style={whiteText} className="me-2"><i className="bi bi-twitter"></i></a>
              <a href="#" style={whiteText} className="me-2"><i className="bi bi-github"></i></a>
              <a href="#" style={whiteText}><i className="bi bi-linkedin"></i></a>
            </div>
          </div>
          <hr className="border-secondary" />
          <p className="text-center" style={whiteText}>© 2025 BugBountyHub. Todos os direitos reservados.</p>
        </div>
      </footer>
    </div>
  );
};

export default Home;
