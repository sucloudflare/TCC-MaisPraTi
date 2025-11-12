
  <h1>🛡️ BugBounty API – Plataforma Avançada de Testes de Vulnerabilidades</h1>
</header>
<br>
<h1>Video:</h1>
<p>clica para assistir no YouTuber</p>


[![Assistir vídeo](https://img.youtube.com/vi/-0daxvoFvI4/0.jpg)](https://www.youtube.com/watch?v=-0daxvoFvI4)


<section>
    <h2>📌 Visão Geral</h2>
    <p>
        O <strong>BugBounty API</strong> é uma plataforma completa e modular, projetada para realizar testes de vulnerabilidades em ambientes controlados, garantindo segurança, rastreabilidade e integração com múltiplos sistemas. Desenvolvido em <strong>Spring Boot</strong> com <strong>Java 17</strong>, o sistema permite que empresas, pentesters ou equipes de segurança conduzam testes automatizados ou manuais em URLs específicas, assegurando que cada resultado seja registrado detalhadamente.
    </p>
    <p>
        A plataforma oferece funcionalidades avançadas, incluindo execução de testes de vulnerabilidades clássicas como <strong>XSS, SQL Injection, CSRF, RCE, LFI</strong>, além de permitir o registro detalhado de payloads, respostas HTTP, validação rigorosa de escopo e integração RESTful com outros sistemas. Todos os testes são auditáveis e possuem logs estruturados, garantindo conformidade com boas práticas de segurança corporativa.
    </p>
    <p>
        A arquitetura da aplicação foi pensada para alta escalabilidade e flexibilidade, permitindo suporte a subdomínios, localhost, autenticação robusta e CORS configurável. Essa abordagem torna o BugBounty API ideal para integração com pipelines de <em>CI/CD</em>, auditorias de segurança internas e programas formais de Bug Bounty.
    </p>
</section>

<section>
    <h2>🏗️ Arquitetura do Sistema</h2>
    <p>
        A arquitetura do BugBounty API segue o modelo de camadas típico de aplicações corporativas em Java, com separação clara entre <em>controllers</em>, <em>services</em>, <em>repositories</em>, entidades e DTOs. O fluxo principal inicia-se no cliente (pentester ou ferramenta automatizada), que envia requisições para os endpoints REST da aplicação.
    </p>
    <pre>
+---------------------+        +---------------------+
|  Client / Pentester | -----> |  Vulnerability API  |
+---------------------+        +---------------------+
                                      |
                                      v
                           +---------------------+
                           | VulnerabilityService|
                           +---------------------+
                                      |
          +---------------------------+--------------------------+
          |                           |                          |
+---------------------+   +---------------------+   +---------------------+
| VulnerabilityRepo   |   | Logging & Monitoring|   | Security & CORS     |
+---------------------+   +---------------------+   +---------------------+
          |
          v
+---------------------+
| PostgreSQL Database |
+---------------------+
    </pre>



<header>
      <div>
        <h1>Explicação das Vulnerabilidades (foco: sites & apps web)</h1>
        <p>Documentação curta para cada teste do scanner — primeiro: vulnerabilidades web; depois: outras vulnerabilidades relevantes.</p>
      </div>
    </header>

   <nav class="toc">
      <h2>Índice</h2>
      <ul>
        <li><a class="anchor" href="#web">Vulnerabilidades focadas em aplicações web</a></li>
        <li><a class="anchor" href="#other">Outras vulnerabilidades / CVEs relevantes</a></li>
        <li><a class="anchor" href="#notes">Notas de uso seguro</a></li>
      </ul>
    </nav>
  <!-- Seção: web-focused -->
    <section id="web" class="card">
      <h3>Vulnerabilidades focadas em aplicações web</h3>

<div class="item">
        <div class="meta"><strong>Advanced XXE OOB</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>O que é:</strong> Falha no processamento de XML que permite referências a entidades externas. <br>
          <strong>Impacto em sites:</strong> vazamento de arquivos internos, SSRF ou chamadas a servidores controlados pelo atacante (observáveis "out‑of‑band").<br>
          <strong>Como é testado (alto nível):</strong> o scanner envia XML que referencia recursos externos e observa callbacks ou conteúdo que indica leitura/exfiltração. <br>
          <strong>Sinais:</strong> chamadas de saída do servidor a domínios não esperados, resposta contendo dados sensíveis.
        </div>
      </div>

   <div class="item">
        <div class="meta"><strong>Blind SSRF DNS</strong><span class="badge sev-high">High</span></div>
        <div class="desc">
          <strong>O que é:</strong> SSRF que usa resolução DNS como sinal, sem necessidade de resposta HTTP direta. <br>
          <strong>Impacto em sites:</strong> permite descobrir se um servidor pode acessar rede interna ou metadata de cloud. <br>
          <strong>Como é testado:</strong> injeta-se uma URL resolvível controlada pelo atacante; se houver lookup/DNS, há indicação de SSRF. <br>
          <strong>Sinais:</strong> registros DNS/consultas externas ou logs do OOB service.
        </div>
      </div>
      <div class="item">
        <div class="meta"><strong>WebSocket Session Steal</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>O que é:</strong> abuso de endpoints WebSocket para provocar comportamento que exponha sessões/tokens. <br>
          <strong>Impacto em sites:</strong> roubo de sessão, execução de comandos em canais em tempo real ou elevação de privilégios para aplicações com WS mal configurado. <br>
          <strong>Como é testado:</strong> handshake/manipulação de cabeçalhos e inspeção da resposta para sinais de exposição de credenciais. <br>
          <strong>Sinais:</strong> respostas 101 inesperadas, tokens/cabecalhos sensíveis no handshake.
        </div>
      </div>
    <div class="item">
        <div class="meta"><strong>Template Sandbox Escape (Server‑side Template Injection)</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>O que é:</strong> injeção em engines de template que permite execução de código no servidor. <br>
          <strong>Impacto em sites:</strong> RCE, leitura de arquivos e execução de comandos quando a sandbox é quebrada. <br>
          <strong>Como é testado:</strong> o scanner envia strings que, se avaliadas pelo engine, resultariam em execução ou saída de dados inesperada; o scanner procura sinais de execução. <br>
          <strong>Sinais:</strong> resposta contendo saída de comandos, variáveis de sistema, ou comportamento alterado do template.
        </div>
      </div>

   <div class="item">
        <div class="meta"><strong>Prototype Pollution → RCE (Node.js)</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>O que é:</strong> modificação maliciosa de propriedades de protótipo em objetos JavaScript que altera lógica da aplicação. <br>
          <strong>Impacto em sites:</strong> comportamento inesperado, bypass de lógica, e em casos extremos execução remota dependendo do contexto (ex.: bibliotecas perigosas). <br>
          <strong>Como é testado:</strong> envio de payloads JSON que alteram `__proto__` e observação de mudanças de comportamento. <br>
          <strong>Sinais:</strong> mudanças no output da API, erros que indicam sobrescrita de funções.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>Log Poisoning RCE</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>O que é:</strong> injeção de conteúdo em logs que mais tarde é interpretado por processos que executam ou reprocessam os logs. <br>
          <strong>Impacto em sites:</strong> se o pipeline de logs executar ou interpretar entradas, pode haver execução remota ou comprometimento de pipelines. <br>
          <strong>Como é testado:</strong> injeção em headers/inputs que terminam em logs; verificação de reprocessamento que possa executar esse conteúdo. <br>
          <strong>Sinais:</strong> entradas de log contendo payloads especiais e processos downstream lendo logs sem validação.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>SSRF Network Scan</strong><span class="badge sev-high">High</span></div>
        <div class="desc">
          <strong>O que é:</strong> uso de SSRF para acessar/recuperar informações de serviços internos a partir do servidor web. <br>
          <strong>Impacto em sites:</strong> descoberta de serviços internos (DBs, painéis admin, metadata), potencial escalonamento para acesso a segredos. <br>
          <strong>Como é testado:</strong> solicitar URLs internas previsíveis e analisar as respostas retornadas pelo servidor alvo. <br>
          <strong>Sinais:</strong> conteúdo de endpoints internos ou respostas que indicam portas/serviços abertos.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>XXE → LFI / Base64</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>O que é:</strong> uso de XXE para forçar inclusão de arquivos locais, frequentemente base64‑encoded, em respostas. <br>
          <strong>Impacto em sites:</strong> leitura de arquivos sensíveis (chaves, passwd), exposição de segredos. <br>
          <strong>Como é testado:</strong> envio de XML configurado para tentar incluir arquivos locais; busca por indícios de conteúdo de arquivos na resposta. <br>
          <strong>Sinais:</strong> respostas contendo trechos esperados de arquivos ou dados codificados.
        </div>
      </div>

   <div class="item">
        <div class="meta"><strong>WebSocket Backdoor</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>O que é:</strong> endpoints WS que aceitam comandos/payloads que abrem acesso persistente ou funcionalidades administrativas sem autenticação. <br>
          <strong>Impacto em sites:</strong> canal persistente para enviar comandos ou exfiltrar dados. <br>
          <strong>Como é testado:</strong> envio de mensagens WS específicas e análise de respostas que indiquem execução de comandos/ativação de funções administrativas. <br>
          <strong>Sinais:</strong> respostas com palavras-chave administrativas, execução de ações sem credenciais.
        </div>
      </div>

   <div class="item">
        <div class="meta"><strong>GraphQL Batching & Introspection Abuse</strong><span class="badge sev-high">High</span></div>
        <div class="desc">
          <strong>O que é:</strong> abuso das funcionalidades de GraphQL (introspection e batching) para descobrir schema e extrair campos sensíveis. <br>
          <strong>Impacto em sites:</strong> exposição de campos sensíveis (ex.: senhas, tokens), extração massiva de dados. <br>
          <strong>Como é testado:</strong> solicitações de introspecção e queries em lote para identificar campos/outras operações. <br>
          <strong>Sinais:</strong> retorno de `__schema`, campos de usuários ou dados que não deveriam ser visíveis.
        </div>
      </div>
      <div class="item">
        <div class="meta"><strong>JWT None Attack (Validação incorreta)</strong><span class="badge sev-high">High</span></div>
        <div class="desc">
          <strong>O que é:</strong> falha na validação de algoritmos de JWT que permite aceitar tokens forjados. <br>
          <strong>Impacto em sites:</strong> bypass de autenticação e privilégios falsos (ex.: admin). <br>
          <strong>Como é testado:</strong> envio de tokens manipulados e observação de acesso autorizado indevido. <br>
          <strong>Sinais:</strong> respostas autorizadas a partir de tokens inválidos ou com algoritmos inconsistentes.
        </div>
      </div>

   <div class="item">
        <div class="meta"><strong>XXE → RCE</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>O que é:</strong> degrau de ataque XXE que leva à execução de comandos no servidor que processa XML. <br>
          <strong>Impacto em sites:</strong> RCE completo do processo que lida com XML, possível comprometimento do host. <br>
          <strong>Como é testado:</strong> envio de payloads XML preparados para acionar pseudo‑protocolos (quando suportados) ou comportamentos que demonstram execução. <br>
          <strong>Sinais:</strong> saída de comandos do sistema na resposta, comportamento de execução detectável.
        </div>
      </div>
      <div class="item">
        <div class="meta"><strong>SSRF Cloud Metadata</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>O que é:</strong> SSRF direcionado a endpoints de metadata (ex.: AWS/GCP) para obter credenciais temporárias. <br>
          <strong>Impacto em sites:</strong> roubo de credenciais/roles que permitem controlar recursos cloud (S3, instâncias, etc.). <br>
          <strong>Como é testado:</strong> requisições internas simuladas ao endpoint de metadata e análise da resposta para tokens/roles. <br>
          <strong>Sinais:</strong> respostas contendo nomes de roles, tokens ou URLs de serviços de cloud.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>DOM XSS Observer</strong><span class="badge sev-medium">Medium</span></div>
        <div class="desc">
          <strong>O que é:</strong> XSS que ocorre no lado do cliente (manipulação do DOM) sem reflexão no servidor. <br>
          <strong>Impacto em sites:</strong> execução de scripts no navegador da vítima — roubo de cookies, execução de ações em nome do usuário. <br>
          <strong>Como é testado:</strong> análise de como parâmetros/fragmentos são inseridos no DOM e busca por execução de código no cliente. <br>
          <strong>Sinais:</strong> execução de scripts, alertas ou injeção direta no DOM visível.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>HTTP Request Smuggling (CL‑TE / CL‑CL)</strong><span class="badge sev-high">High</span></div>
        <div class="desc">
          <strong>O que é:</strong> técnicas que manipulam cabeçalhos que descrevem tamanho do corpo para confundir proxies e servidores. <br>
          <strong>Impacto em sites:</strong> cache poisoning, bypass de autenticação, envio de requests a backends inesperados. <br>
          <strong>Como é testado:</strong> envio de combinações inconsistentes de Content‑Length e Transfer‑Encoding e análise de respostas e comportamento do proxy/backend. <br>
          <strong>Sinais:</strong> acesso a rotas administrativas, respostas inconsistentes via proxy, headers inesperados.
        </div>
      </div>
  </section>
  <!-- Seção: other CVEs / infra -->
    <section id="other" class="card">
      <h3>Outras vulnerabilidades / CVEs relevantes (contexto web e infra)</h3>

   <div class="item">
        <div class="meta"><strong>Log4Shell (CVE‑2021‑44228)</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>Contexto em sites:</strong> bibliotecas de logging usadas por apps Java podem permitir execuções remotas se dados controlados pelo usuário forem logados sem sanitização forte. <br>
          <strong>Impacto:</strong> RCE em servidores que hospedam aplicações web Java, compromete a integridade do site e dos dados. <br>
          <strong>Sinais:</strong> execução remota aparente, callbacks de serviços externos vinculados a entradas de log.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>PrintNightmare (CVE‑2021‑34527)</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>Contexto em sites:</strong> embora seja um problema de serviço Windows (spooler), servidores web Windows vulneráveis podem ser totalmente comprometidos, afetando sites hospedados. <br>
          <strong>Impacto:</strong> execução com privilégios de sistema, instalação de backdoors. <br>
          <strong>Sinais:</strong> execução nao-autorizada de processos no servidor, persistência inesperada.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>BlueKeep / EternalBlue / Zerologon</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>Contexto:</strong> falhas em serviços de sistema (RDP, SMB, Netlogon) que permitem comprometimento da máquina que também serve aplicações web. <br>
          <strong>Impacto na web:</strong> comprometimento do host do site, possibilidade de propagar malware entre servidores. <br>
          <strong>Sinais:</strong> tráfego anômalo, portas vulneráveis expostas, comportamento de worm.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>Spring4Shell (CVE‑2022‑22965)</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>Contexto em sites:</strong> vulnerabilidade em aplicações que usam versões vulneráveis do Spring Framework, levando a RCE via requests HTTP específicos. <br>
          <strong>Impacto:</strong> execução remota no servidor de aplicação Java; pode resultar em takeover do site. <br>
          <strong>Sinais:</strong> criação de arquivos shells, respostas que contêm saída de comandos.
        </div>
      </div>
  <div class="item">
        <div class="meta"><strong>Confluence OGNL (CVE‑2022‑26134) e Apache Struts2 (CVE‑2017‑5638)</strong><span class="badge sev-high">High</span></div>
        <div class="desc">
          <strong>Contexto:</strong> deserialização, OGNL e outros vetores em frameworks web famosos que permitem execução arbitrária quando combinados com entradas perigosas. <br>
          <strong>Impacto:</strong> RCE em aplicações web que utilizam versões vulneráveis. <br>
          <strong>Sinais:</strong> execuções estranhas, alteração de páginas administrativas, criação de usuários não autorizados.
        </div>
      </div>

   <div class="item">
        <div class="meta"><strong>Heartbleed, Shellshock, Heartbleed (OpenSSL)</strong><span class="badge sev-high">High</span></div>
        <div class="desc">
          <strong>Contexto:</strong> vulnerabilidades em bibliotecas críticas (TLS, shell) que podem vazar informações sensíveis ou permitir execução de comandos em servidores que hospedam sites. <br>
          <strong>Impacto:</strong> vazamento de chaves privadas, credenciais, execução remota dependendo do contexto. <br>
          <strong>Sinais:</strong> respostas anômalas, vazamento de conteúdo da memória, logs de erros.
        </div>
      </div>

<div class="item">
        <div class="meta"><strong>CMS / Plugins (Drupalgeddon, WordPress plugins vulneráveis)</strong><span class="badge sev-high">High</span></div>
        <div class="desc">
          <strong>Contexto em sites:</strong> vulnerabilidades específicas de CMSs ou plugins que permitem RCE, SQLi, upload de shells, etc. <br>
          <strong>Impacto:</strong> comprometimento do site e possível escalonamento a infraestrutura. <br>
          <strong>Sinais:</strong> arquivos novos em diretórios públicos, shells detectados, páginas administrativas modificadas.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>F5 BIG-IP, Citrix, Fortinet, appliances</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>Contexto:</strong> vulnerabilidades em appliances e devices que fazem proxy/reverse proxy para sites (ex.: F5, Citrix) – impacto direto no tráfego web. <br>
          <strong>Impacto:</strong> bypass de auth, execução remota, comprometimento do tráfego TLS/terminação. <br>
          <strong>Sinais:</strong> comportamento de proxy estranho, acesso administrativo não autorizado, logs do appliance.
        </div>
      </div>

  <div class="item">
        <div class="meta"><strong>Supply Chain (ex.: SolarWinds)</strong><span class="badge sev-critical">Critical</span></div>
        <div class="desc">
          <strong>Contexto em sites:</strong> compromissos em componentes/artefatos que sites dependem (bibliotecas, CI/CD, pacotes). <br>
          <strong>Impacto:</strong> backdoors distribuídos via updates, comprometimento generalizado. <br>
          <strong>Sinais:</strong> comportamentos idênticos em múltiplos serviços, tráfego/sinais para infra de terceiros desconhecidos.
        </div>
      </div>

   </section>

  <section id="notes" class="card">
      <h3>Notas de uso seguro & recomendações</h3>
      <ul style="color:var(--muted); line-height:1.6;">
        <li><strong>Autorização:</strong> execute testes apenas em alvos que você tem permissão (bug bounty, pentest autorizado) — testes de SSRF/XXE/metadata podem vazar segredos.</li>
        <li><strong>Ambientes de teste:</strong> prefira ambientes isolados e cópias dos serviços para validação (staging, sandboxes).</li>
        <li><strong>Logs e monitoração:</strong> ative monitoração para detectar tentativas de exploração e rever logs antes/depois de testes.</li>
        <li><strong>Remediação rápida:</strong> priorize patches para bibliotecas críticas (Log4j, Spring, OpenSSL) e configuração de hardening de proxies e headers.</li>
        <li><strong>Limitação do scanner:</strong> o scanner observa sinais e padrões; resultados devem ser validados manualmente por um analista experiente.</li>
      </ul>
      <footer>
        Documento gerado para suporte ao seu scanner. Contato: edson / equipe. Use com responsabilidade.
      </footer>
    </section>
  </div>



  
   <h3>Camadas e Funções</h3>
    <table>
        <tr>
            <th>Camada</th>
            <th>Tecnologias / Função</th>
        </tr>
        <tr>
            <td>Controller (REST)</td>
            <td>Spring Web, endpoints <code>/vulnerabilities</code></td>
        </tr>
        <tr>
            <td>Service</td>
            <td>Lógica de negócio, execução de payloads, validação de escopo</td>
        </tr>
        <tr>
            <td>Repository</td>
            <td>JPA / Hibernate, persistência de vulnerabilidades</td>
        </tr>
        <tr>
            <td>Security & Config</td>
            <td>Controle de escopo, CORS, logs, autenticação</td>
        </tr>
        <tr>
            <td>DTOs & Models</td>
            <td>Comunicação segura entre API e cliente</td>
        </tr>
        <tr>
            <td>Database</td>
            <td>PostgreSQL, histórico completo de vulnerabilidades</td>
        </tr>
        <tr>
            <td>Logging</td>
            <td>SLF4J + Logback, logs detalhados</td>
        </tr>
    </table>
</section>

<section>
    <h2>📂 Estrutura do Projeto</h2>
    <pre>
com.example.bugbounty
├── controller
│   └── VulnerabilityController.java    # REST endpoints
├── service
│   └── VulnerabilityService.java       # Lógica de execução e persistência
├── repository
│   └── VulnerabilityRepository.java    # CRUD de vulnerabilidades
├── entity
│   └── Vulnerability.java              # Entidade principal
├── dto
│   └── VulnerabilityDTO.java           # DTO REST
├── model
│   └── TestRequest.java                # Payload de requisição
├── config
│   └── SecurityConfig.java             # Segurança, CORS e logs
├── exception
│   └── CustomExceptionHandlers.java    # Tratamento centralizado de erros
├── util
│   └── ValidationUtils.java            # Funções auxiliares
└── docs
    └── logo.png
    </pre>
</section>

<section>
    <h2>💻 Frontend e Backend</h2>
    <p>
        O sistema BugBounty API possui um backend robusto e um frontend opcional para visualização e execução de testes. O backend é responsável por toda a lógica de negócio, execução de payloads, validação de escopo, persistência de dados e geração de logs detalhados. Ele é desenvolvido em <strong>Java 17</strong> com <strong>Spring Boot</strong>, utilizando <strong>PostgreSQL</strong> para armazenamento e <strong>SLF4J/Logback</strong> para logging estruturado.
    </p>
    <p>
        O frontend, que pode ser integrado via REST ou usando frameworks modernos como React ou Angular, oferece interfaces de usuário para: cadastro de vulnerabilidades, visualização de relatórios detalhados, filtragem por severidade, tipo de vulnerabilidade e status de execução. Ele se comunica com o backend utilizando JSON e DTOs para garantir consistência e segurança das informações.
    </p>
    <p>
        A arquitetura frontend-backend é desenhada para escalabilidade. O frontend não possui lógica crítica de segurança, que é totalmente controlada no backend, incluindo validação de escopo, sanitização de payloads, autenticação, controle de CORS e auditoria de logs. Essa separação garante que mesmo usuários mal-intencionados não consigam explorar falhas no sistema.
    </p>
</section>

<section>
    <h2>🚀 Endpoints Principais</h2>
    <h3>1️⃣ Testar Vulnerabilidade</h3>
    <p><strong>POST</strong> <code>/vulnerabilities/test</code></p>
    <p>Executa um teste de vulnerabilidade em uma URL dentro do escopo permitido.</p>
    <h4>Request Body (<code>TestRequest</code>)</h4>
    <pre>
{
  "targetUrl": "https://example.com/login",
  "vulnerabilityType": "XSS",
  "payload": "&lt;script&gt;alert('test')&lt;/script&gt;"
}
    </pre>
    <h4>Response (<code>VulnerabilityDTO</code>)</h4>
    <pre>
{
  "id": 123,
  "name": "XSS",
  "targetUrl": "https://example.com/login",
  "vulnerabilityType": "XSS",
  "payload": "&lt;script&gt;alert('test')&lt;/script&gt;",
  "result": "SUCCESS",
  "responseDetails": "&lt;input&gt; vulnerável",
  "category": "Security",
  "severity": "Critical",
  "createdAt": "2025-11-04T16:00:00",
  "jobId": 12,
  "httpStatus": 200
}
    </pre>
    <h4>Códigos HTTP Retornáveis</h4>
    <table>
        <tr><th>Código</th><th>Significado</th></tr>
        <tr><td>200</td><td>Teste executado com sucesso</td></tr>
        <tr><td>403</td><td>URL fora do escopo permitido</td></tr>
        <tr><td>400</td><td>Payload inválido ou malformado</td></tr>
        <tr><td>500</td><td>Erro interno do servidor</td></tr>
    </table>

   <h3>2️⃣ Listar Vulnerabilidades</h3>
   <p><strong>GET</strong> <code>/vulnerabilities</code></p>
    <p>Retorna todas as vulnerabilidades registradas, filtráveis por tipo, severidade, URL e status do teste.</p>
    <pre>
GET /vulnerabilities?type=XSS&severity=Critical
    </pre>

   <h3>3️⃣ Consultar Vulnerabilidade por ID</h3>
    <p><strong>GET</strong> <code>/vulnerabilities/{id}</code></p>
    <p>Retorna detalhes completos de uma vulnerabilidade específica, incluindo payload, resultado, categoria e severidade.</p>
</section>

<section>
    <h2>🔄 Fluxo Interno de Validação</h2>
    <ul>
        <li>Recebe URL e tipo de vulnerabilidade.</li>
        <li>Valida o host com a lista de domínios permitidos (subdomínios, localhost e 127.0.0.1).</li>
        <li>Executa o teste via <code>VulnerabilityService</code>.</li>
        <li>Persiste resultado, payload e detalhes HTTP.</li>
        <li>Retorna DTO seguro para o cliente.</li>
    </ul>
</section>

<section>
    <h2>⚡ Validação de Escopo</h2>
    <pre>
# application.properties
bugbounty.allowed-domains=example.com,api.example.org,localhost
    </pre>
    <p><strong>URLs permitidas:</strong></p>
    <ul>
        <li>https://example.com/login</li>
        <li>http://sub.example.com/page</li>
        <li>http://localhost:8080/test</li>
    </ul>
    <p><strong>URLs bloqueadas:</strong></p>
    <ul>
        <li>https://malicious.com/</li>
        <li>http://evil.example.net/</li>
    </ul>
</section>

<section>
    <h2>🔐 Segurança e Boas Práticas</h2>
    <ul>
        <li>Controle rigoroso de escopo.</li>
        <li>Logs detalhados de cada requisição e resultado.</li>
        <li>Severidade padronizada: Low, Medium, High, Critical.</li>
        <li>Categoria: Security, Operational, Functional.</li>
        <li>Auditoria completa: registro de <code>createdAt</code> e <code>jobId</code>.</li>
        <li>Sanitização de payloads antes da execução.</li>
        <li>Tratamento de erros centralizado.</li>
    </ul>
</section>

<section>
    <h2>🛠️ Setup Local</h2>
    <pre>
git clone https://github.com/usuario/bugbounty-api.git
cd bugbounty-api
    </pre>
    <p>Configurar <code>application.properties</code>:</p>
    <pre>
spring.datasource.url=jdbc:postgresql://localhost:5432/bugbounty
spring.datasource.username=postgres
spring.datasource.password=senha
bugbounty.allowed-domains=example.com,localhost
    </pre>
    <p>Executar:</p>
    <pre>
./mvnw clean install
./mvnw spring-boot:run
    </pre>
</section>

<section>
    <h2>🧪 Testes Automatizados</h2>
    <p>Frameworks utilizados: <strong>JUnit 5 + Mockito</strong></p>
    <ul>
        <li>Cobertura mínima recomendada: 80%</li>
        <li>Testes recomendados:
            <ul>
                <li>Validação de escopo (<code>isInScope</code>)</li>
                <li>Execução de payloads</li>
                <li>Conversão de entidades para DTO</li>
                <li>Cenários de sucesso e erro</li>
            </ul>
        </li>
    </ul>
    <pre>
./mvnw test
    </pre>
</section>

<section>
    <h2>📈 Integrações e CI/CD</h2>
    <ul>
        <li>Jenkins / GitHub Actions para pipeline de testes e deploy.</li>
        <li>Exportação de resultados para SIEM, dashboards e sistemas de monitoramento.</li>
        <li>Webhooks para integração com Slack / Teams.</li>
    </ul>
</section>

<section>
    <h2>📊 Métricas e Logs</h2>
    <ul>
        <li>Total de vulnerabilidades testadas.</li>
        <li>Vulnerabilidades por severidade.</li>
        <li>Payloads que falharam ou foram bloqueados.</li>
        <li>Logs estruturados e auditáveis.</li>
    </ul>
</section>

<section>
    <h2>🗺️ Roadmap Futuro</h2>
    <ul>
        <li>Multi-tenancy para suporte a múltiplas equipes.</li>
        <li>Dashboard web em tempo real com métricas de vulnerabilidade.</li>
        <li>Exportação de relatórios em CSV, PDF e HTML.</li>
        <li>Integração com scanners de terceiros (OWASP ZAP, Nikto).</li>
        <li>Alertas automáticos para vulnerabilidades críticas.</li>
    </ul>
</section>

<section>
    <h2>👨‍💻 Contribuição</h2>
    <ul>
        <li>Fork → Branch <code>feature/nova-feature</code></li>
        <li>Pull request detalhado.</li>
        <li>Testes obrigatórios para cada mudança.</li>
        <li>Revisão de código e aprovação antes de merge.</li>
    </ul>
</section>

<section>
    <h2>💡 Considerações Finais</h2>
    <p>
        O BugBounty API foi projetado para fornecer uma plataforma sólida, segura e extensível para testes de vulnerabilidades. Ele combina arquitetura moderna, práticas de segurança avançadas, logging auditável, integração RESTful e suporte completo para CI/CD. Sua implementação modular permite que equipes de segurança expandam e personalizem funcionalidades conforme necessário, mantendo alto nível de confiabilidade e rastreabilidade.
    </p>
    <p>
        Ao seguir as boas práticas apresentadas neste documento, desenvolvedores e pentesters podem garantir que os testes sejam realizados de maneira segura, eficiente e dentro do escopo autorizado, contribuindo para um ecossistema de segurança cibernética mais robusto e confiável.
    </p>
</section>

