
  <h1>🛡️ BugBounty API – Plataforma Avançada de Testes de Vulnerabilidades</h1>
</header>

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

