# 🛡️ WebSec Auditor

![Project Status](https://img.shields.io/badge/status-live-success)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**WebSec Auditor** é uma ferramenta de reconhecimento passivo e análise de segurança web projetada para auditores, pentesters e desenvolvedores.

Diferente de scanners agressivos, esta ferramenta realiza uma **auditoria não-intrusiva**, coletando dados públicos de infraestrutura, criptografia e configurações de front-end para gerar um relatório de postura de segurança em tempo real com uma estética Cyberpunk/Dark.

---

## 🚀 Live Demo

Acesse a ferramenta online:
### [🔗 https://secheader-vinicius.onrender.com](https://secheader-vinicius.onrender.com)

*(Nota: Como está hospedado em plano gratuito, pode levar alguns segundos para iniciar na primeira execução).*

---

## 👁️ Visual Tour & Funcionalidades

O WebSec Auditor divide a análise em camadas de segurança. Abaixo estão os módulos visuais da ferramenta:

### 1. Dashboard de Segurança (Score & Headers)
A primeira linha de defesa. O sistema analisa cabeçalhos HTTP críticos (como CSP, HSTS e X-Frame-Options) e atribui uma nota de **A+ a F** baseada nas melhores práticas da OWASP.

![Screenshot do Dashboard com Nota e Headers](screenshots/dashboard.png)
*Exibe visualmente quais proteções estão ativas (Verde) ou ausentes (Vermelho).*

### 2. Infraestrutura e Criptografia
Análise profunda da identidade e proteção do servidor.
* **Auditoria SSL/TLS:** Verifica a validade do certificado, emissor (CA) e dias para expiração.
* **Whois Intelligence:** Consulta dados de registro do domínio para identificar datas de criação e expiração (prevenção de Domain Hijacking).

![Screenshot do SSL e Whois](screenshots/infra.png)

### 3. Inteligência de DNS & E-mail
Verifica se o domínio possui proteções contra **Phishing** e **Spoofing** de e-mail.
* **SPF (Sender Policy Framework):** Quem pode enviar e-mails por este domínio?
* **DMARC:** O domínio rejeita e-mails falsos?
* **MX Records:** Mapeamento de servidores de e-mail.

![Screenshot do DNS e Email](screenshots/dns.png)

### 4. Reconhecimento (OSINT & Superfície de Ataque)
Módulos focados em descobrir o que não está óbvio na página inicial.
* **Caçador de Subdomínios:** Enumeração passiva de subdomínios comuns (`api`, `dev`, `admin`).
* **LinkFinder (API Discovery):** Análise estática do código-fonte para encontrar possíveis rotas de API (`/api/v1/...`) e vazamento de chaves.
* **Arquivos Sensíveis:** Verifica a existência de `robots.txt`, `sitemap.xml` e `security.txt`.

![Screenshot do OSINT e APIs](screenshots/osint.png)

### 5. Aplicação & Frontend
Análise das tecnologias que sustentam o site.
* **Tech Stack:** Detecta CMS (WordPress), Frameworks (React, Vue), Servidores Web e CDNs.
* **Auditoria de Cookies:** Verifica se os cookies de sessão possuem as flags `Secure` e `HttpOnly`.
* **SRI (Subresource Integrity):** Checa se scripts externos possuem integridade criptográfica para prevenir ataques de Supply Chain.

![Screenshot da Stack e Cookies](screenshots/tech.png)

---

## 🛠️ Tecnologias Utilizadas

* **Backend:** Python 3 (Flask, Gunicorn).
* **Networking:** Requests, Socket, DNS Resolver, PyOpenSSL, Whois.
* **Frontend:** HTML5 Semântico, CSS3 (Grid/Flexbox, Neon UI), JavaScript (Fetch API).
* **Deploy:** Render (CI/CD Pipeline via GitHub).

---

## 💻 Como Rodar Localmente

Se você deseja rodar ou modificar o projeto na sua máquina:

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/SEU_USUARIO/secheader-scan.git](https://github.com/SEU_USUARIO/secheader-scan.git)
    cd secheader-scan
    ```

2.  **Instale as dependências:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Execute a aplicação:**
    ```bash
    python app.py
    ```

4.  **Acesse:** Abra `http://127.0.0.1:5000` no seu navegador.

---

## 📄 Licença

Este projeto está sob a licença MIT - sinta-se livre para usar e modificar.

<br>

<p align="center">
  Desenvolvido por <a href="https://www.linkedin.com/in/vinicius-wandembruck/" target="_blank">Vinicius Wandembruck</a>
</p>
