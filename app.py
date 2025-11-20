from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
import OpenSSL
from bs4 import BeautifulSoup
import re
import dns.resolver
import whois

app = Flask(__name__, static_url_path='', static_folder='.')
CORS(app)

# --- AUTO-BLINDAGEM ---
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = """default-src 'self' 'unsafe-inline'; img-src 'self' https://licensebuttons.net https://ui-avatars.com https://utfpr.curitiba.br data:;"""
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Força HTTPS.",
    "Content-Security-Policy": "Previne XSS.",
    "X-Frame-Options": "Previne Clickjacking.",
    "X-Content-Type-Options": "Previne MIME Sniffing.",
    "Referrer-Policy": "Privacidade de navegação.",
    "Permissions-Policy": "Bloqueio de hardware."
}

# --- FUNÇÕES DE ANÁLISE ---

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        expiration = w.expiration_date
        if isinstance(expiration, list): expiration = expiration[0]
        return {
            "registrar": w.registrar,
            "creation_date": str(creation),
            "expiration_date": str(expiration),
            "emails": w.emails if w.emails else "Oculto"
        }
    except: return {"error": "Dados WHOIS ocultos."}

def check_sri(html_content):
    sri_report = []
    soup = BeautifulSoup(html_content, 'html.parser')
    resources = soup.find_all(['script', 'link'])
    for tag in resources:
        src = tag.get('src') or tag.get('href')
        if src and ('http' in src or '//' in src):
            if tag.get('integrity'):
                sri_report.append({"resource": src, "status": "pass", "msg": "Integrity Check Ativo"})
            else:
                sri_report.append({"resource": src, "status": "warn", "msg": "Sem SRI"})
    return sri_report[:10]

def check_dns_security(domain):
    dns_report = []
    try:
        # SPF
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_found = False
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    spf_found = True
                    dns_report.append({"name": "SPF Record", "status": "pass", "value": txt[:60]+"..."})
            if not spf_found: dns_report.append({"name": "SPF Record", "status": "fail", "value": "Não configurado"})
        except: dns_report.append({"name": "SPF Record", "status": "fail", "value": "Ausente"})

        # DMARC
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            dmarc = answers[0].to_text().strip('"')
            dns_report.append({"name": "DMARC Record", "status": "pass", "value": dmarc[:60]+"..."})
        except: dns_report.append({"name": "DMARC Record", "status": "fail", "value": "Ausente"})
    except: pass
    return dns_report

def check_special_files(url):
    files = []
    base = url.rstrip('/')
    targets = [{"path": "/robots.txt", "desc": "Crawler Rules"}, {"path": "/sitemap.xml", "desc": "Site Map"}, {"path": "/.well-known/security.txt", "desc": "Security Policy"}]
    headers = {'User-Agent': 'Mozilla/5.0'}
    for t in targets:
        try:
            res = requests.get(base + t['path'], headers=headers, timeout=3)
            status = "found" if res.status_code == 200 else "missing"
            files.append({"name": t['path'], "status": status, "desc": t['desc']})
        except: pass
    return files

def check_common_subdomains(domain):
    subs = ['www', 'api', 'blog', 'dev', 'mail', 'admin', 'secure', 'vpn', 'portal']
    found = []
    domain = domain.lstrip('www.').lower()
    for s in subs:
        target = f"{s}.{domain}"
        try:
            socket.setdefaulttimeout(0.5)
            ip = socket.gethostbyname(target)
            found.append({"subdomain": target, "ip": ip, "status": "LIVE"})
        except: pass
    return found

def get_ssl_info(hostname):
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(3.0)
        conn.connect((hostname, 443))
        cert = conn.getpeercert(True)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ssl.DER_cert_to_PEM_cert(cert))
        not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        days = (not_after - datetime.now()).days
        issuer = dict(x509.get_issuer().get_components()).get(b'CN', b'Unknown').decode('utf-8')
        conn.close()
        return {"ssl_ok": True, "issuer": issuer, "expires_in_days": days}
    except: return {"ssl_ok": False, "error": "Erro SSL"}

def extract_api_patterns(html):
    findings = []
    pattern = re.compile(r"['\"]((?:/|https?://)[a-zA-Z0-9_./?-]*?(?:api|v[0-9]|admin|auth)[a-zA-Z0-9_./?-]*)['\"]")
    for match in set(pattern.findall(html)):
        clean = match.strip("'\"")
        if not any(x in clean for x in ['.png','.jpg','.css','.svg','.ico']):
            findings.append({"type": "Possible Endpoint", "content": clean, "severity": "INFO"})
    return findings[:10]

def analyze_cookies(jar):
    report = []
    for c in jar:
        flags = []
        if c.secure: flags.append("Secure")
        if c.has_nonstandard_attr('HttpOnly') or c.get_nonstandard_attr('HttpOnly'): flags.append("HttpOnly")
        report.append({"name": c.name, "flags": flags if flags else ["Nenhuma"], "status": "pass" if len(flags)==2 else "warn"})
    return report

def detect_technologies(headers, html, cookies):
    techs = []
    if 'Server' in headers: techs.append({"name": "Server", "value": headers['Server']})
    if 'X-Powered-By' in headers: techs.append({"name": "Powered By", "value": headers['X-Powered-By']})
    if 'cf-ray' in headers: techs.append({"name": "CDN", "value": "Cloudflare"})
    
    soup = BeautifulSoup(html, 'html.parser')
    meta = soup.find('meta', attrs={'name': 'generator'})
    if meta and meta.get('content'): techs.append({"name": "Generator", "value": meta['content']})
    
    return techs

# --- ROTAS ---
@app.route('/')
def home(): return send_from_directory('.', 'index.html')

@app.route('/about')
def about(): return send_from_directory('.', 'about.html')

@app.route('/feedback')
def feedback(): return send_from_directory('.', 'feedback.html')

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.json
    raw_url = data.get('url', '').strip()
    if not raw_url: return jsonify({"success": False, "message": "URL Vazia"}), 400
    
    if not raw_url.startswith(('http://', 'https://')): target = 'https://' + raw_url
    else: target = raw_url

    try:
        parsed = urlparse(target)
        hostname = parsed.netloc.split(':')[0]
        if not parsed.netloc: raise ValueError
    except: return jsonify({"success": False, "message": "URL Inválida"}), 400

    try:
        headers_ua = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36'}
        session = requests.Session()
        resp = session.get(target, headers=headers_ua, timeout=10)
        
        # Executa Scanners
        ssl_data = get_ssl_info(hostname)
        sub_data = check_common_subdomains(hostname)
        api_data = extract_api_patterns(resp.text)
        cookie_data = analyze_cookies(session.cookies)
        tech_data = detect_technologies(resp.headers, resp.text, session.cookies)
        dns_data = check_dns_security(hostname)
        file_data = check_special_files(target)
        whois_data = get_whois_info(hostname)
        sri_data = check_sri(resp.text)

        # Score
        results = []
        score = 0
        total = len(SECURITY_HEADERS) + 1
        
        for h, desc in SECURITY_HEADERS.items():
            val = resp.headers.get(h)
            status = "pass" if val else "fail"
            if val: score += 1
            results.append({"name": h, "status": status, "desc": desc, "value": val if val else "N/A"})
            
        if ssl_data['ssl_ok']: score += 1
        
        pct = (score / total) * 100
        if pct >= 95: grade, color, msg = "A+", "#00ff41", "BLINDADO"
        elif pct >= 80: grade, color, msg = "A", "#00ff41", "EXCELENTE"
        elif pct >= 60: grade, color, msg = "B", "#eab308", "SEGURO"
        elif pct >= 40: grade, color, msg = "C", "#f97316", "ATENÇÃO"
        elif pct >= 20: grade, color, msg = "D", "#ff3333", "VULNERÁVEL"
        else: grade, color, msg = "F", "#ff0000", "CRÍTICO"

        return jsonify({
            "success": True, "grade": grade, "scoreColor": color, "message": msg,
            "headers": results, "ssl_info": ssl_data, "subdomain_info": sub_data,
            "api_info": api_data, "cookie_info": cookie_data, "tech_info": tech_data,
            "dns_info": dns_data, "files_info": file_data, "whois_info": whois_data,
            "sri_info": sri_data, "finalUrl": resp.url
        })

    except Exception as e:
        print(e)
        return jsonify({"success": False, "message": "Erro ao conectar."}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)