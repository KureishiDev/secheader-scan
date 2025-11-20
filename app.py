from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
from urllib.parse import urlparse

app = Flask(__name__, static_url_path='', static_folder='.')
CORS(app)

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline'; img-src 'self' https://licensebuttons.net data:;"
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Força HTTPS. Protege contra Man-in-the-Middle.",
    "Content-Security-Policy": "A defesa #1 contra ataques XSS e Injection.",
    "X-Frame-Options": "Impede que seu site seja clonado em iframes (Clickjacking).",
    "X-Content-Type-Options": "Bloqueia arquivos maliciosos disfarçados (MIME Sniffing).",
    "Referrer-Policy": "Protege dados de navegação do usuário.",
    "Permissions-Policy": "Bloqueia acesso não autorizado a hardware (câmera, mic)."
}

@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.json
    raw_url = data.get('url', '').strip()

    if not raw_url:
        return jsonify({"success": False, "message": "A URL não pode estar vazia."}), 400

    if not raw_url.startswith(('http://', 'https://')):
        target_url = 'https://' + raw_url
    else:
        target_url = raw_url

    try:
        parsed = urlparse(target_url)
        if not parsed.netloc:
            raise ValueError("Domínio inválido")
    except:
        return jsonify({"success": False, "message": "Formato de URL inválido."}), 400

    try:
        headers_fake = {'User-Agent': 'Mozilla/5.0 (SecHeaderScan/1.0)'}
        
        response = requests.get(target_url, headers=headers_fake, timeout=5)
        site_headers = response.headers
        
        results = []
        score = 0
        total_checks = len(SECURITY_HEADERS)

        for header, description in SECURITY_HEADERS.items():
            match = False
            for h in site_headers:
                if h.lower() == header.lower():
                    match = True
                    break
            
            status = "fail"
            if match:
                score += 1
                status = "pass"
            
            results.append({
                "name": header,
                "status": status,
                "desc": description
            })

        percentage = (score / total_checks) * 100
        
        if percentage == 100:
            grade, color, message = "A", "#00ff41", "SISTEMA BLINDADO"
        elif percentage >= 80:
            grade, color, message = "B", "#00ff41", "MUITO SEGURO"
        elif percentage >= 60:
            grade, color, message = "C", "#eab308", "ATENÇÃO REQUERIDA"
        elif percentage >= 40:
            grade, color, message = "D", "#f97316", "VULNERÁVEL"
        else:
            grade, color, message = "F", "#ef4444", "CRÍTICO"

        return jsonify({
            "success": True,
            "grade": grade,
            "scoreColor": color,
            "message": message,
            "headers": results,
            "finalUrl": response.url
        })

    except requests.exceptions.SSLError:
        return jsonify({"success": False, "message": "FALHA SSL: O certificado do site é inválido."}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({"success": False, "message": "FALHA DE CONEXÃO: O site não existe ou recusou a conexão."}), 400
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "message": "TIMEOUT: O servidor demorou muito para responder."}), 400
    except Exception as e:
        return jsonify({"success": False, "message": f"Erro interno: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
