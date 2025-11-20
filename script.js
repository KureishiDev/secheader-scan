document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const loadingArea = document.getElementById('loadingArea');
    const resultsArea = document.getElementById('resultsArea');
    const displayUrl = document.getElementById('displayUrl');
    const scoreCircle = document.getElementById('scoreCircle');
    const scoreText = document.getElementById('scoreText');
    const headersContainer = document.getElementById('headersContainer');
    const submitBtn = form.querySelector('button');
    const downloadBtn = document.getElementById('downloadBtn');

    // Containers
    const sslContainer = document.getElementById('sslContainer');
    const whoisContainer = document.getElementById('whoisContainer'); // NOVO
    const sriContainer = document.getElementById('sriContainer');     // NOVO
    const techContainer = document.getElementById('techContainer');
    const dnsContainer = document.getElementById('dnsContainer');
    const cookieContainer = document.getElementById('cookieContainer');
    const apiContainer = document.getElementById('apiContainer');
    const fullReportContainer = document.getElementById('fullReportContainer');
    
    let lastScanData = null; // Armazena o resultado para download

    // Função de Download
    downloadBtn.addEventListener('click', () => {
        if (!lastScanData) return;
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(lastScanData, null, 4));
        const downloadAnchorNode = document.createElement('a');
        downloadAnchorNode.setAttribute("href", dataStr);
        downloadAnchorNode.setAttribute("download", "websec_report.json");
        document.body.appendChild(downloadAnchorNode);
        downloadAnchorNode.click();
        downloadAnchorNode.remove();
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        let url = urlInput.value.trim(); 
        if (url.length < 4 || !url.includes('.')) { showInputError(); return; }
        urlInput.classList.remove('input-error'); submitBtn.disabled = true; 
        loadingArea.classList.remove('hidden'); resultsArea.classList.add('hidden');
        
        // Limpa Containers
        headersContainer.innerHTML = '';
        if (fullReportContainer) fullReportContainer.innerHTML = '';
        if (sslContainer) sslContainer.innerHTML = '';
        if (whoisContainer) whoisContainer.innerHTML = '';
        if (sriContainer) sriContainer.innerHTML = '';
        if (apiContainer) apiContainer.innerHTML = '';
        if (cookieContainer) cookieContainer.innerHTML = '';
        if (techContainer) techContainer.innerHTML = '';
        if (dnsContainer) dnsContainer.innerHTML = '';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: url })
            });
            const data = await response.json();
            lastScanData = data; // Salva para o download

            loadingArea.classList.add('hidden'); submitBtn.disabled = false;

            if (data.success) {
                resultsArea.classList.remove('hidden');
                displayUrl.textContent = data.finalUrl;
                scoreCircle.textContent = data.grade;
                scoreCircle.style.borderColor = data.scoreColor;
                scoreCircle.style.color = data.scoreColor;
                scoreText.textContent = data.message;
                scoreText.style.color = data.scoreColor;

                renderHeaders(data.headers);
                if (data.ssl_info) renderSSL(data.ssl_info);
                if (data.whois_info) renderWhois(data.whois_info); // NOVO
                if (data.dns_info) renderDNS(data.dns_info, data.files_info);
                if (data.tech_info) renderTech(data.tech_info);
                if (data.sri_info) renderSRI(data.sri_info); // NOVO
                if (data.cookie_info) renderCookies(data.cookie_info);
                if (data.api_info) renderApis(data.api_info);
                if (data.subdomain_info) renderSubdomains(data.subdomain_info);
            } else {
                alert("ERRO: " + data.message); showInputError();
            }
        } catch (error) {
            console.error(error); loadingArea.classList.add('hidden'); submitBtn.disabled = false; alert('ERRO CRÍTICO.');
        }
    });

    function showInputError() { urlInput.classList.add('input-error'); urlInput.focus(); setTimeout(() => { urlInput.classList.remove('input-error'); }, 1000); }

    // --- NOVAS RENDERIZAÇÕES ---
    function renderWhois(whois) {
        if (!whoisContainer || whois.error) return;
        let html = `
            <div class="card" style="margin-bottom: 20px; border-left: 4px solid --neon-green;">
                <h3 class="report-title" style="color: --neon-green;">DOMAIN INTEL (WHOIS)</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
                    <div><strong style="color:#888; font-size:0.7rem;">REGISTRAR</strong><div style="color:#fff;">${whois.registrar || 'N/A'}</div></div>
                    <div><strong style="color:#888; font-size:0.7rem;">CRIAÇÃO</strong><div style="color:#fff;">${whois.creation_date || 'N/A'}</div></div>
                    <div><strong style="color:#888; font-size:0.7rem;">EXPIRAÇÃO</strong><div style="color:#fff;">${whois.expiration_date || 'N/A'}</div></div>
                </div>
            </div>`;
        whoisContainer.innerHTML = html;
    }

    function renderSRI(sri) {
        if (!sriContainer || sri.length === 0) return;
        let html = `
            <div class="card" style="margin-bottom: 20px;">
                <h3 class="report-title">SUBRESOURCE INTEGRITY (SRI)</h3>
                <table><thead><tr><th>Recurso Externo</th><th>Status</th></tr></thead><tbody>`;
        sri.forEach(s => {
            let badge = s.status === 'pass' ? 'pass' : 'warn';
            let label = s.status === 'pass' ? 'SECURE' : 'MISSING';
            html += `<tr><td style="color:var(--text-primary); word-break:break-all; font-size:0.8rem;">${s.resource}</td><td class="badge ${badge}">${label}</td></tr>`;
        });
        html += `</tbody></table></div>`;
        sriContainer.innerHTML = html;
    }

    
    
    function renderDNS(dns, files) {
        if (!dnsContainer) return;
        let html = `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;"><div class="card"><h3 class="report-title">DNS SECURITY</h3>`;
        dns.forEach(d => { let badge = d.status==='pass'?'pass':(d.status==='info'?'warn':'fail'); html += `<div style="margin-bottom:8px;"><div style="display:flex; justify-content:space-between;"><strong style="color:#eee;">${d.name}</strong><span class="badge ${badge}">${d.status.toUpperCase()}</span></div><code class="header-value" style="margin-top:4px;">${d.value}</code></div>`; });
        html += `</div>`;
        if(files && files.length>0) { html += `<div class="card"><h3 class="report-title">FILES RECON</h3>`; files.forEach(f => { let icon = f.status==='found'?'✅':'❌'; html += `<div style="padding:8px 0; border-bottom:1px solid #222;"><div style="display:flex; justify-content:space-between;"><span style="color:#eee;">${f.name}</span><span>${icon}</span></div></div>`; }); html += `</div>`; }
        html += `</div>`;
        dnsContainer.innerHTML = html;
    }
    function renderTech(techs) { if (!techContainer || techs.length === 0) return; let html = `<div class="card" style="margin-bottom: 20px; border-left: 4px solid var(--neon-green);"><h3 class="report-title" style="color: var(--neon-green);">STACK DETECTADA</h3><div style="display: flex; gap: 15px; flex-wrap: wrap;">`; techs.forEach(t => { html += `<div style="background: #111; padding: 8px 12px; border-radius: 4px; border: 1px solid #333;"><strong style="display:block; color: #888; font-size: 0.7rem;">${t.name}</strong><span style="color: #fff;">${t.value}</span></div>`; }); html += `</div></div>`; techContainer.innerHTML = html; }
    function renderCookies(cookies) { if (!cookieContainer || cookies.length === 0) return; let html = `<div class="card" style="margin-bottom: 20px;"><h3 class="report-title">INSPEÇÃO DE COOKIES</h3><table><thead><tr><th>Nome</th><th>Flags</th></tr></thead><tbody>`; cookies.forEach(c => { let f = c.flags.map(x=>`<span class="badge pass">${x}</span>`).join(' '); if(c.flags[0]==='Nenhuma') f=`<span class="badge fail">Nenhuma</span>`; html+=`<tr><td style="color:#ccc">${c.name}</td><td>${f}</td></tr>`; }); html+=`</tbody></table></div>`; cookieContainer.innerHTML = html; }
    function renderSSL(ssl) { if (!sslContainer) return; const s = ssl.ssl_ok; const c = s?'var(--neon-green)':'var(--danger)'; let h=`<div class="card" style="border-left:4px solid ${c}; margin-bottom:20px;"><h3 class="report-title" style="color:${c}">AUDITORIA SSL</h3><div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;"><div><strong style="color:#666;font-size:0.8rem;">STATUS</strong><span style="color:${c};font-weight:bold;">${s?'🔒 SEGURO':'🔓 INSEGURO'}</span></div>`; if(s){ h+=`<div><strong style="color:#666;font-size:0.8rem;">VALIDADE</strong><span style="color:#fff;">${ssl.expires_in_days} dias</span></div><div style="grid-column:span 2;margin-top:10px;"><strong style="color:#666;font-size:0.8rem;">EMISSOR</strong><code class="header-value">${ssl.issuer}</code></div>`; } else { h+=`<div style="grid-column:span 2;"><strong style="color:var(--danger)">ERRO:</strong> ${ssl.error}</div>`; } h+=`</div></div>`; sslContainer.innerHTML=h; }
    function renderApis(apis) { if (!apiContainer || apis.length === 0) return; let h=`<div class="card" style="margin-bottom: 20px;"><h3 class="report-title">ENDPOINTS (JS)</h3><table><thead><tr><th>String</th><th>Tipo</th></tr></thead><tbody>`; apis.forEach(i=>{ h+=`<tr><td style="word-break:break-all;color:#ccc;">${i.content}</td><td class="badge warn">${i.type}</td></tr>`; }); h+=`</tbody></table></div>`; apiContainer.innerHTML=h; }
    function renderSubdomains(subs) { if (!fullReportContainer || subs.length === 0) return; let h=`<div class="card" style="margin-top:20px;"><h3 class="report-title">ATIVOS (OSINT)</h3><table><thead><tr><th>Subdomínio</th><th>IP</th><th>Status</th></tr></thead><tbody>`; subs.forEach(s=>{ h+=`<tr><td>${s.subdomain}</td><td>${s.ip}</td><td class="badge pass">${s.status}</td></tr>`; }); h+=`</tbody></table></div>`; fullReportContainer.innerHTML=h; }
    function renderHeaders(headers) { headers.forEach(h => { const d = document.createElement('div'); d.className='header-item'; let b=h.status==='pass'?'pass':'fail'; let v=h.value!=='N/A'?`<code class="header-value">${h.value}</code>`:''; d.innerHTML=`<div class="header-info"><strong>${h.name}</strong><span class="header-desc">${h.desc}</span>${v}</div><span class="badge ${b}">${h.status==='pass'?'ATIVO':'AUSENTE'}</span>`; headersContainer.appendChild(d); }); }
});

