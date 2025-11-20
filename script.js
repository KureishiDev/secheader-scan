document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');
    const loadingArea = document.getElementById('loadingArea');
    const resultsArea = document.getElementById('resultsArea');
    
    const displayUrl = document.getElementById('displayUrl');
    const scoreCircle = document.getElementById('scoreCircle');
    const scoreText = document.getElementById('scoreText');
    const headersContainer = document.getElementById('headersContainer');
    const submitBtn = form ? form.querySelector('button') : null;
    const downloadBtn = document.getElementById('downloadBtn');

    const sslContainer = document.getElementById('sslContainer');
    const whoisContainer = document.getElementById('whoisContainer');
    const dnsContainer = document.getElementById('dnsContainer');
    const techContainer = document.getElementById('techContainer');
    const sriContainer = document.getElementById('sriContainer');
    const cookieContainer = document.getElementById('cookieContainer');
    const apiContainer = document.getElementById('apiContainer');
    const fullReportContainer = document.getElementById('fullReportContainer');
    
    let lastScanData = null;

    // Validacao critica
    if (!form || !urlInput || !submitBtn) return;

    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            if (!lastScanData) return;
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(lastScanData, null, 4));
            const node = document.createElement('a');
            node.setAttribute("href", dataStr);
            node.setAttribute("download", "websec_report.json");
            document.body.appendChild(node); node.click(); node.remove();
        });
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        let url = urlInput.value.trim(); 
        if (url.length < 4 || !url.includes('.')) { showInputError(); return; }

        urlInput.classList.remove('input-error');
        submitBtn.disabled = true; 
        loadingArea.classList.remove('hidden');
        resultsArea.classList.add('hidden');
        
        if(headersContainer) headersContainer.innerHTML = '';
        if(sslContainer) sslContainer.innerHTML = '';
        if(whoisContainer) whoisContainer.innerHTML = '';
        if(dnsContainer) dnsContainer.innerHTML = '';
        if(techContainer) techContainer.innerHTML = '';
        if(sriContainer) sriContainer.innerHTML = '';
        if(cookieContainer) cookieContainer.innerHTML = '';
        if(apiContainer) apiContainer.innerHTML = '';
        if(fullReportContainer) fullReportContainer.innerHTML = '';

        try {
            const response = await fetch('/api/scan', {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: url })
            });
            const data = await response.json();
            lastScanData = data; 

            loadingArea.classList.add('hidden');
            submitBtn.disabled = false;

            if (data.success) {
                resultsArea.classList.remove('hidden');
                if(displayUrl) displayUrl.textContent = data.finalUrl;
                if(scoreCircle) { scoreCircle.textContent = data.grade; scoreCircle.style.borderColor = data.scoreColor; scoreCircle.style.color = data.scoreColor; }
                if(scoreText) { scoreText.textContent = data.message; scoreText.style.color = data.scoreColor; }

                if(headersContainer) renderHeaders(data.headers);
                if(data.ssl_info) renderSSL(data.ssl_info);
                if(data.whois_info) renderWhois(data.whois_info);
                if(data.dns_info) renderDNS(data.dns_info, data.files_info);
                if(data.tech_info) renderTech(data.tech_info);
                if(data.sri_info) renderSRI(data.sri_info);
                if(data.cookie_info) renderCookies(data.cookie_info);
                if(data.api_info) renderApis(data.api_info);
                if(data.subdomain_info) renderSubdomains(data.subdomain_info);
            } else {
                alert("ERRO: " + data.message); showInputError();
            }
        } catch (error) {
            loadingArea.classList.add('hidden'); submitBtn.disabled = false;
            alert('ERRO CRÍTICO: Falha na comunicação.');
        }
    });

    function showInputError() { urlInput.classList.add('input-error'); urlInput.focus(); setTimeout(() => { urlInput.classList.remove('input-error'); }, 1000); }

    // Render Functions
    function renderHeaders(headers) {
        if (!headersContainer) return;
        headers.forEach(h => {
            const d = document.createElement('div'); d.className = 'header-item';
            let b = h.status==='pass'?'pass':'fail';
            let v = h.value!=='N/A'?`<code class="header-value">${h.value}</code>`:'';
            d.innerHTML =`<div class="header-info"><strong>${h.name}</strong><span class="header-desc">${h.desc}</span>${v}</div><span class="badge ${b}">${h.status==='pass'?'ATIVO':'AUSENTE'}</span>`;
            headersContainer.appendChild(d);
        });
    }
    function renderSSL(s) {
        if(!sslContainer) return;
        let c = s.ssl_ok ? 'var(--neon-green)' : 'var(--danger)';
        let h = `<div class="card" style="border-left:4px solid ${c}; margin-bottom:20px;"><h3 class="report-title" style="color:${c}">AUDITORIA SSL/TLS</h3><div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;"><div><strong style="display:block;color:#666;font-size:0.8rem;">STATUS</strong><span style="color:${c};font-weight:bold;">${s.ssl_ok?'🔒 BLINDADO':'🔓 INSEGURO'}</span></div>`;
        if(s.ssl_ok) h+=`<div><strong style="display:block;color:#666;font-size:0.8rem;">DIAS</strong><span style="color:#fff;">${s.expires_in_days}</span></div><div style="grid-column:span 2;margin-top:10px;"><strong style="display:block;color:#666;font-size:0.8rem;">EMISSOR</strong><code class="header-value" style="margin-top:2px;">${s.issuer}</code></div>`;
        else h+=`<div style="grid-column:span 2;"><strong style="color:var(--danger)">ERRO:</strong> ${s.error}</div>`;
        h+=`</div></div>`; sslContainer.innerHTML = h;
    }
    function renderWhois(whois) {
        
        if (!whoisContainer || whois.error) return;
        
        let html = `
            <div class="card" style="margin-bottom: 20px; border-left: 4px solid var(--neon-green);">
                <h3 class="report-title" style="color: var(--neon-green);">DOMAIN INTEL (WHOIS)</h3>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px;">
                    <div>
                        <strong style="color:#888; font-size:0.7rem;">REGISTRAR</strong>
                        <div style="color:#fff; font-size:0.9rem;">${whois.registrar || 'N/A'}</div>
                    </div>
                    <div>
                        <strong style="color:#888; font-size:0.7rem;">CRIAÇÃO</strong>
                        <div style="color:#fff; font-size:0.9rem;">${whois.creation_date || 'N/A'}</div>
                    </div>
                    <div>
                        <strong style="color:#888; font-size:0.7rem;">EXPIRAÇÃO</strong>
                        <div style="color:#fff; font-size:0.9rem;">${whois.expiration_date || 'N/A'}</div>
                    </div>
                </div>
            </div>`;
            
        whoisContainer.innerHTML = html;
    }
    function renderDNS(dns, files) {
        if(!dnsContainer) return;
        let h = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;"><div class="card"><h3 class="report-title">DNS SECURITY</h3>`;
        dns.forEach(d=>{let b=d.status==='pass'?'pass':(d.status==='info'?'warn':'fail'); h+=`<div style="margin-bottom:10px;"><div style="display:flex;justify-content:space-between;"><strong style="color:#eee;">${d.name}</strong><span class="badge ${b}">${d.status.toUpperCase()}</span></div><code class="header-value" style="margin-top:4px;">${d.value}</code></div>`;});
        h+=`</div>`;
        if(files && files.length>0){ h+=`<div class="card"><h3 class="report-title">FILES</h3>`; files.forEach(f=>{let i=f.status==='found'?'✅':'❌'; h+=`<div style="padding:8px 0;border-bottom:1px solid #222;"><div style="display:flex;justify-content:space-between;"><span style="color:#eee;">${f.name}</span><span>${i}</span></div></div>`;}); h+=`</div>`;}
        h+=`</div>`; dnsContainer.innerHTML = h;
    }
    function renderTech(t) { if(!techContainer || t.length===0) return; let h=`<div class="card" style="margin-bottom:20px;border-left:4px solid var(--neon-green);"><h3 class="report-title" style="color:var(--neon-green);">STACK</h3><div style="display:flex;gap:15px;flex-wrap:wrap;">`; t.forEach(x=>{ h+=`<div style="background:#111;padding:8px 12px;border-radius:4px;border:1px solid #333;"><strong style="display:block;color:#888;font-size:0.7rem;">${x.name}</strong><span style="color:#fff;">${x.value}</span></div>`; }); h+=`</div></div>`; techContainer.innerHTML = h; }
    function renderSRI(s) { if(!sriContainer || s.length===0) return; let h=`<div class="card" style="margin-bottom:20px;"><h3 class="report-title">SRI</h3><table><thead><tr><th>Recurso</th><th>Status</th></tr></thead><tbody>`; s.forEach(x=>{ let b=x.status==='pass'?'pass':'warn'; h+=`<tr><td style="color:var(--text-primary);word-break:break-all;font-size:0.8rem;">${x.resource}</td><td class="badge ${b}">${x.status==='pass'?'SECURE':'MISSING'}</td></tr>`; }); h+=`</tbody></table></div>`; sriContainer.innerHTML=h; }
    function renderCookies(c) { if(!cookieContainer || c.length===0) return; let h=`<div class="card" style="margin-bottom:20px;"><h3 class="report-title">COOKIES</h3><table><thead><tr><th>Nome</th><th>Flags</th></tr></thead><tbody>`; c.forEach(x=>{ let f=x.flags.map(i=>`<span class="badge pass">${i}</span>`).join(' '); if(x.flags[0]==='Nenhuma')f=`<span class="badge fail">Risco</span>`; h+=`<tr><td style="color:#ccc;">${x.name}</td><td>${f}</td></tr>`; }); h+=`</tbody></table></div>`; cookieContainer.innerHTML=h; }
    function renderApis(a) { if(!apiContainer || a.length===0) return; let h=`<div class="card" style="margin-bottom:20px;"><h3 class="report-title">ENDPOINTS (JS)</h3><table><thead><tr><th>String</th><th>Tipo</th></tr></thead><tbody>`; a.forEach(i=>{ h+=`<tr><td style="word-break:break-all;color:#ccc;">${i.content}</td><td class="badge warn">${i.type}</td></tr>`; }); h+=`</tbody></table></div>`; apiContainer.innerHTML=h; }
    function renderSubdomains(s) { if(!fullReportContainer || s.length===0) return; let h=`<div class="card" style="margin-top:20px;"><h3 class="report-title">OSINT ATIVOS</h3><table><thead><tr><th>Subdomínio</th><th>IP</th><th>Status</th></tr></thead><tbody>`; s.forEach(i=>{ h+=`<tr><td>${i.subdomain}</td><td>${i.ip}</td><td class="badge pass">${i.status}</td></tr>`; }); h+=`</tbody></table></div>`; fullReportContainer.innerHTML=h; }
});