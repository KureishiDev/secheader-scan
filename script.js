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
    const dorksContainer = document.getElementById('dorksContainer'); 
    const fullReportContainer = document.getElementById('fullReportContainer');
    
    let lastScanData = null;

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
        
        // Limpa tudo
        if(headersContainer) headersContainer.innerHTML = '';
        if(sslContainer) sslContainer.innerHTML = '';
        if(whoisContainer) whoisContainer.innerHTML = '';
        if(dnsContainer) dnsContainer.innerHTML = '';
        if(techContainer) techContainer.innerHTML = '';
        if(sriContainer) sriContainer.innerHTML = '';
        if(cookieContainer) cookieContainer.innerHTML = '';
        if(apiContainer) apiContainer.innerHTML = '';
        if(dorksContainer) dorksContainer.innerHTML = '';
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

                let hostname = data.finalUrl.replace(/^https?:\/\//, '').split('/')[0];

                if(headersContainer) renderHeaders(data.headers);
                if(data.ssl_info) renderSSL(data.ssl_info);
                if(data.whois_info) renderWhois(data.whois_info);
                if(data.dns_info) renderDNS(data.dns_info, data.files_info);
                if(data.tech_info) renderTech(data.tech_info);
                if(data.sri_info) renderSRI(data.sri_info);
                if(data.cookie_info) renderCookies(data.cookie_info);
                if(data.api_info) renderApis(data.api_info);
                
                renderDorks(hostname); 

                if(data.subdomain_info) renderSubdomains(data.subdomain_info);
            } else {
                alert("ERRO: " + data.message); showInputError();
            }
        } catch (error) {
            console.error(error); loadingArea.classList.add('hidden'); submitBtn.disabled = false; alert('ERRO CRÍTICO.');
        }
    });

    function showInputError() { urlInput.classList.add('input-error'); urlInput.focus(); setTimeout(() => { urlInput.classList.remove('input-error'); }, 1000); }

    // --- FUNÇÃO GOOGLE DORKS (ATUALIZADA: Só Botão, Sem Texto Extra) ---
    function renderDorks(domain) {
        if (!dorksContainer) return;

        const dorks = [
            { title: "Arquivos Públicos", query: `site:${domain} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:ppt OR filetype:txt` },
            { title: "Páginas de Login", query: `site:${domain} inurl:login OR inurl:admin OR inurl:cpanel` },
            { title: "Arquivos de Config", query: `site:${domain} ext:xml OR ext:conf OR ext:cnf OR ext:reg OR ext:inf OR ext:rdp OR ext:cfg` },
            { title: "Backup & SQL", query: `site:${domain} ext:sql OR ext:dbf OR ext:mdb OR ext:bkp OR ext:bak OR ext:old` },
            { title: "Directory Listing", query: `site:${domain} intitle:"index of"` },
            { title: "Subdomínios Google", query: `site:${domain} -www` },
            { title: "Pastebin Leaks", query: `site:pastebin.com "${domain}"` },
            { title: "Github Leaks", query: `site:github.com "${domain}"` }
        ];

        let html = `
            <div class="card" style="margin-bottom: 20px; border-left: 4px solid var(--neon-green);">
                <h3 class="report-title" style="color: var(--neon-green);">GOOGLE HACKING (DORKS)</h3>
                <p style="font-size: 0.75rem; color: #888; margin-bottom: 15px;">
                    *Links diretos para pesquisas avançadas no Google.
                </p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px;">
        `;

        dorks.forEach(dork => {
            const googleLink = `https://www.google.com/search?q=${encodeURIComponent(dork.query)}`;
            // REMOVIDO: O texto "Abrir Pesquisa"
            // AJUSTADO: Padding e centralização
            html += `
                <a href="${googleLink}" target="_blank" style="text-decoration: none;">
                    <div style="background: #111; border: 1px solid #333; padding: 15px; border-radius: 4px; text-align: center; transition: all 0.3s; color: #ccc; font-size: 0.85rem; display: flex; align-items: center; justify-content: center; height: 100%;">
                        <span style="color: var(--neon-green); font-weight:bold;">🔍 ${dork.title}</span>
                    </div>
                </a>
            `;
        });

        html += `</div></div>`;
        dorksContainer.innerHTML = html;
    }

    // --- FUNÇÃO WHOIS ---
    function renderWhois(w) {
        if(!whoisContainer || w.error) return;
        let h = `<div class="card" style="margin-bottom:20px; border-left:4px solid var(--neon-green);"><h3 class="report-title" style="color:var(--neon-green)">DOMAIN INTEL (WHOIS)</h3><div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:15px;"><div><strong style="color:#888;font-size:0.7rem;">REGISTRAR</strong><div style="color:#fff;font-size:0.9rem;">${w.registrar||'N/A'}</div></div><div><strong style="color:#888;font-size:0.7rem;">CRIAÇÃO</strong><div style="color:#fff;font-size:0.9rem;">${w.creation_date||'N/A'}</div></div><div><strong style="color:#888;font-size:0.7rem;">EXPIRAÇÃO</strong><div style="color:#fff;font-size:0.9rem;">${w.expiration_date||'N/A'}</div></div></div></div>`;
        whoisContainer.innerHTML=h;
    }

    function renderHeaders(h){if(!headersContainer)return;h.forEach(x=>{const d=document.createElement('div');d.className='header-item';let b=x.status==='pass'?'pass':'fail';let v=x.value!=='N/A'?`<code class="header-value">${x.value}</code>`:'';d.innerHTML=`<div class="header-info"><strong>${x.name}</strong><span class="header-desc">${x.desc}</span>${v}</div><span class="badge ${b}">${x.status==='pass'?'ATIVO':'AUSENTE'}</span>`;headersContainer.appendChild(d);});}
    function renderSSL(s){if(!sslContainer)return;let c=s.ssl_ok?'var(--neon-green)':'var(--danger)';let h=`<div class="card" style="border-left:4px solid ${c};margin-bottom:20px;"><h3 class="report-title" style="color:${c}">AUDITORIA SSL/TLS</h3><div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;"><div><strong style="display:block;color:#666;font-size:0.8rem;">STATUS</strong><span style="color:${c};font-weight:bold;">${s.ssl_ok?'🔒 BLINDADO':'🔓 INSEGURO'}</span></div>`;if(s.ssl_ok){h+=`<div><strong style="display:block;color:#666;font-size:0.8rem;">DIAS</strong><span style="color:#fff;">${s.expires_in_days}</span></div><div style="grid-column:span 2;margin-top:10px;"><strong style="display:block;color:#666;font-size:0.8rem;">EMISSOR</strong><code class="header-value" style="margin-top:2px;">${s.issuer}</code></div>`;}else{h+=`<div style="grid-column:span 2;"><strong style="color:var(--danger)">ERRO:</strong> ${s.error}</div>`;}h+=`</div></div>`;sslContainer.innerHTML=h;}
    
    function renderDNS(d,f){if(!dnsContainer)return;let h=`<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;"><div class="card"><h3 class="report-title">DNS SECURITY</h3>`;d.forEach(x=>{let b=x.status==='pass'?'pass':(x.status==='info'?'warn':'fail');h+=`<div style="margin-bottom:10px;"><div style="display:flex;justify-content:space-between;"><strong style="color:#eee;">${x.name}</strong><span class="badge ${b}">${x.status.toUpperCase()}</span></div><code class="header-value" style="margin-top:4px;">${x.value}</code></div>`;});h+=`</div>`;if(f&&f.length>0){h+=`<div class="card"><h3 class="report-title">FILES RECON</h3>`;f.forEach(x=>{let i=x.status==='found'?'✅':'❌';h+=`<div style="padding:8px 0;border-bottom:1px solid #222;"><div style="display:flex;justify-content:space-between;"><span style="color:#eee;">${x.name}</span><span>${i}</span></div></div>`;});h+=`</div>`;}h+=`</div>`;dnsContainer.innerHTML=h;}
    
    function renderTech(t){if(!techContainer||t.length===0)return;let h=`<div class="card" style="margin-bottom:20px;border-left:4px solid var(--neon-green);"><h3 class="report-title" style="color:var(--neon-green);">STACK DETECTADA</h3><div style="display:flex;gap:15px;flex-wrap:wrap;">`;t.forEach(x=>{h+=`<div style="background:#111;padding:8px 12px;border-radius:4px;border:1px solid #333;"><strong style="display:block;color:#888;font-size:0.7rem;">${x.name}</strong><span style="color:#fff;">${x.value}</span></div>`;});h+=`</div></div>`;techContainer.innerHTML=h;}
    
    function renderSRI(s){if(!sriContainer||s.length===0)return;let h=`<div class="card" style="margin-bottom:20px;"><h3 class="report-title">SUBRESOURCE INTEGRITY (SRI)</h3><table><thead><tr><th>Recurso Externo</th><th>Status</th></tr></thead><tbody>`;s.forEach(x=>{let b=x.status==='pass'?'pass':'warn';h+=`<tr><td style="color:var(--text-primary);word-break:break-all;font-size:0.8rem;">${x.resource}</td><td class="badge ${b}">${x.status==='pass'?'SECURE':'MISSING'}</td></tr>`;});h+=`</tbody></table></div>`;sriContainer.innerHTML=h;}
    function renderCookies(c){if(!cookieContainer||c.length===0)return;let h=`<div class="card" style="margin-bottom:20px;"><h3 class="report-title">INSPEÇÃO DE COOKIES</h3><table><thead><tr><th>Nome do Cookie</th><th>Flags de Segurança</th></tr></thead><tbody>`;c.forEach(x=>{let f=x.flags.map(i=>`<span class="badge pass">${i}</span>`).join(' ');if(x.flags[0]==='Nenhuma')f=`<span class="badge fail">Risco</span>`;h+=`<tr><td style="color:var(--text-primary);">${x.name}</td><td>${f}</td></tr>`;});h+=`</tbody></table></div>`;cookieContainer.innerHTML=h;}
    function renderApis(a){if(!apiContainer||a.length===0)return;let h=`<div class="card" style="margin-bottom:20px;"><h3 class="report-title">POSSÍVEIS ENDPOINTS (JS)</h3><table><thead><tr><th>Endpoint / String</th><th>Tipo</th></tr></thead><tbody>`;a.forEach(x=>{h+=`<tr><td style="word-break:break-all;color:var(--text-primary);">${x.content}</td><td class="badge warn">${x.type}</td></tr>`;});h+=`</tbody></table></div>`;apiContainer.innerHTML=h;}
    function renderSubdomains(s){if(!fullReportContainer||s.length===0)return;let h=`<div class="card" style="margin-top:20px;"><h3 class="report-title">ATIVOS ENCONTRADOS (OSINT)</h3><table><thead><tr><th>Subdomínio</th><th>IP Resolvido</th><th>Status</th></tr></thead><tbody>`;s.forEach(x=>{h+=`<tr><td>${x.subdomain}</td><td>${x.ip}</td><td class="badge pass">${x.status}</td></tr>`;});h+=`</tbody></table></div>`;fullReportContainer.innerHTML=h;}
});