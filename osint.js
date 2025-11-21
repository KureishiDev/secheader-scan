document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('osintForm');
    const userInput = document.getElementById('userInput');
    const resultsArea = document.getElementById('osintResults');
    const loadingArea = document.getElementById('loadingArea');
    const resultsContainer = document.getElementById('resultsContainer');
    const btn = form.querySelector('button');

    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        let username = userInput.value.trim();
        
        // Remove espaços (usernames não têm espaço)
        username = username.replace(/\s/g, '');

        if(username.length < 2) { 
            alert("Username muito curto."); 
            return; 
        }

        // UI de Carregamento
        btn.disabled = true;
        btn.innerText = "GERANDO LINKS...";
        loadingArea.classList.remove('hidden');
        resultsArea.classList.add('hidden');
        resultsContainer.innerHTML = '';

        try {
            const response = await fetch('/api/osint', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username })
            });
            
            const data = await response.json();
            
            // Simula um pequeno delay para parecer que processou
            setTimeout(() => {
                loadingArea.classList.add('hidden');
                btn.disabled = false;
                btn.innerText = "RASTREAR";
                
                if(data.success) {
                    resultsArea.classList.remove('hidden');
                    renderLinks(data.data); // Chama a nova função de renderização
                } else {
                    alert("Erro: " + data.message);
                }
            }, 500);

        } catch (error) {
            console.error(error);
            loadingArea.classList.add('hidden');
            btn.disabled = false;
            btn.innerText = "ERRO";
            alert("Erro ao conectar com a API.");
        }
    });

    // --- NOVA FUNÇÃO DE RENDERIZAÇÃO (BOTÕES DE LINK) ---
    function renderLinks(links) {
        let html = '';
        
        links.forEach(item => {
            html += `
                <a href="${item.url}" target="_blank" style="text-decoration: none;">
                    <div style="
                        border: 1px solid #333; 
                        background: #111; 
                        padding: 20px; 
                        border-radius: 6px; 
                        text-align: center; 
                        transition: all 0.3s;
                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: center;
                        height: 100%;
                        cursor: pointer;
                        position: relative;
                        overflow: hidden;
                    " 
                    onmouseover="this.style.borderColor='var(--neon-green)'; this.style.boxShadow='0 0 15px rgba(0, 255, 65, 0.2)';" 
                    onmouseout="this.style.borderColor='#333'; this.style.boxShadow='none';">
                        
                        <div style="font-size: 2rem; margin-bottom: 10px;">${item.icon}</div>
                        
                        <div style="font-weight:bold; color:#fff; margin-bottom:5px; font-size:1rem;">
                            ${item.name}
                        </div>
                        
                        <div style="
                            margin-top: 10px; 
                            font-size: 0.7rem; 
                            color: #000; 
                            background: var(--neon-green); 
                            padding: 5px 15px; 
                            border-radius: 20px; 
                            font-weight: bold; 
                            letter-spacing: 1px;">
                            VERIFICAR ↗
                        </div>
                    </div>
                </a>
            `;
        });

        resultsContainer.innerHTML = html;
    }
});