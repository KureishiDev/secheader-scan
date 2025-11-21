document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('radarForm');
    const emailInput = document.getElementById('emailInput');
    const resultsArea = document.getElementById('radarResults');
    const leakCount = document.getElementById('leakCount');
    const breachList = document.getElementById('breachList');
    const btn = form.querySelector('button');
    const radarContainer = document.querySelector('.radar-container');

    if (!form || !emailInput || !btn) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        let email = emailInput.value.trim();
        
        if(email.length < 5 || !email.includes('@')) {
            alert("Por favor, digite um e-mail válido.");
            return;
        }

        btn.disabled = true;
        btn.innerText = "ESCANEANDO BASE...";
        
        resultsArea.classList.add('hidden');
        breachList.innerHTML = '';
        if(radarContainer) radarContainer.classList.remove('safe-mode'); 

        try {
            const response = await fetch('/api/radar', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            });
            
            const data = await response.json();
            
            resultsArea.classList.remove('hidden');
            btn.disabled = false;
            btn.innerText = "INVESTIGAR";
            
            if(data.success && data.data.count > 0) {
                
                if(radarContainer) radarContainer.classList.remove('safe-mode');
                leakCount.innerText = data.data.count;
                leakCount.style.color = "var(--danger)";
                
                renderBreaches(data.data.breaches);
                
            } else {
               
                if(radarContainer) radarContainer.classList.add('safe-mode');
                leakCount.innerText = "0";
                leakCount.style.color = "var(--neon-green)";
                
                breachList.innerHTML = `
                    <div class="card" style="text-align:center; border-left: 4px solid var(--neon-green);">
                        <h3 style="color: var(--neon-green);">NENHUM VAZAMENTO ENCONTRADO</h3>
                        <p style="color: #ccc;">Este e-mail não consta nas bases de dados públicas verificadas.</p>
                    </div>
                `;
            }

        } catch (error) {
            console.error(error);
            btn.disabled = false;
            btn.innerText = "ERRO";
            alert("Erro ao consultar API de vazamentos.");
        }
    });

    function renderBreaches(breaches) {
        let html = '';
        
       
        breaches.forEach(b => {
            html += `
                <div class="leak-card">
                    <div style="display:flex; justify-content:space-between;">
                        <span class="leak-title">⚠️ ${b.name}</span>
                    </div>
                    <span class="leak-desc">${b.desc}</span>
                </div>
            `;
        });

      
        html += `
            <div class="card" style="margin-top: 40px; border: 1px solid #333; background: #0a0a0a;">
                <h3 style="color: #fff; margin-bottom: 15px; font-size: 1rem; border-bottom: 1px solid #333; padding-bottom: 10px;">
                     PLANO DE AÇÃO RECOMENDADO
                </h3>
                <ul style="list-style: none; padding: 0; color: #ccc; font-size: 0.9rem;">
                    <li style="margin-bottom: 12px; display: flex; gap: 10px;">
                        <span></span>
                        <div>
                            <strong style="color: #fff;">Troque sua senha imediatamente:</strong>
                            <br>Se você usa essa mesma senha em outros sites, troque-as também.
                        </div>
                    </li>
                    <li style="margin-bottom: 12px; display: flex; gap: 10px;">
                        <span></span>
                        <div>
                            <strong style="color: #fff;">Ative o 2FA (Dois Fatores):</strong>
                            <br>Configure a autenticação de dois fatores. Isso impede invasões mesmo com a senha vazada.
                        </div>
                    </li>
                    <li style="margin-bottom: 12px; display: flex; gap: 10px;">
                        <span></span>
                        <div>
                            <strong style="color: #fff;">Atenção com Phishing:</strong>
                            <br>Como seu e-mail é público, verifique sempre o remetente de e-mails suspeitos.
                        </div>
                    </li>
                </ul>
                <p style="font-size: 0.75rem; color: #666; margin-top: 15px; text-align: center;">
                    * Os dados acima são públicos e foram agregados apenas para fins de conscientização.
                </p>
            </div>
        `;

        breachList.innerHTML = html;
    }
});