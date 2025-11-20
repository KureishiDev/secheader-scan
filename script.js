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

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        let url = urlInput.value.trim(); 
        
        if (url.length < 4 || !url.includes('.')) {
            showInputError();
            return;
        }

        urlInput.classList.remove('input-error');
        submitBtn.disabled = true; 

        loadingArea.classList.remove('hidden');
        resultsArea.classList.add('hidden');
        headersContainer.innerHTML = ''; 

        try {
            // CORREÇÃO: Usando caminho relativo '/api/scan' em vez de http://127.0.0.1:5000
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();

            loadingArea.classList.add('hidden');
            submitBtn.disabled = false;

            if (data.success) {
                resultsArea.classList.remove('hidden');
                
                displayUrl.textContent = data.finalUrl;
                
                scoreCircle.textContent = data.grade;
                scoreCircle.style.borderColor = data.scoreColor;
                scoreCircle.style.color = data.scoreColor;
                
                scoreText.textContent = data.message;
                scoreText.style.color = data.scoreColor;

                renderHeaders(data.headers);
            } else {
                alert("ERRO: " + data.message);
                showInputError();
            }

        } catch (error) {
            console.error(error);
            loadingArea.classList.add('hidden');
            submitBtn.disabled = false;
            // Se cair no catch, o problema é grave (rede, servidor Flask está offline)
            alert('ERRO CRÍTICO: Falha na comunicação com o servidor. Tente novamente mais tarde.');
        }
    });

    function showInputError() {
        urlInput.classList.add('input-error');
        urlInput.focus();
        setTimeout(() => {
            urlInput.classList.remove('input-error');
        }, 1000);
    }

    function renderHeaders(headers) {
        headers.forEach(header => {
            const itemDiv = document.createElement('div');
            itemDiv.className = 'header-item';

            let badgeClass = header.status === 'pass' ? 'pass' : 'fail';
            let badgeLabel = header.status === 'pass' ? 'ATIVO' : 'AUSENTE';

            itemDiv.innerHTML = `
                <div class="header-info">
                    <strong>${header.name}</strong>
                    <span class="header-desc">${header.desc}</span>
                </div>
                <span class="badge ${badgeClass}">${badgeLabel}</span>
            `;

            headersContainer.appendChild(itemDiv);
        });
    }
});
