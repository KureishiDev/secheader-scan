document.addEventListener("DOMContentLoaded", () => {
    const modal = document.getElementById('disclaimerModal');
    const btnAccept = document.getElementById('btnAccept');
    const btnDecline = document.getElementById('btnDecline');

    if (!modal) return;

    // LÓGICA CORRIGIDA PARA EVITAR "PISCAR":
    // 1. O CSS padrão esconde o modal (opacity: 0).
    // 2. O JS verifica se PRECISA mostrar.
    const hasConsented = localStorage.getItem('websec_consent');

    if (!hasConsented) {
        // Se NÃO tiver consentimento, mostra o modal suavemente
        // Pequeno delay para garantir que o CSS carregou
        setTimeout(() => {
            modal.classList.add('show-modal');
        }, 100);
    }

    // Botão ACEITAR
    if (btnAccept) {
        btnAccept.addEventListener('click', () => {
            localStorage.setItem('websec_consent', 'true');
            modal.classList.remove('show-modal'); // Remove a classe que torna visível
        });
    }

    // Botão RECUSAR
    if (btnDecline) {
        btnDecline.addEventListener('click', () => {
            window.location.href = "https://www.google.com";
        });
    }
});