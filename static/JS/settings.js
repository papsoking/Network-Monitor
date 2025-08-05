// Activer/désactiver le bouton de confirmation de réinitialisation
document.getElementById('confirmReset').addEventListener('change', function() {
    document.getElementById('confirmResetBtn').disabled = !this.checked;
});

// Copier la clé API
document.getElementById('copyApiKey').addEventListener('click', function() {
    const apiKey = document.getElementById('apiKey');
    apiKey.select();
    document.execCommand('copy');
    
    // Afficher une notification
    const toast = document.createElement('div');
    toast.className = 'position-fixed bottom-0 end-0 p-3';
    toast.style.zIndex = '11';
    toast.innerHTML = `
        <div class="toast show" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-success text-white">
                <strong class="me-auto">Succès</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                Clé API copiée dans le presse-papiers.
            </div>
        </div>
    `;
    document.body.appendChild(toast);
    
    // Supprimer la notification après 3 secondes
    setTimeout(() => {
        toast.remove();
    }, 3000);
});

// Régénérer la clé API
document.getElementById('regenerateApiKey').addEventListener('click', function() {
    if (confirm('Êtes-vous sûr de vouloir générer une nouvelle clé API ? Les applications utilisant l\'ancienne clé cesseront de fonctionner.')) {
        // Générer une nouvelle clé API (simulation)
        const newApiKey = 'nm_' + Math.random().toString(36).substring(2, 18) + Math.random().toString(36).substring(2, 18);
        document.getElementById('apiKey').value = newApiKey;
        
        // Afficher une notification
        const toast = document.createElement('div');
        toast.className = 'position-fixed bottom-0 end-0 p-3';
        toast.style.zIndex = '11';
        toast.innerHTML = `
            <div class="toast show" role="alert" aria-live="assertive" aria-atomic="true">
                <div class="toast-header bg-success text-white">
                    <strong class="me-auto">Succès</strong>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
                </div>
                <div class="toast-body">
                    Nouvelle clé API générée avec succès.
                </div>
            </div>
        `;
        document.body.appendChild(toast);
        
        // Supprimer la notification après 3 secondes
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }
});

// Afficher/masquer les champs en fonction des sélections
document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
    checkbox.addEventListener('change', function() {
        const integrationCard = this.closest('.integration-card');
        if (integrationCard) {
            const inputs = integrationCard.querySelectorAll('input:not([type="checkbox"]), select, button');
            inputs.forEach(input => {
                input.disabled = !this.checked;
            });
        }
    });
});

// Initialiser l'état des champs d'intégration
document.querySelectorAll('.integration-card input[type="checkbox"]').forEach(checkbox => {
    const integrationCard = checkbox.closest('.integration-card');
    const inputs = integrationCard.querySelectorAll('input:not([type="checkbox"]), select, button');
    inputs.forEach(input => {
        input.disabled = !checkbox.checked;
    });
});