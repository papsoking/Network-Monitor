document.addEventListener('DOMContentLoaded', function () {
    // Filtrage des alertes
    document.getElementById('severityFilter').addEventListener('change', filterAlerts);
    document.getElementById('statusFilter').addEventListener('change', filterAlerts);
    document.getElementById('typeFilter').addEventListener('change', filterAlerts);
    document.getElementById('searchAlertsInput').addEventListener('input', filterAlerts);
    function filterAlerts() {
        const severity = document.getElementById('severityFilter').value;
        const status = document.getElementById('statusFilter').value;
        const type = document.getElementById('typeFilter').value;
        const searchText = document.getElementById('searchAlertsInput').value.toLowerCase();
        
        // Ici, vous implémenteriez la logique de filtrage
        console.log(`Filtrage: Gravité=${severity}, Statut=${status}, Type=${type}, Recherche=${searchText}`);
    }
    // Marquer toutes les alertes comme lues
    document.getElementById('markAllAsReadBtn').addEventListener('click', function() {
        if (confirm('Marquer toutes les alertes comme lues ?')) {
            alert('Toutes les alertes ont été marquées comme lues.');
        }
    });
    // Exporter les alertes
    document.getElementById('exportAlertsBtn').addEventListener('click', function() {
        alert('Export des alertes en cours...');
    });
    // Rafraîchir la liste des alertes
    document.getElementById('refreshAlertsBtn').addEventListener('click', function() {
        alert('Actualisation des alertes...');
    });
    // Initialiser le tooltip Bootstrap
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});