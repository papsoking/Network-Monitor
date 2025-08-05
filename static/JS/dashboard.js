// === Initialisation globale du graphique ===
const networkCtx = document.getElementById('networkActivityChart').getContext('2d');
const networkChart = new Chart(networkCtx, {
    type: 'line',
    data: {
        labels: [], // Labels horaires (ex: 13:45:02, 13:45:05...)
        datasets: [
            {
                label: 'Trafic entrant (Mbps)',
                data: [],
                borderColor: '#3498db',
                backgroundColor: 'rgba(52, 152, 219, 0.1)',
                tension: 0.3,
                fill: true
            },
            {
                label: 'Trafic sortant (Mbps)',
                data: [],
                borderColor: '#e74c3c',
                backgroundColor: 'rgba(231, 76, 60, 0.1)',
                tension: 0.3,
                fill: true
            }
        ]
    },
    options: {
        responsive: true,
        plugins: {
            legend: { position: 'top' },
            tooltip: { mode: 'index', intersect: false }
        },
        scales: {
            y: { beginAtZero: true }
        }
    }
});

// === Fonction de mise à jour réseau ===
function updateNetworkChart() {
    fetch('/api/network-traffic')
        .then(response => response.json())
        .then(data => {
            // console.log('Réponse API:', data); // Pour debug

            // Sécurité : vérifier que les données sont bien là
            if (!data.timestamp || data.incoming === undefined || data.outgoing === undefined) {
                console.warn("Données incomplètes", data);
                return;
            }

            const labels = networkChart.data.labels;
            const inData = networkChart.data.datasets[0].data;
            const outData = networkChart.data.datasets[1].data;

            if (labels.length >= 20) {
                labels.shift();
                inData.shift();
                outData.shift();
            }

            labels.push(data.timestamp);
            inData.push(data.incoming);
            outData.push(data.outgoing);

            networkChart.update();
        })
        .catch(err => console.error("Erreur fetch /api/network-traffic:", err));
}

// === Démarrage de la mise à jour réseau ===
updateNetworkChart(); // Premier appel immédiat
setInterval(updateNetworkChart, 3000); // Ensuite toutes les 3 sec

// Recommencer le graphique des données à 0 après 30 secondes
setTimeout(() => {
    networkChart.data.labels = [];
    networkChart.data.datasets[0].data = [];
    networkChart.data.datasets[1].data = [];
    networkChart.update();
}, 30000);



// Graphique des types d'appareils
const deviceCtx = document.getElementById('deviceTypesChart').getContext('2d');
const deviceChart = new Chart(deviceCtx, {
    type: 'doughnut',
    data: {
        labels: ['PC', 'Mobile', 'Serveurs', 'IoT', 'Imprimantes'],
        datasets: [{
            data: [12, 8, 3, 5, 2],
            backgroundColor: [
                '#3498db',
                '#2ecc71',
                '#f39c12',
                '#9b59b6',
                '#e74c3c'
            ],
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: {
                position: 'right',
            }
        }
    }
});
// Initialiser le tooltip Bootstrap
const tooltipTriggerList1 = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
tooltipTriggerList1.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl);
});

// Fonction pour charger les statistiques
function loadDashboardStats() {
    fetch('/api/dashboard-stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('total-devices').textContent = (data.registered_devices).length;
            document.getElementById('online-devices').textContent = data.online_devices;
            document.getElementById('devicesAlerts').textContent = data.unauthorized_devices.length;

            console.log('appareils récents:', data);
            
        });
}

// Charger les stats au départ
loadDashboardStats();

// Rafraîchir périodiquement
setInterval(loadDashboardStats, 30000); // Toutes les 30 secondes