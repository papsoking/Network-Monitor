        // Graphique Bande Passante
        const bandwidthCtx = document.getElementById('bandwidthChart').getContext('2d');
        const bandwidthChart = new Chart(bandwidthCtx, {
            type: 'line',
            data: {
                labels: ['01/07', '08/07', '15/07', '22/07', '29/07'],
                datasets: [
                    {
                        label: 'Bande passante entrante (Mbps)',
                        data: [32, 45, 28, 51, 42],
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        tension: 0.3,
                        fill: true
                    },
                    {
                        label: 'Bande passante sortante (Mbps)',
                        data: [18, 23, 15, 28, 21],
                        borderColor: '#e74c3c',
                        backgroundColor: 'rgba(231, 76, 60, 0.1)',
                        tension: 0.3,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Graphique Appareils
        const devicesCtx = document.getElementById('devicesChart').getContext('2d');
        const devicesChart = new Chart(devicesCtx, {
            type: 'bar',
            data: {
                labels: ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim'],
                datasets: [{
                    label: 'Appareils connectés',
                    data: [42, 45, 48, 40, 38, 32, 28],
                    backgroundColor: 'rgba(52, 152, 219, 0.7)',
                    borderColor: 'rgba(52, 152, 219, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Graphique Sécurité
        const securityCtx = document.getElementById('securityChart').getContext('2d');
        const securityChart = new Chart(securityCtx, {
            type: 'radar',
            data: {
                labels: ['Vulnérabilités', 'Accès non autorisés', 'Ports ouverts', 'Appareils non patchés', 'Politiques faible'],
                datasets: [{
                    label: 'Score de sécurité',
                    data: [65, 59, 80, 45, 70],
                    backgroundColor: 'rgba(231, 76, 60, 0.2)',
                    borderColor: 'rgba(231, 76, 60, 1)',
                    pointBackgroundColor: 'rgba(231, 76, 60, 1)',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: 'rgba(231, 76, 60, 1)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        angleLines: {
                            display: true
                        },
                        suggestedMin: 0,
                        suggestedMax: 100
                    }
                }
            }
        });

        // Graphique Alertes
        const alertsCtx = document.getElementById('alertsChart').getContext('2d');
        const alertsChart = new Chart(alertsCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critiques', 'Élevées', 'Moyennes', 'Faibles', 'Informations'],
                datasets: [{
                    data: [3, 7, 15, 8, 4],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#0dcaf0',
                        '#198754'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                    }
                }
            }
        });

        // Initialiser les dates pour la période personnalisée
    const today = new Date();
    const endDateInput = document.getElementById('reportEndDate');
    endDateInput.valueAsDate = today;
    
    const startDateInput = document.getElementById('reportStartDate');
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(today.getDate() - 7);
    startDateInput.valueAsDate = oneWeekAgo;
    
    // Validation des dates
    startDateInput.addEventListener('change', function() {
        if (new Date(this.value) > new Date(endDateInput.value)) {
            alert('La date de début ne peut pas être postérieure à la date de fin');
            this.value = endDateInput.value;
        }
    });
    
    endDateInput.addEventListener('change', function() {
        if (new Date(this.value) < new Date(startDateInput.value)) {
            alert('La date de fin ne peut pas être antérieure à la date de début');
            this.value = startDateInput.value;
        }
    });

    // Afficher/masquer la sélection de date personnalisée
    document.getElementById('reportTimeframe').addEventListener('change', function() {
        const customDateRange = document.getElementById('customDateRange');
        if (this.value === 'custom') {
            customDateRange.style.display = 'flex';
        } else {
            customDateRange.style.display = 'none';
        }
    });

    // Gestion de la génération de rapport
    document.getElementById('generateReportBtn').addEventListener('click', function() {
        const form = document.getElementById('generateReportForm');
        if (!form.checkValidity()) {
            form.classList.add('was-validated');
            return;
        }
        
        // Simulation de génération de rapport
        const reportType = document.getElementById('reportType').value;
        const reportName = document.getElementById('reportName').value || `Rapport ${reportType}`;
        
        // Afficher une notification de succès
        const toastHTML = `
            <div class="position-fixed bottom-0 end-0 p-3" style="z-index: 11">
                <div class="toast show" role="alert" aria-live="assertive" aria-atomic="true">
                    <div class="toast-header bg-success text-white">
                        <strong class="me-auto">Succès</strong>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
                    </div>
                    <div class="toast-body">
                        Le rapport "${reportName}" est en cours de génération. Vous recevrez une notification une fois terminé.
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', toastHTML);
        
        // Fermer le modal après 2 secondes
        setTimeout(() => {
            bootstrap.Modal.getInstance(document.getElementById('generateReportModal')).hide();
            document.querySelector('.toast').remove();
        }, 2000);
    });