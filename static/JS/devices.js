document.addEventListener('DOMContentLoaded', function () {
    // Fonction de formatage
    function formatLastSeen(dateInput) {
        if (!dateInput) return 'Jamais';
        
        // Gestion des différents formats de date
        let dateObj;
        
        if (typeof dateInput === 'string') {
            // Si c'est au format "04/08/2025 20:36:19" (jour/mois/année)
            if (dateInput.includes('/')) {
                const [datePart, timePart] = dateInput.split(' ');
                const [day, month, year] = datePart.split('/');
                const [hours, minutes, seconds] = timePart?.split(':') || ['00', '00', '00'];
                dateObj = new Date(year, month-1, day, hours, minutes, seconds);
            }
            // Si c'est un timestamp string
            else if (!isNaN(dateInput)) {
                dateObj = new Date(parseInt(dateInput) * 1000);
            }
        }
        // Si c'est un timestamp numérique
        else if (typeof dateInput === 'number') {
            dateObj = new Date(dateInput * 1000);
        }
        
        if (!dateObj || isNaN(dateObj.getTime())) return 'Inconnu';
        
        const now = new Date();
        const diffSeconds = Math.floor((now - dateObj) / 1000);
        
        // Moins d'une minute
        if (diffSeconds < 60) return 'À l\'instant';
        
        // Moins d'une heure
        if (diffSeconds < 3600) {
            const mins = Math.floor(diffSeconds / 60);
            return `Il y a ${mins} min${mins > 1 ? '' : ''}`;
        }
        
        // Moins d'un jour
        if (diffSeconds < 86400) {
            const hours = Math.floor(diffSeconds / 3600);
            return `Il y a ${hours} h`;
        }
        
        // Moins de 30 jours
        if (diffSeconds < 2592000) {
            const days = Math.floor(diffSeconds / 86400);
            return `Il y a ${days} jour${days > 1 ? 's' : ''}`;
        }
        
        // Format complet pour les dates anciennes (jour/mois/année)
        return dateObj.toLocaleDateString('fr-FR', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric'
        });
    }

    // Fonction pour rafraîchir les temps
    function refreshLastSeenTimes() {
        document.querySelectorAll('td[data-timestamp]').forEach(cell => {
            const timestamp = parseFloat(cell.dataset.timestamp);
            cell.textContent = formatLastSeen(timestamp);
            cell.classList.add('loaded'); // Ajoute la classe pour l'affichage progressif
        });
    }

    const tbody = document.getElementById('devicesTableBody');
    tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4">Chargement des appareils...</td></tr>';

    // Récupérer les appareils via l'API
    function lanceScan () {
    fetch('/api/devices')
        .then(response => response.json())
        .then(data => {
            tbody.innerHTML = ''; // Vider le tableau avant d'ajouter les lignes
            if (!data || !data.devices) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4">Aucun appareil détecté sur le réseau</td></tr>';
                return;
            }
            
            if (data.devices.length === 0) {
                // Afficher un message si aucun appareil n'est trouvé
                tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4">Aucun appareil détecté sur le réseau</td></tr>';
                return;
            }

            console.log('Appareils récupérés:', data);

            data.devices.forEach((device, index) => {
                // Détermination du type d'icône et badge
                let icon = '<i class="fas fa-question-circle me-2 text-muted"></i>';
                let type = 'Inconnu';
                if (
                device.extra_info &&
                Array.isArray(device.extra_info.os_details) &&
                device.extra_info.os_details.length > 0
                ) {
                const mainOsClass = device.extra_info.os_details[0].osclass;
                if (Array.isArray(mainOsClass) && mainOsClass.length > 0) {
                    type = mainOsClass[0].osfamily || 'Inconnu';
                }
                }

                let badgeClass = 'bg-secondary';
                if (type.includes('Web')) { icon = '<i class="fas fa-globe me-2 text-primary"></i>'; badgeClass = 'bg-primary'; }
                else if (type.includes('Windows')) { icon = '<i class="fas fa-laptop me-2 text-primary"></i>'; badgeClass = 'bg-primary'; }
                else if (type.includes('Linux')) { icon = '<i class="fas fa-server me-2 text-secondary"></i>'; badgeClass = 'bg-secondary'; }
                else if (type.includes('Mobile')) { icon = '<i class="fas fa-mobile-alt me-2 text-info"></i>'; badgeClass = 'bg-info'; }
                else if (type.includes('ios')) { icon = '<i class="fas fa-mobile-alt me-2 text-info"></i>'; badgeClass = 'bg-info'; }
                else if (type.includes('iOS')) { icon = '<i class="fas fa-mobile-alt me-2 text-info"></i>'; badgeClass = 'bg-info'; }
                else if (type.includes('android')) { icon = '<i class="fas fa-mobile-alt me-2 text-info"></i>'; badgeClass = 'bg-info'; }
                else if (type.includes('Printer')) { icon = '<i class="fas fa-print me-2 text-warning"></i>'; badgeClass = 'bg-warning'; }
                else if (type.includes('IoT')) { icon = '<i class="fas fa-camera me-2 text-success"></i>'; badgeClass = 'bg-success'; }

                // Statut badge
                let statusBadge = device.status === 'online'
                    ? '<span class="badge bg-success">En ligne</span>'
                    : '<span class="badge bg-danger">Hors ligne</span>';

            

                // Génération du menu dropdown en fonction du statut d'autorisation
                let dropdownMenu = '';
                if (device.authorization === 'authorized') {
                    dropdownMenu = `
                        <li><a class="dropdown-item" href="/devices/${index+1}"><i class="fas fa-eye me-1"></i> Détails</a></li>
                        <li><a class="dropdown-item" href=""><i class="fas fa-pencil-alt me-1"></i> Modifier</a></li>
                        <li><a class="dropdown-item" href=""><i class="fas fa-plug me-1"></i> Tester la connexion</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item text-danger" href=""><i class="fas fa-trash me-1"></i> Supprimer</a></li>
                    `;
                } else if (device.authorization === 'unauthorized') {
                    dropdownMenu = `
                        <li><a class="dropdown-item" href=""><i class="fas fa-save me-1"></i> Enregistrer</a></li>
                        <li><a class="dropdown-item" href=""><i class="fas fa-plug me-1"></i> Tester la connexion</a></li>
                    `;
                }

                let my_device = '';
                if (device.my_device) {
                    my_device = '(Votre appareil)';
                } else {
                    my_device = '';
                }

                const lastSeen = device.status === 'online' 
                    ? 'À l\'instant' 
                    : formatLastSeen(device.last_seen);
                

                // Créer la ligne
                const row = `
<tr>
    <td><a href="/devices/${device.ip}" class="text-style-none">${icon} ${device.hostname || 'Inconnu'} ${my_device}</a></td>
    <td>${device.ip}</td>
    <td>${device.mac ? device.mac.toUpperCase() : 'N/A'}</td>
    <td>${device.vendor || 'Inconnu'}</td>
    <td><span class="badge ${badgeClass}">${type}</span></td>
    <td>${statusBadge}</td>
    <td>${lastSeen}</td>
    <td>
        <div class="dropdown">
            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                <i class="fas fa-ellipsis-h"></i>
            </button>
            <ul class="dropdown-menu">
                <li><button class="dropdown-item edit-device" 
                    data-bs-toggle="modal" 
                    data-bs-target="#editDeviceModal"
                    data-device-id="${device.id}"
                    data-device-ip="${device.ip}"
                    data-device-mac="${device.mac}"
                    data-device-hostname="${device.hostname || ''}"
                    data-device-vendor="${device.vendor || ''}"
                    data-device-type="${device.device_type || ''}"
                    data-device-auth="${device.authorization}"
                    <i class="fas fa-pencil-alt me-1"></i> Modifier
                </button></li>
                ${device.authorization === 'authorized' ? `
                <li><button class="dropdown-item delete-device text-danger" data-device-id="${device.id}">
                    <i class="fas fa-trash me-1"></i> Supprimer
                </button></li>
                ` : ''}
            </ul>
        </div>
    </td>
</tr>`;
                tbody.insertAdjacentHTML('beforeend', row);
            });

            
        })
        .catch(error => {
            console.error('Erreur lors du chargement des appareils:', error);
        });
    }

    // Bouton de rafraîchissement
    document.getElementById('scanBtn').addEventListener('click', function() {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center py-4">Chargement...</td></tr>';
        lanceScan();
    });

    // Initialisation
    lanceScan();
    
    // Mise à jour périodique
    setInterval(refreshLastSeenTimes, 60000); // Toutes les minutes

    setInterval(lanceScan, 300000); // Toutes les 5 minutes
    
    
    // Gestion du formulaire modal
    const editDeviceModal = document.getElementById('editDeviceModal');
    if (editDeviceModal) {
        editDeviceModal.addEventListener('show.bs.modal', function(event) {
            const button = event.relatedTarget;
            const deviceId = button.getAttribute('data-device-id');
            const deviceIp = button.getAttribute('data-device-ip');
            const deviceMac = button.getAttribute('data-device-mac');
            const deviceHostname = button.getAttribute('data-device-hostname');
            const deviceAuth = button.getAttribute('data-device-auth');
            const deviceVendor = button.getAttribute('data-device-vendor') || '';
            const deviceType = button.getAttribute('data-device-type') || 'Inconnu';

            document.getElementById('deviceId').value = deviceId;
            document.getElementById('ip').value = deviceIp;
            document.getElementById('mac').value = deviceMac;
            document.getElementById('hostname').value = deviceHostname || '';
            document.getElementById('vendor').value = deviceVendor || '';
            document.getElementById('deviceType').value = deviceType;
            
            // Sélectionner le bon bouton radio
            if (deviceAuth === 'authorized') {
                document.getElementById('authorized').checked = true;
            } else {
                document.getElementById('unauthorized').checked = true;
            }
        });
    }

    // Sauvegarde de l'appareil
    document.getElementById('saveDeviceBtn').addEventListener('click', function() {
        const authorization = document.querySelector('input[name="authorization"]:checked');
        if (!authorization) {
            alert('Veuillez sélectionner un statut d\'autorisation');
            return;
        }
        

        const formData = {
            device_id: document.getElementById('deviceId').value,
            hostname: document.getElementById('hostname').value,
            ip: document.getElementById('ip').value,
            mac: document.getElementById('mac').value,
            authorization: authorization.value,
            vendor: document.getElementById('vendor').value,
            device_type: document.getElementById('deviceType').value
        };

        console.log("id de l'appareil:", document.getElementById('deviceId').value);

        const method = formData.device_id ? 'PUT' : 'POST';
        const url = formData.device_id ? `/api/devices/${formData.device_id}` : '/api/devices';

        console.log('Envoi des données:', formData);
        console.log('Méthode:', method);
        console.log('URL:', url);


        fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                alert('Erreur: ' + data.error);
            } else {
                // Rafraîchir la liste des appareils
                lanceScan();
                // Fermer le modal
                const modalEl = document.getElementById('editDeviceModal');
                const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
                modal.hide();
            }
        })
        .catch(error => {
            console.error('Erreur:', error);
            alert('Une erreur est survenue');
        });
    });

    // Gestion de la suppression
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('delete-device')) {
            e.preventDefault();
            const deviceId = e.target.getAttribute('data-device-id');
            
            if (confirm('Êtes-vous sûr de vouloir supprimer cet appareil ?')) {
                fetch(`/api/devices/${deviceId}`, {
                    method: 'DELETE'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert('Erreur: ' + data.error);
                    } else {
                        // Rafraîchir la liste des appareils
                        lanceScan();
                    }
                })
                .catch(error => {
                    console.error('Erreur:', error);
                    alert('Une erreur est survenue');
                });
            }
        }
    });
});