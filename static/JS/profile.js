// // Enregistrer les modifications du profil
// document.getElementById('saveProfileBtn').addEventListener('click', function() {
//     // Simulation de sauvegarde
//     const toast = document.createElement('div');
//     toast.className = 'position-fixed bottom-0 end-0 p-3';
//     toast.style.zIndex = '11';
//     toast.innerHTML = `
//         <div class="toast show" role="alert" aria-live="assertive" aria-atomic="true">
//             <div class="toast-header bg-success text-white">
//                 <strong class="me-auto">Succès</strong>
//                 <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
//             </div>
//             <div class="toast-body">
//                 Profil mis à jour avec succès.
//             </div>
//         </div>
//     `;
//     document.body.appendChild(toast);
    
//     // Fermer le modal après 2 secondes
//     setTimeout(() => {
//         bootstrap.Modal.getInstance(document.getElementById('editProfileModal')).hide();
//         setTimeout(() => toast.remove(), 1000);
//     }, 2000);
// });

// // Prévisualisation de l'avatar
// document.getElementById('avatar').addEventListener('change', function(e) {
//     const file = e.target.files[0];
//     if (file) {
//         const reader = new FileReader();
//         reader.onload = function(event) {
//             document.querySelector('.profile-avatar').src = event.target.result;
//         };
//         reader.readAsDataURL(file);
//     }
// });

document.addEventListener('DOMContentLoaded', function() {
    // Sauvegarde du profil
    document.getElementById('saveProfileBtn').addEventListener('click', function() {
        document.getElementById('profileForm').submit();
    });
    
    // Suppression du compte
    document.getElementById('deleteAccountBtn').addEventListener('click', function() {
        if (confirm('Êtes-vous sûr de vouloir supprimer votre compte ? Cette action est irréversible.')) {
            fetch("{{ url_for('delete_profile') }}", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                credentials: 'same-origin'
            })
            .then(response => response.json())
            .then(data => {
                if (data.redirect) {
                    window.location.href = data.redirect;
                }
            })
            .catch(error => console.error('Error:', error));
        }
    });
    
    // Validation du formulaire
    document.getElementById('profileForm').addEventListener('submit', function(e) {
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        
        if (newPassword !== confirmPassword) {
            e.preventDefault();
            alert('Les mots de passe ne correspondent pas');
        }
    });
});