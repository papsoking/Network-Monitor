document.addEventListener('DOMContentLoaded', function () {
    // var ctx = document.getElementById('availabilityChart').getContext('2d');
    // var chart = new Chart(ctx, {
    //     type: 'line',
    //     data: {
    //         labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
    //         datasets: [{
    //             label: 'Disponibilité',
    //             data: [90, 95, 98, 92, 96, 99],
    //             borderColor: 'rgba(75, 192, 192, 1)',
    //             backgroundColor: 'rgba(75, 192, 192, 0.2)',
    //             tension: 0.1
    //         }]
    //     },
    //     options: {
    //         responsive: true,
    //         scales: {
    //             y: {
    //                 beginAtZero: true,
    //                 max: 100
    //             }
    //         }
    //     }
    // });

    // Fonction de formatage
    function formatLastSeen(timestamp) {
        if (!timestamp) return 'Jamais';
        const date = new Date(timestamp * 1000); // ×1000 car JS utilise ms
        return date.toLocaleString('fr-FR');
    }
});