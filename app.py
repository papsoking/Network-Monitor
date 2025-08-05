from flask import Flask, render_template, url_for, request, redirect, session, flash, jsonify
import mysql.connector
from mysql.connector import Error
import bcrypt
from flask_cors import CORS
import platform
import socket
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
import nmap
import time
from ping3 import ping
import os
from threading import Lock
from collections import Counter
import uuid
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()


app = Flask(__name__)
CORS(app) # Permettre CORS pour toutes les routes
# CORS(app, resources={r"/api/*": {"origins": os.getenv("URI_FRONT")}}) # Autoriser les requêtes CORS depuis l'URI du front
app.secret_key = os.getenv("SECRET_KEY")
devices_lock = Lock()


# Configuration de la base de données
try:
    conn = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )
except mysql.connector.Error as err:
    print(f"Erreur de connexion à la base de données: {err}")
    # Gérer l'erreur (redémarrer ou quitter)

# Page Accueil ou Dashboard
@app.route('/')
def home():
    return render_template('home.html')

# Pages d'authentification
# Connexion
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email and password:
            if not conn :
                flash('Erreur de connexion à la base de données.', 'danger')
                return redirect(request.url)
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.close()

            if user:
                # Récupérer le mot de passe hashé depuis la base
                hashed_password = user['password']

                # Comparer le mot de passe fourni avec le hash
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                    # Mot de passe correct, on peut enregistrer l'utilisateur dans la session
                    session['user_id'] = user['id']
                    session['user_email'] = user['email']
                    session['user_firstname'] = user['firstname'].capitalize()
                    session['user_lastname'] = user['lastname'].capitalize()
                    flash('Connexion réussie!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    # Mot de passe incorrect
                    flash('Mot de passe incorrect.', 'danger')
                    return redirect(request.url)
            else:
                # Aucun utilisateur trouvé avec cet email
                flash('Aucun utilisateur trouvé avec cet email.', 'danger')
                return redirect(request.url)
        else:
            # Email ou mot de passe manquant
            flash('Tous les champs sont requis.', 'danger')
            return redirect(request.url)

    return render_template('/auth/login.html')

# Inscription
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        firstname = request.form.get('firstName')
        lastname = request.form.get('lastName')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


        if firstname and lastname and email and password:
            cursor = conn.cursor()
            sql_query = "INSERT INTO users (firstname, lastname, email, password) VALUES (%s, %s, %s, %s)"
            values = (firstname, lastname, email, hashed_password.decode('utf-8'))
            cursor.execute(sql_query, values)
            conn.commit()
            cursor.close()

            flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        else:
            # Afficher un message d'erreur (tu peux utiliser flash par ex.)
            flash('Tous les champs sont requis.', 'danger')
            return redirect(request.url)
    return render_template('/auth/register.html')

# Page de mot de passe oublié
@app.route("/forgotPassword", methods=['GET', 'POST'])
def forgot_password():
    return render_template('/auth/forgot-password.html')

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        # Logique pour récupérer les données du dashboard
        return render_template('/dashboard/dashboard.html', current_page='dashboard',
                               user_firstname=session.get('user_firstname', 'Utilisateur'),
                               user_lastname=session.get('user_lastname', ''))
    else:
        flash('Veuillez vous connecter pour accéder au dashboard.', 'warning')
        return redirect(url_for('login'))


# Page Appareils
@app.route('/devices')
def devices():
    if 'user_id' in session:
        # Logique pour récupérer les appareils
        return render_template('/dashboard/devices.html', current_page='devices')
    else:
        flash('Veuillez vous connecter pour accéder à la page de gestion des appareils.', 'warning')
        return redirect(url_for('login'))

# Page Réseaux
@app.route('/networks')
def networks():
    if 'user_id' in session:
        # Logique pour récupérer les réseaux
        return render_template('/dashboard/networks.html', current_page='networks')
    else:
        flash('Veuillez vous connecter pour accéder à la page de gestion du réseaux.', 'warning')
        return redirect(url_for('login'))

# Page Alertes
@app.route('/alerts')
def alerts():
    if 'user_id' in session:
        # Logique pour récupérer les alertes
        return render_template('/dashboard/alerts.html', current_page='alerts')
    else:
        flash('Veuillez vous connecter pour accéder à la page des alertes.', 'warning')
        return redirect(url_for('login'))

# Page Rapports
@app.route('/reports')
def reports():
    if 'user_id' in session:
        # Logique pour récupérer les rapports
        return render_template('/dashboard/reports.html', current_page='reports')
    else:
        flash('Veuillez vous connecter pour accéder à la page des rapports.', 'warning')
        return redirect(url_for('login'))

# Page Profil
# @app.route('/profile')
# def profile():
#     if 'user_id' in session:
#         # Logique pour récupérer les informations du profil
#         return render_template('/dashboard/profile.html', current_page='profile',
#                                user_firstname=session.get('user_firstname', 'Utilisateur'),
#                                user_lastname=session.get('user_lastname', ''),
#                                user_email=session.get('user_email', ''))
#     else:
#         flash('Veuillez vous connecter pour accéder à votre profil.', 'warning')
#         return redirect(url_for('login'))

# Page Paramètres
@app.route('/settings')
def settings():
    if 'user_id' in session:
        # Logique pour récupérer les paramètres
        return render_template('/dashboard/settings.html', current_page='settings')
    else:
        flash('Veuillez vous connecter pour accéder aux paramètres.', 'warning')
        return redirect(url_for('login'))

# Page de déconnexion
@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Logique pour déconnecter l'utilisateur
        session.pop('user_id', None)
        flash('Vous avez été déconnecté.', 'info')
        return redirect(url_for('home'))
    else:
        flash('Vous n\'êtes pas connecté.', 'warning')
        return redirect(url_for('login'))

# Gestion du cache pour les réponses
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


#########################################################
#### Partie scanning réseau et gestion des appareils ####
#########################################################

# Configuration
APPAREILS_AUTORISES = "SELECT ip FROM devices WHERE status = 'authorized'"
SCAN_INTERVAL = 300  # 5 minutes entre les scans complets



@app.route('/api/network-traffic')
def get_network_stats():
    """API pour les statistiques réseau"""
    net1 = psutil.net_io_counters()
    time.sleep(1)
    net2 = psutil.net_io_counters()

    # Calcule la différence sur 1 seconde
    bytes_sent = net2.bytes_sent - net1.bytes_sent
    bytes_recv = net2.bytes_recv - net1.bytes_recv

    # Conversion en Mbps
    incoming_mbps = (bytes_recv * 8) / (1024 * 1024)
    outgoing_mbps = (bytes_sent * 8) / (1024 * 1024)

    # print(f"Incoming: {incoming_mbps:.2f} Mbps, Outgoing: {outgoing_mbps:.2f} Mbps")

    return jsonify({
        "timestamp": time.strftime("%H:%M:%S"),
        "incoming": incoming_mbps,
        "outgoing": outgoing_mbps
    })


@app.route('/api/dashboard-stats')
def dashboard_stats(network_prefix='192.168.1.', start=1, end=254):
    """API pour les statistiques du dashboard"""
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Non autorisé'}), 401
    
    all_devices = []
    unauthorized_devices = []
    user_id = session['user_id']

    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT deviceIP, deviceMAC, deviceName 
        FROM devices 
        WHERE user_id = %s
    """, (user_id,))
    all_devices = {
        (row['deviceMAC'], row['deviceIP']): row['deviceName']
        for row in cursor.fetchall()
    }
    cursor.close()

    # Pour les appareils non autorisés
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT deviceIP, deviceMAC, deviceName 
        FROM devices 
        WHERE user_id = %s AND deviceAuthorization = 'unauthorized'
    """, (user_id,))
    unauthorized_devices = {
        (row['deviceMAC'], row['deviceIP']): row['deviceName']
        for row in cursor.fetchall()
    }
    cursor.close()

    # Scan rapide du réseau pour détecter les appareils actifs
    
    active_ips = []

    def ping_ip(i):
        ip = f"{network_prefix}{i}"
        if ping(ip, timeout=0.5):  # timeout court
            return ip
        return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(ping_ip, range(start, end+1))

    for ip in results:
        if ip:
            active_ips.append(ip)

    return jsonify({
        'total_devices': len(active_ips),
        'online_devices': len(active_ips),
        'recent_devices': active_ips,  # [-5] Derniers 5 appareils détectés
        'registered_devices': list(all_devices.keys()),
        'unauthorized_devices': list(unauthorized_devices.keys()),
    })

def save_devices_to_db(devices, user_id):
    """Enregistre les appareils scannés dans la base de données"""
    try:
        cursor = conn.cursor()
        
        for device in devices:
            # Vérifier si l'appareil existe déjà
            cursor.execute("""
                SELECT id FROM devices 
                WHERE deviceIP = %s OR deviceMAC = %s
            """, (device['ip'], device.get('mac', '')))
            existing = cursor.fetchone()
            
            if existing:
                # Mise à jour de l'appareil existant
                cursor.execute("""
                    UPDATE devices SET 
                    deviceMAC = %s,
                    deviceName = %s,
                    deviceVendor = %s,
                    lastSeen = %s,
                    status = 'online',
                    user_id = %s
                    WHERE id = %s
                """, (
                    device.get('mac', ''),
                    device.get('hostname', ''),
                    device.get('vendor', ''),
                    datetime.now(),
                    user_id,
                    existing[0]
                ))
            else:
                # Insertion d'un nouvel appareil
                cursor.execute("""
                    INSERT INTO devices (
                        deviceIP, deviceMAC, deviceName, 
                        deviceVendor, firstSeen, lastSeen, 
                        status, user_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    device['ip'],
                    device.get('mac', ''),
                    device.get('hostname', ''),
                    device.get('vendor', ''),
                    datetime.now(),
                    datetime.now(),
                    'online',
                    user_id
                ))
        
        conn.commit()
        cursor.close()
        print(f"{len(devices)} appareils enregistrés/mis à jour en base de données")
    except Exception as e:
        print(f"Erreur lors de l'enregistrement des appareils: {e}")
        conn.rollback()

network_devices = {}
last_scan_time = 0

# Fonction pour scanner le réseau local
# Ping sur les adresses IP pour vérifier la connectivité
def get_mac_vendor(mac):
    """Trouve le fabricant à partir de l'adresse MAC"""
    if not mac or mac == "00:00:00:00:00:00":
        return "Inconnu"
    
    # Convertit en format standard (00:00:00)
    mac_prefix = mac.replace(':', '').replace('-', '')[:6].upper()
    
    # Base de données locale
    mac_vendors = load_mac_vendors("mac-vendors.txt")
    
    return mac_vendors.get(mac_prefix, "Inconnu")

def load_mac_vendors(filepath):
    vendors = {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:  # On vérifie maintenant la présence de ':'
                    # Séparation du préfixe MAC et du nom du fabricant
                    mac_part, vendor_part = line.split(':', 1)  # split sur le premier ':' seulement
                    
                    # Nettoyage et normalisation du préfixe MAC
                    prefix = mac_part.strip().upper().replace('-', '').replace(':', '')[:6]
                    
                    # Nettoyage du nom du fabricant
                    vendor_name = vendor_part.strip()
                    
                    # Ajout au dictionnaire
                    vendors[prefix] = vendor_name
    except Exception as e:
        print(f"Erreur lors du chargement des vendors: {e}")
    return vendors

# Charger au démarrage
mac_vendors = load_mac_vendors("mac-vendors.txt")

def get_device_details(ip, device_base=None):
    """Récupère les détails complets d'un appareil"""
    details = {
        'ip': ip,
        'id': None,  # ID sera défini lors de l'enregistrement en base de données
        'hostname': 'Inconnu',
        'os': "Inconnu",
        'os_accuracy': 0,
        'mac': "00:00:00:00:00:00",
        'vendor': "Inconnu",
        'ports': [],
        'services': {},
        'last_seen': datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
        'status': 'online',
        'device_type': 'Inconnu',
        'extra_info': {}
    }

    if device_base:
        details.update(device_base)


    try:
        # D'abord essayer de récupérer le nom d'hôte
        try:
            details['hostname'] = socket.getfqdn(ip) or 'Inconnu'
            print(f"Nom d'hôte pour {ip}: {details['hostname']}")
        except:
            pass

        # Scan Nmap plus approfondi
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-O -sV --host-timeout 180s')

        print(f"Scan Nmap pour {nm.all_hosts()} en cours...")

        if ip in nm.all_hosts():
            host = nm[ip]
            print(f"Scan Nmap pour {host} terminé.")

            # Détection OS
            if 'osmatch' in host and host['osmatch']:
                best_os = max(host['osmatch'], key=lambda x: int(x['accuracy']))
                details['os'] = best_os['name']
                details['os_accuracy'] = best_os['accuracy']
                details['extra_info']['os_details'] = host['osmatch']

            # Adresse MAC et fabricant
            if 'mac' in host['addresses']:
                details['mac'] = host['addresses']['mac']
                details['vendor'] = get_mac_vendor(details['mac'])
            elif 'vendor' in host and host['vendor']:
                details['vendor'] = list(host['vendor'].values())[0]

            vendor = 'Inconnu'

            if (
                'extra_info' in details and
                isinstance(details['extra_info'].get('os_details'), list) and
                len(details['extra_info']['os_details']) > 0
            ):
                main_os_class = details['extra_info']['os_details'][0].get('osclass')
                if isinstance(main_os_class, list) and len(main_os_class) > 0:
                    vendor = main_os_class[0].get('vendor', 'Inconnu')
            
            details['vendor'] = vendor or get_mac_vendor(details['mac'])

            # Ports et services
            details['ports'] = [
                {
                    'port': port, 
                    'state': data['state'], 
                    'service': data.get('name', 'unknown'),
                    'version': data.get('version', ''),
                    'product': data.get('product', ''),
                    'extra': data.get('extrainfo', '')
                } 
                for port, data in host.get('tcp', {}).items()
            ]

            # Détection du type d'appareil (osfamily)
            osfamily = 'Inconnu'

            if (
                'extra_info' in details and
                isinstance(details['extra_info'].get('os_details'), list) and
                len(details['extra_info']['os_details']) > 0
            ):
                main_os_class = details['extra_info']['os_details'][0].get('osclass')
                if isinstance(main_os_class, list) and len(main_os_class) > 0:
                    osfamily = main_os_class[0].get('osfamily', 'Inconnu')

            details['device_type'] = osfamily or detect_device_type(host)


            # Informations supplémentaires des scripts Nmap
            if 'hostscript' in host:
                details['extra_info']['scripts'] = host['hostscript']

    except Exception as e:
        print(f"Erreur lors du scan approfondi de {ip}: {e}")

    return details

def detect_device_type(host_data):
    """Détecte le type d'appareil basé sur les informations Nmap"""
    open_ports = host_data.get('tcp', {}).keys()
    
    # Détection basée sur les ports ouverts
    if 80 in open_ports or 443 in open_ports:
        return 'Serveur Web'
    elif 22 in open_ports:
        return 'Serveur SSH (Linux?)'
    elif 3389 in open_ports:
        return 'Bureau à distance (Windows?)'
    elif 445 in open_ports:
        return 'Partage de fichiers (Windows/Samba)'
    elif 5353 in open_ports or 1900 in open_ports:
        return 'Appareil IoT (Smart TV, etc.)'
    
    # Détection basée sur l'OS
    if 'osmatch' in host_data and host_data['osmatch']:
        os_name = host_data['osmatch'][0]['name'].lower()
        if 'windows' in os_name:
            return 'Appareil Windows'
        elif 'linux' in os_name:
            return 'Appareil Linux'
        elif 'android' in os_name:
            return 'Appareil Android'
        elif 'ios' in os_name or 'apple' in os_name:
            return 'Appareil Apple'
    
    # Détection basée sur le MAC vendor
    if 'mac' in host_data['addresses']:
        mac_vendor = get_mac_vendor(host_data['addresses']['mac']).lower()
        if 'cisco' in mac_vendor:
            return 'Equipement réseau Cisco'
        elif 'huawei' in mac_vendor:
            return 'Appareil Huawei'
        elif 'xiaomi' in mac_vendor:
            return 'Appareil Xiaomi'
    
    return 'Inconnu'


quick_scan_results = {}
quick_scan_lock = Lock()

# 2. Route pour le scan rapide
@app.route('/api/quick-scan', methods=['GET'])
def fast_nmap_scan(network):
    """Scan rapide avec Nmap pour détecter les hôtes actifs"""
    nm = nmap.PortScanner()
    # Arguments pour un scan rapide (pas de scan de ports, juste détection d'hôtes)
    nm.scan(hosts=network, arguments='-sn -T4 --max-retries 1 --host-timeout 15s')
    
    # Récupérer les infos de l'appareil local une seule fois
    local_device_info = get_current_device_info()
    local_ip = local_device_info.get('ip', '')
    local_mac = local_device_info.get('mac', '').upper()
    local_vendor = local_device_info.get('vendor', 'Inconnu')
    
    active_hosts = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            # Déterminer si c'est l'appareil local
            is_local_device = (host == local_ip)
            if is_local_device:
                nm[host]['addresses']['mac'] = local_mac
                nm[host]['vendor'] = {local_mac: local_vendor}
            else:
                # Récupérer l'adresse MAC si disponible
                mac = nm[host].get('addresses', {}).get('mac', '')
            print(f"Host {host} is up, MAC: {mac if mac else 'Inconnu'}")
            
            
            # Récupérer les informations de l'hôte
            host_info = {
                'ip': host,
                'mac': nm[host].get('addresses', {}).get('mac', '') or '00:00:00:00:00:00',
                'hostname': nm[host].hostname() or 'Inconnu',
                'status': 'online',
                'vendor': (local_device_info.get('vendor', 'Inconnu') if is_local_device 
                          else nm[host].get('vendor', {}).get(mac, '') or get_mac_vendor(mac)),
                'my_device': is_local_device
            }
            active_hosts.append(host_info)
    
    return active_hosts

# 3. Fonction pour récupérer les infos de l'appareil local
def get_current_device_info():
    """Retourne les infos de l'appareil qui exécute le scan"""
    info = {}
    try:
        # Nom d'hôte
        hostname = socket.gethostname()
        info['hostname'] = hostname

        # IP locale
        ip_address = socket.gethostbyname(hostname)
        info['ip'] = ip_address

        # Adresse MAC (première interface)
        mac_num = hex(uuid.getnode()).replace('0x', '').zfill(12)
        mac_address = ':'.join(mac_num[i:i+2] for i in range(0, 12, 2))
        info['mac'] = mac_address

        # Vendor (si tu as la base mac_vendors)
        info['vendor'] = get_mac_vendor(mac_address)

        # OS
        info['os'] = platform.system() + " " + platform.release()

        # occurance de l'OS
        info['os_accuracy'] = 100  # Valeur par défaut, peut être ajustée

        # Type d'architecture (ex: x86_64)
        info['architecture'] = platform.machine()

    except Exception as e:
        print(f"Erreur lors de la récupération des infos de l'appareil local: {e}")
    
    return info

# Route pour récupérer les infos de l'appareil local
@app.route('/api/my-device', methods=['GET'])
def api_my_device():
    info = get_current_device_info()
    return jsonify(info)

# 1. Fonction pour scanner le réseau
def scan_network():
    """Scan uniquement rapide du réseau (fast scan)"""
    global network_devices, last_scan_time
    with devices_lock:
        current_time = time.time()
        if current_time - last_scan_time < SCAN_INTERVAL and network_devices:
            return network_devices

        print("Lancement d'un scan rapide du réseau...")
        network = '192.168.1.0/24'

        # Exécuter uniquement le fast scan
        nmap_hosts = fast_nmap_scan(network)

        # Stocker le résultat sous forme de dictionnaire
        network_devices = {host['ip']: host for host in nmap_hosts}
        last_scan_time = current_time
        return network_devices
  

def check_device(ip):
    """Vérifie si un appareil est actif et récupère ses infos de base"""
    try:
        response = ping(str(ip), timeout=1)
        if response is not None and response is not False:
            try:
                hostname = socket.gethostbyaddr(str(ip))[0]
            except socket.herror:
                hostname = "Inconnu"
            
            return {
                'ip': ip,
                'hostname': hostname,
                'status': 'online',
                'last_seen': time.time()
            }
    except Exception as e:
        print(f"Erreur lors du check de {ip}: {e}")
    
    return None


@app.route('/api/devices')
def get_devices():
    try:
        if 'user_id' not in session:
            return jsonify({'status': 'error', 'message': 'Non autorisé'}), 401

        user_id = session['user_id']
        cursor = conn.cursor(dictionary=True)

        # 1. D'abord scanner le réseau pour détecter les appareils en ligne
        scanned_devices = scan_network()
        online_ips = [ip for ip in scanned_devices.keys()]

        # 2. Mettre à jour les appareils en ligne avec NOW()
        if online_ips:
            placeholders = ','.join(['%s'] * len(online_ips))
            cursor.execute(f"""
                UPDATE devices 
                SET lastSeen = NOW(), status = 'online'
                WHERE user_id = %s 
                AND deviceIP IN ({placeholders})
            """, [user_id] + online_ips)
            conn.commit()

        # 3. Mettre à jour le statut des appareils hors ligne
        cursor.execute("""
            UPDATE devices 
            SET status = 'offline'
            WHERE user_id = %s 
            AND status = 'online'
            AND deviceIP NOT IN ({placeholders})
        """.format(placeholders=','.join(['%s']*len(online_ips)) if online_ips else """
            UPDATE devices 
            SET status = 'offline'
            WHERE user_id = %s 
            AND status = 'online'
        """), [user_id] + online_ips if online_ips else [user_id])
        conn.commit()

        # Le reste de votre fonction reste inchangé...
        # 4. Appareils autorisés
        cursor.execute("""
            SELECT deviceIP, deviceMAC, deviceName 
            FROM devices 
            WHERE user_id = %s AND deviceAuthorization = 'authorized'
        """, (user_id,))
        authorized_devices = {
            (row['deviceMAC'], row['deviceIP']): row['deviceName']
            for row in cursor.fetchall()
        }

        # 5. Appareils connus
        cursor.execute("""
            SELECT deviceMAC, deviceIP 
            FROM devices 
            WHERE user_id = %s
        """, (user_id,))
        known_devices = set((row['deviceMAC'], row['deviceIP']) for row in cursor.fetchall())

        # 6. Tous les appareils BDD
        cursor.execute("""
            SELECT deviceIP, deviceMAC, deviceName, deviceAuthorization, lastSeen, status 
            FROM devices 
            WHERE user_id = %s
        """, (user_id,))
        db_devices = cursor.fetchall()
        db_device_map = {
            (row['deviceMAC'], row['deviceIP']): row
            for row in db_devices
        }

        all_devices = []

        # 7. Appareils de la base
        for device_key, db_device in db_device_map.items():
            mac, ip = device_key
            scanned = scanned_devices.get(ip)  # None si non scanné
            is_my_device = ip == get_current_device_info().get('ip')

            device_data = {
                'ip': ip,
                'hostname': scanned.get('hostname') if scanned else db_device.get('deviceName', 'Inconnu'),
                'status': 'online' if scanned else 'offline',
                'os': scanned.get('os', 'Inconnu') if scanned else 'Inconnu',
                'os_accuracy': scanned.get('os_accuracy', 0) if scanned else 0,
                'mac': mac,
                'vendor': scanned.get('vendor', 'Inconnu') if scanned else 'Inconnu',
                'device_type': scanned.get('device_type', 'Inconnu') if scanned else 'Inconnu',
                'last_seen': db_device.get('lastSeen').strftime("%d/%m/%Y %H:%M:%S") if db_device.get('lastSeen') else 'Jamais',
                'open_ports': len(scanned.get('ports', [])) if scanned else 0,
                'ports_details': scanned.get('ports', []) if scanned else [],
                'extra_info': scanned.get('extra_info', {}) if scanned else {},
                'authorization': db_device.get('deviceAuthorization', 'unauthorized'),
                'authorized_name': db_device.get('deviceName') if db_device.get('deviceAuthorization') == 'authorized' else None,
                'my_device': is_my_device
            }

            all_devices.append(device_data)

        # 8. Appareils scannés non enregistrés
        for ip, device in scanned_devices.items():
            mac = device.get('mac', '').upper()
            if not mac:
                continue

            device_key = (mac, ip)
            if device_key in db_device_map:
                continue  # déjà traité

            # Insertion BDD
            try:
                cursor.execute("""
                    INSERT INTO devices (deviceIP, deviceMAC, deviceName, deviceVendor, deviceAuthorization, user_id, lastSeen, status)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
                """, (
                    ip,
                    mac,
                    device.get('hostname', ip),
                    device.get('vendor', 'Inconnu'),
                    'unauthorized',
                    user_id,
                    'online'
                ))
                conn.commit()
                known_devices.add(device_key)
            except Exception as insert_error:
                print(f"Erreur insertion {ip}: {insert_error}")

            is_authorized = device_key in authorized_devices
            authorization_status = 'authorized' if is_authorized else 'unauthorized'
            is_my_device = ip == get_current_device_info().get('ip')

            all_devices.append({
                'ip': ip,
                'hostname': device.get('hostname', 'Inconnu'),
                'status': 'online',
                'os': device.get('os', 'Inconnu'),
                'os_accuracy': device.get('os_accuracy', 0),
                'mac': mac,
                'vendor': device.get('vendor', 'Inconnu'),
                'device_type': device.get('device_type', 'Inconnu'),
                'last_seen': datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                'open_ports': len(device.get('ports', [])),
                'ports_details': device.get('ports', []),
                'extra_info': device.get('extra_info', {}),
                'authorization': authorization_status,
                'authorized_name': authorized_devices.get(device_key) if is_authorized else None,
                'my_device': is_my_device
            })

        cursor.close()

        # 9. Statistiques
        device_counter = Counter(d['device_type'] for d in all_devices)
        auth_counter = Counter(d['authorization'] for d in all_devices)

        return jsonify({
            'devices': all_devices,
            'stats': {
                'total': len(all_devices),
                'online': sum(1 for d in all_devices if d.get('status') == 'online'),
                'authorized': auth_counter.get('authorized', 0),
                'unauthorized': auth_counter.get('unauthorized', 0),
                'alerts': [
                    device['ip'] for device in all_devices
                    if device['authorization'] == 'unauthorized'
                ],
                'device_types': device_counter,
                'auth_stats': {
                    'authorized_devices': [
                        {'ip': d['ip'], 'name': d['authorized_name']} 
                        for d in all_devices 
                        if d['authorization'] == 'authorized'
                    ],
                    'unauthorized_devices': [
                        {'ip': d['ip'], 'hostname': d['hostname']} 
                        for d in all_devices 
                        if d['authorization'] == 'unauthorized'
                    ]
                }
            }
        })

    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
# Détail sur un appareil
@app.route('/devices/<ip>', methods=['GET', 'POST'])
def device_details(ip):
    if 'user_id' not in session:
        flash('Veuillez vous connecter pour accéder à cette page.', 'warning')
        return redirect(url_for('login'))
    
    # Récupérer les détails de l'appareil
    device = None
    devices = scan_network()
    if ip in devices:
        device = devices[ip]
        # Si on a seulement les infos basiques, on complète avec un scan détaillé
        if 'os' not in device:
            device.update(get_device_details(ip, device_base=device))
    
    if not device:
        flash('Appareil non trouvé.', 'danger')
        return redirect(url_for('devices'))
    
    return render_template('/dashboard/device_details.html', 
                         device=device,
                         current_page='devices')


@app.route('/api/devices', methods=['POST'])
def create_device():
    data = request.get_json()
    required_fields = ['hostname', 'ip', 'mac', 'vendor', 'device_type', 'authorization']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Veuillez remplir tous les champs'}), 400
    
    try:
        try:
            connection = mysql.connector.connect(
                host=os.getenv("DB_HOST"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                database=os.getenv("DB_NAME")
            )
        except mysql.connector.Error as err:
            print(f"Erreur de connexion à la base de données: {err}")

        if connection:
            cursor = connection.cursor()
            query = """
                INSERT INTO devices (deviceName, deviceIP, deviceMAC, deviceVendor, deviceType, deviceAuthorization, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """
            cursor.execute(query, (
                data['hostname'],
                data['ip'],
                data['mac'],
                data.get('vendor', 'Inconnu'),
                data.get('device_type', 'Inconnu'),
                data['authorization']
            ))
            connection.commit()
            device_id = cursor.lastrowid
            cursor.close()
            connection.close()
            return jsonify({'message': 'Device created', 'id': device_id}), 201
        return jsonify({'error': 'Database connection failed'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<int:device_id>', methods=['PUT'])
def update_device(device_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Aucune données envoyé'}), 400
    
    try:
        try:
            connection = mysql.connector.connect(
                host=os.getenv("DB_HOST"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                database=os.getenv("DB_NAME")
            )
        except mysql.connector.Error as err:
            print(f"Erreur de connexion à la base de données: {err}")
            
        if connection:
            cursor = connection.cursor()
            query = """
                UPDATE devices
                SET deviceName = %s, deviceAuthorization = %s
                WHERE id = %s
            """
            cursor.execute(query, (
                data.get('hostname'),
                data.get('authorization'),
                device_id
            ))
            connection.commit()
            affected_rows = cursor.rowcount
            cursor.close()
            connection.close()
            if affected_rows == 0:
                return jsonify({'error': 'Device not found'}), 404
            return jsonify({'message': 'Device updated'})
        return jsonify({'error': 'Database connection failed'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
def delete_device(device_id):
    try:
        try:
            connection = mysql.connector.connect(
                host=os.getenv("DB_HOST"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                database=os.getenv("DB_NAME")
            )
        except mysql.connector.Error as err:
            print(f"Erreur de connexion à la base de données: {err}")

        if connection:
            cursor = connection.cursor()
            cursor.execute("DELETE FROM devices WHERE id = %s", (device_id,))
            connection.commit()
            affected_rows = cursor.rowcount
            cursor.close()
            connection.close()
            if affected_rows == 0:
                return jsonify({'error': 'Device not found'}), 404
            return jsonify({'message': 'Device deleted'})
        return jsonify({'error': 'Database connection failed'}), 500
    except Error as e:
        return jsonify({'error': str(e)}), 500

#####################################################################
########### Partie Gestion des utilisateurs #########################
#####################################################################


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )
    except mysql.connector.Error as err:
        print(f"Erreur de connexion à la base de données: {err}")
        # Gérer l'erreur (redémarrer ou quitter)
    
    if request.method == 'POST':
        # Récupération des données du formulaire
        firstname = request.form.get('firstName')
        lastname = request.form.get('lastName')
        birth_date = request.form.get('birthDate')
        phone = request.form.get('phone')
        email = request.form.get('email')
        address = request.form.get('address')
        job_title = request.form.get('jobTitle')
        department = request.form.get('department')
        skills = request.form.get('skills')
        bio = request.form.get('bio')

        print("firstname:", firstname)
        print("lastname:", lastname)
        print("email:", email)


        if not firstname or not lastname or not email:
            flash("Les champs prénom, nom et email sont obligatoires", "danger")
            return redirect(url_for('profile', current_page="profile"))

        
        # Gestion du mot de passe si modifié
        current_password = request.form.get('currentPassword')
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')
        
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Vérification et mise à jour du mot de passe si nécessaire
            if current_password and new_password and confirm_password:
                # Récupérer le mot de passe actuel
                cursor.execute("SELECT password FROM users WHERE id = %s", (user_id,))
                user = cursor.fetchone()
                
                if user and bcrypt.checkpw(current_password.encode('utf-8'), user['password'].encode('utf-8')):
                    if new_password == confirm_password:
                        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                        cursor.execute("UPDATE users SET password = %s WHERE id = %s", 
                                     (hashed_password, user_id))
                    else:
                        flash("Les nouveaux mots de passe ne correspondent pas", "danger")
                else:
                    flash("Mot de passe actuel incorrect", "danger")
            
            # Mise à jour des autres informations
            cursor.execute("""
                UPDATE users 
                SET firstname = %s, lastname = %s, birth_date = %s, phone = %s, 
                    email = %s, address = %s, job_title = %s, department = %s, 
                    skills = %s, bio = %s 
                WHERE id = %s
            """, (firstname, lastname, birth_date, phone, email, address, 
                  job_title, department, skills, bio, user_id))
            
            connection.commit()
            flash("Profil mis à jour avec succès", "success")
            
        except Error as e:
            connection.rollback()
            flash(f"Erreur lors de la mise à jour du profil: {e}", "danger")
        finally:
            cursor.close()
            connection.close()
        
        return redirect(url_for('profile'), current_page="profile")
    
    else:
        # Affichage du profil
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()
            
            if user:
                print("User found:", user)
                return render_template('/dashboard/profile.html', 
                                      user_firstname=user['firstname'],
                                      user_lastname=user['lastname'],
                                      user=user, current_page="profile")
            else:
                flash("Utilisateur non trouvé", "danger")
                return redirect(url_for('login'))
                
        except Error as e:
            flash(f"Erreur lors de la récupération du profil: {e}", "danger")
            return redirect(url_for('login'))
        finally:
            cursor.close()
            connection.close()

# Route pour la suppression du compte
@app.route('/profile/delete', methods=['POST'])
def delete_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    try:
        connection = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME")
        )
    except mysql.connector.Error as err:
        print(f"Erreur de connexion à la base de données: {err}")
        # Gérer l'erreur (redémarrer ou quitter)
    
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        connection.commit()
        session.clear()
        flash("Votre compte a été supprimé avec succès", "success")
        return redirect(url_for('login'))
    except Error as e:
        connection.rollback()
        flash(f"Erreur lors de la suppression du compte: {e}", "danger")
        return redirect(url_for('profile'))
    finally:
        cursor.close()
        connection.close()


if __name__ == '__main__':
    app.run(debug=True)