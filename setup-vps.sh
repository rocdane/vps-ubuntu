#!/bin/bash

# =============================================
# Script de configuration de serveur VPS Ubuntu 24.04
# Contrôleur DNS (Bind9) + Stack Email Complète (Postfix/Dovecot)
# Sécurité renforcée (UFW, Fail2Ban, DNSSEC, TLS)
# 
# Auteur: rocdane
# Date: $(date +%Y-%m-%d)
# Version: 1.0
# =============================================

# Couleurs pour la journalisation
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration personnalisable
# =============================
DOMAIN="example.com"               # Votre domaine principal
EMAIL="admin@example.com"          # Email de l'administrateur
IP_PUBLIC=""                       # Laisser vide pour auto-détection
MX_PRIORITY=10                     # Priorité MX
DKIM_SELECTOR="mail"               # Sélecteur DKIM

# Sous-domaines importants
MAIL_SUBDOMAIN="mail.${DOMAIN}"    # Sous-domaine pour les services mail
NS1_SUBDOMAIN="ns1.${DOMAIN}"      # Premier serveur DNS
NS2_SUBDOMAIN="ns2.${DOMAIN}"      # Second serveur DNS (modifier si applicable)

# Paramètres supplémentaires
TIMEZONE="Europe/Paris"            # Fuseau horaire
ADMIN_USER="admin"                 # Utilisateur admin (existant ou à créer)
SSH_PORT=22                        # Port SSH (modifier si nécessaire)

# Initialisation
# ===============
LOG_FILE="/var/log/vps_setup_$(date +%Y%m%d_%H%M%S).log"
START_TIME=$(date +%s)

# Fonctions utilitaires
# =====================

# Journalisation avec date et couleur
log() {
    local level=$1
    local message=$2
    local color=$NC
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case $level in
        "SUCCESS") color=$GREEN ;;
        "ERROR") color=$RED ;;
        "WARNING") color=$YELLOW ;;
        "INFO") color=$BLUE ;;
    esac
    
    echo -e "${color}[${timestamp}] [${level}] ${message}${NC}"
    echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
}

# Vérifie si une commande a réussi
check_success() {
    if [ $? -eq 0 ]; then
        log "SUCCESS" "$1"
    else
        log "ERROR" "$2"
        exit 1
    fi
}

# Vérifie si un paquet est installé
is_package_installed() {
    dpkg -l | grep -q "^ii  $1 "
    return $?
}

# Installation sécurisée des paquets
install_package() {
    local pkg=$1
    if ! is_package_installed "$pkg"; then
        log "INFO" "Installation de $pkg..."
        apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1
        check_success "$pkg installé avec succès." "Échec de l'installation de $pkg."
    else
        log "INFO" "$pkg est déjà installé."
    fi
}

# Configuration de base du système
# ===============================

# Vérifier les privilèges root
if [ "$(id -u)" -ne 0 ]; then
    log "ERROR" "Ce script doit être exécuté en tant que root."
    exit 1
fi

log "INFO" "Début de la configuration du serveur pour le domaine $DOMAIN"

# Mettre à jour le système
log "INFO" "Mise à jour des paquets existants..."
apt-get update >> "$LOG_FILE" 2>&1
apt-get upgrade -y >> "$LOG_FILE" 2>&1
check_success "Mise à jour du système effectuée." "Échec de la mise à jour du système."

# Installer les paquets de base
install_package "software-properties-common"
install_package "apt-transport-https"
install_package "ca-certificates"
install_package "curl"
install_package "gnupg"
install_package "ufw"
install_package "fail2ban"
install_package "haveged"
install_package "unzip"
install_package "git"
install_package "net-tools"

# Configurer le fuseau horaire
timedatectl set-timezone "$TIMEZONE" >> "$LOG_FILE" 2>&1
check_success "Fuseau horaire configuré sur $TIMEZONE." "Échec de la configuration du fuseau horaire."

# Détection automatique de l'IP publique si non spécifiée
if [ -z "$IP_PUBLIC" ]; then
    IP_PUBLIC=$(curl -s http://checkip.amazonaws.com)
    if [ -z "$IP_PUBLIC" ]; then
        IP_PUBLIC=$(hostname -I | awk '{print $1}')
    fi
    log "INFO" "IP publique détectée: $IP_PUBLIC"
fi

# Configuration DNS (Bind9)
# ========================

install_dns_server() {
    log "INFO" "Installation et configuration de Bind9..."
    install_package "bind9"
    install_package "dnsutils"
    install_package "bind9-doc"

    # Configuration de base de Bind9
    local named_conf_options="/etc/bind/named.conf.options"
    local named_conf_local="/etc/bind/named.conf.local"
    
    # Configurer les options de Bind9
    cat > "$named_conf_options" <<EOF
options {
    directory "/var/cache/bind";
    dnssec-validation auto;
    auth-nxdomain no;    # conform to RFC1035
    listen-on-v6 { any; };
    allow-query { any; };
    recursion no;
    allow-transfer { none; };
    version "not disclosed";
};
EOF

    # Créer les zones DNS
    cat > "$named_conf_local" <<EOF
// Zone directe pour $DOMAIN
zone "$DOMAIN" {
    type master;
    file "/etc/bind/db.$DOMAIN";
    allow-transfer { none; };
    allow-update { none; };
};

// Zone inverse (si applicable)
zone "$(echo $IP_PUBLIC | awk -F. '{print $3"."$2"."$1}').in-addr.arpa" {
    type master;
    file "/etc/bind/db.$(echo $IP_PUBLIC | awk -F. '{print $1"."$2"."$3}')";
    allow-transfer { none; };
    allow-update { none; };
};
EOF

    # Créer le fichier de zone directe
    local zone_file="/etc/bind/db.$DOMAIN"
    cat > "$zone_file" <<EOF
\$TTL    86400
@       IN      SOA     $NS1_SUBDOMAIN. $EMAIL. (
                          $(date +%Y%m%d)01 ; Serial
                          3600       ; Refresh
                          1800       ; Retry
                          604800     ; Expire
                          86400 )    ; Minimum TTL

; Enregistrements NS
@       IN      NS      $NS1_SUBDOMAIN.
@       IN      NS      $NS2_SUBDOMAIN.

; Enregistrements A
@       IN      A       $IP_PUBLIC
$NS1_SUBDOMAIN. IN      A       $IP_PUBLIC
$NS2_SUBDOMAIN. IN      A       $IP_PUBLIC
$MAIL_SUBDOMAIN. IN     A       $IP_PUBLIC

; Enregistrements MX
@       IN      MX      $MX_PRIORITY $MAIL_SUBDOMAIN.

; Enregistrements TXT pour SPF, DMARC, etc.
@       IN      TXT     "v=spf1 mx a:$MAIL_SUBDOMAIN -all"
_dmarc  IN      TXT     "v=DMARC1; p=reject; rua=mailto:$EMAIL"
EOF

    # Créer le fichier de zone inverse (si applicable)
    local rev_ip=$(echo $IP_PUBLIC | awk -F. '{print $3"."$2"."$1}')
    local rev_zone_file="/etc/bind/db.$(echo $IP_PUBLIC | awk -F. '{print $1"."$2"."$3}')"
    cat > "$rev_zone_file" <<EOF
\$TTL    86400
@       IN      SOA     $NS1_SUBDOMAIN. $EMAIL. (
                          $(date +%Y%m%d)01 ; Serial
                          3600       ; Refresh
                          1800       ; Retry
                          604800     ; Expire
                          86400 )    ; Minimum TTL

@       IN      NS      $NS1_SUBDOMAIN.
@       IN      NS      $NS2_SUBDOMAIN.

$(echo $IP_PUBLIC | awk -F. '{print $4}')       IN      PTR     $NS1_SUBDOMAIN.
EOF

    # Configurer DNSSEC
    log "INFO" "Configuration de DNSSEC..."
    dnssec-keygen -a ECDSAP256SHA256 -n ZONE "$DOMAIN" >> "$LOG_FILE" 2>&1
    dnssec-keygen -f KSK -a ECDSAP256SHA256 -n ZONE "$DOMAIN" >> "$LOG_FILE" 2>&1
    
    for key in $(ls K$DOMAIN*.key); do
        echo "\$INCLUDE $key" >> "$zone_file"
    done
    
    # Signer la zone
    dnssec-signzone -A -3 $(head -c 1000 /dev/random | sha1sum | cut -b 1-16) -N INCREMENT -o "$DOMAIN" -t "$zone_file" >> "$LOG_FILE" 2>&1
    check_success "Zone DNSSEC signée." "Échec de la signature DNSSEC."

    # Redémarrer Bind9
    systemctl restart bind9 >> "$LOG_FILE" 2>&1
    check_success "Bind9 configuré et démarré." "Échec du démarrage de Bind9."
}

# Configuration de la stack email
# =============================

install_mail_stack() {
    log "INFO" "Installation de la stack email..."
    
    # Installer les paquets nécessaires
    install_package "postfix"
    install_package "dovecot-core"
    install_package "dovecot-imapd"
    install_package "dovecot-pop3d"
    install_package "dovecot-lmtpd"
    install_package "opendkim"
    install_package "opendkim-tools"
    install_package "opendmarc"
    install_package "spamassassin"
    install_package "clamav"
    install_package "clamav-daemon"
    install_package "libclamunrar9"
    install_package "postgrey"

    # Configurer Postfix
    log "INFO" "Configuration de Postfix..."
    postconf -e "myhostname = $MAIL_SUBDOMAIN"
    postconf -e "mydomain = $DOMAIN"
    postconf -e "myorigin = \$mydomain"
    postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"
    postconf -e "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"
    postconf -e "inet_interfaces = all"
    postconf -e "inet_protocols = all"
    postconf -e "smtpd_banner = \$myhostname ESMTP"
    postconf -e "smtpd_tls_cert_file=/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    postconf -e "smtpd_tls_key_file=/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    postconf -e "smtpd_tls_security_level=may"
    postconf -e "smtpd_tls_auth_only=yes"
    postconf -e "smtpd_tls_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
    postconf -e "smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1"
    postconf -e "smtpd_tls_mandatory_ciphers=high"
    postconf -e "smtpd_tls_ciphers=high"
    postconf -e "smtpd_tls_exclude_ciphers=aNULL, LOW, EXP, MEDIUM, ADH, AECDH, MD5, DSS, ECDSA, CAMELLIA128, 3DES, CAMELLIA256, RSA+AES, eNULL"
    postconf -e "smtpd_tls_received_header=yes"
    postconf -e "smtpd_tls_session_cache_timeout=3600s"
    postconf -e "tls_random_source=dev:/dev/urandom"
    postconf -e "smtpd_relay_restrictions=permit_mynetworks permit_sasl_authenticated defer_unauth_destination"
    postconf -e "smtpd_recipient_restrictions=permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_unknown_recipient_domain, reject_unauth_pipelining, reject_invalid_hostname"
    postconf -e "smtpd_sender_restrictions=reject_unknown_sender_domain, reject_sender_login_mismatch"
    postconf -e "smtpd_helo_restrictions=permit_mynetworks, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname"
    postconf -e "smtpd_client_restrictions=permit_mynetworks, reject_rbl_client sbl.spamhaus.org, reject_rbl_client blackholes.easynet.nl"
    postconf -e "smtpd_sasl_type=dovecot"
    postconf -e "smtpd_sasl_path=private/auth"
    postconf -e "smtpd_sasl_auth_enable=yes"
    postconf -e "smtpd_sasl_security_options=noanonymous"
    postconf -e "smtpd_sasl_local_domain=\$myhostname"
    postconf -e "broken_sasl_auth_clients=yes"
    postconf -e "smtpd_helo_required=yes"
    postconf -e "smtpd_delay_reject=yes"
    postconf -e "disable_vrfy_command=yes"
    postconf -e "message_size_limit=52428800"
    postconf -e "mailbox_size_limit=0"
    postconf -e "virtual_alias_maps=hash:/etc/postfix/virtual"
    postconf -e "virtual_mailbox_domains=hash:/etc/postfix/virtual_domains"
    postconf -e "virtual_mailbox_base=/var/mail/vhosts"
    postconf -e "virtual_mailbox_maps=hash:/etc/postfix/virtual_mailboxes"
    postconf -e "virtual_minimum_uid=1000"
    postconf -e "virtual_uid_maps=static:5000"
    postconf -e "virtual_gid_maps=static:5000"
    postconf -e "virtual_transport=lmtp:unix:private/dovecot-lmtp"
    postconf -e "smtpd_milters=inet:127.0.0.1:8891,inet:127.0.0.1:8893"
    postconf -e "non_smtpd_milters=inet:127.0.0.1:8891,inet:127.0.0.1:8893"
    postconf -e "milter_default_action=accept"
    postconf -e "milter_protocol=2"

    # Créer la structure de répertoires pour les mails
    mkdir -p /var/mail/vhosts/"$DOMAIN"
    groupadd -g 5000 vmail
    useradd -g vmail -u 5000 vmail -d /var/mail
    chown -R vmail:vmail /var/mail

    # Configurer les fichiers de virtual domains
    echo "$DOMAIN OK" > /etc/postfix/virtual_domains
    postmap /etc/postfix/virtual_domains

    # Exemple d'alias (à personnaliser)
    echo "postmaster@$DOMAIN $EMAIL" > /etc/postfix/virtual
    echo "abuse@$DOMAIN $EMAIL" >> /etc/postfix/virtual
    postmap /etc/postfix/virtual

    # Configurer OpenDKIM
    log "INFO" "Configuration de OpenDKIM..."
    mkdir -p /etc/opendkim/keys/"$DOMAIN"
    cp /etc/opendkim.conf /etc/opendkim.conf.orig

    cat > /etc/opendkim.conf <<EOF
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  Yes
SyslogSuccess           Yes
LogWhy                  Yes
Canonicalization        relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                  opendkim:opendkim
Socket                  inet:8891@localhost
EOF

    # Configurer les fichiers OpenDKIM
    echo "127.0.0.1" > /etc/opendkim/TrustedHosts
    echo "localhost" >> /etc/opendkim/TrustedHosts
    echo "*@$DOMAIN $DKIM_SELECTOR._domainkey.$DOMAIN" > /etc/opendkim/SigningTable
    echo "$DKIM_SELECTOR._domainkey.$DOMAIN $DOMAIN:$DKIM_SELECTOR:/etc/opendkim/keys/$DOMAIN/$DKIM_SELECTOR.private" > /etc/opendkim/KeyTable

    # Générer les clés DKIM
    opendkim-genkey -b 2048 -d "$DOMAIN" -D /etc/opendkim/keys/"$DOMAIN" -s "$DKIM_SELECTOR" -v
    chown -R opendkim:opendkim /etc/opendkim
    chmod 640 /etc/opendkim/keys/"$DOMAIN"/*.private

    # Configurer OpenDMARC
    log "INFO" "Configuration de OpenDMARC..."
    cat > /etc/opendmarc.conf <<EOF
AuthservID $MAIL_SUBDOMAIN
PidFile /var/run/opendmarc/opendmarc.pid
RejectFailures false
Syslog true
TrustedAuthservIDs $MAIL_SUBDOMAIN
Socket  inet:8893@localhost
UMask 0002
UserID opendmarc:opendmarc
IgnoreHosts /etc/opendmarc/ignore.hosts
HistoryFile /var/run/opendmarc/opendmarc.dat
EOF

    mkdir -p /etc/opendmarc
    echo "127.0.0.1" > /etc/opendmarc/ignore.hosts

    # Configurer Dovecot
    log "INFO" "Configuration de Dovecot..."
    cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.orig

    cat > /etc/dovecot/dovecot.conf <<EOF
listen = *
mail_location = maildir:/var/mail/vhosts/%d/%n
mail_privileged_group = mail
namespace inbox {
  inbox = yes
}
passdb {
  driver = pam
}
protocols = imap pop3 lmtp
service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }
  user = dovecot
}
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    group = postfix
    mode = 0600
    user = postfix
  }
}
service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}
ssl = required
ssl_cert = </etc/letsencrypt/live/$DOMAIN/fullchain.pem
ssl_key = </etc/letsencrypt/live/$DOMAIN/privkey.pem
ssl_prefer_server_ciphers = yes
ssl_protocols = !SSLv2 !SSLv3 !TLSv1 !TLSv1.1
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
protocol lmtp {
  postmaster_address = postmaster@$DOMAIN
}
EOF

    # Configurer SpamAssassin
    log "INFO" "Configuration de SpamAssassin..."
    sed -i 's/^ENABLED=0/ENABLED=1/' /etc/default/spamassassin
    sed -i 's/^CRON=0/CRON=1/' /etc/default/spamassassin

    cat > /etc/spamassassin/local.cf <<EOF
required_score 5.0
report_safe 0
rewrite_header Subject ***SPAM***
use_bayes 1
bayes_auto_learn 1
skip_rbl_checks 0
use_razor2 1
use_dcc 1
use_pyzor 1
EOF

    # Configurer ClamAV
    log "INFO" "Configuration de ClamAV..."
    freshclam >> "$LOG_FILE" 2>&1

    # Configurer Postgrey
    log "INFO" "Configuration de Postgrey..."
    sed -i 's/^POSTGREY_OPTS="--inet=10023"/POSTGREY_OPTS="--inet=127.0.0.1:10023 --delay=60"/' /etc/default/postgrey

    # Redémarrer les services
    systemctl restart postfix dovecot opendkim opendmarc spamassassin clamav-daemon postgrey >> "$LOG_FILE" 2>&1
    check_success "Services mail redémarrés avec succès." "Échec du redémarrage des services mail."
}

# Configuration de la sécurité
# ===========================

configure_security() {
    log "INFO" "Configuration de la sécurité..."

    # Configurer UFW
    log "INFO" "Configuration du pare-feu UFW..."
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    ufw allow ssh >> "$LOG_FILE" 2>&1
    ufw allow 53/tcp >> "$LOG_FILE" 2>&1   # DNS TCP
    ufw allow 53/udp >> "$LOG_FILE" 2>&1   # DNS UDP
    ufw allow 80/tcp >> "$LOG_FILE" 2>&1   # HTTP
    ufw allow 443/tcp >> "$LOG_FILE" 2>&1  # HTTPS
    ufw allow 25/tcp >> "$LOG_FILE" 2>&1   # SMTP
    ufw allow 587/tcp >> "$LOG_FILE" 2>&1  # Submission
    ufw allow 465/tcp >> "$LOG_FILE" 2>&1  # SMTPS
    ufw allow 993/tcp >> "$LOG_FILE" 2>&1  # IMAPS
    ufw allow 995/tcp >> "$LOG_FILE" 2>&1  # POP3S
    ufw --force enable >> "$LOG_FILE" 2>&1
    check_success "Pare-feu UFW configuré." "Échec de la configuration UFW."

    # Configurer Fail2Ban
    log "INFO" "Configuration de Fail2Ban..."
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime = 86400
findtime = 3600
maxretry = 5

[sshd]
enabled = true

[postfix]
enabled = true

[postfix-sasl]
enabled = true

[dovecot]
enabled = true

[recidive]
enabled = true
EOF

    systemctl restart fail2ban >> "$LOG_FILE" 2>&1
    check_success "Fail2Ban configuré." "Échec de la configuration Fail2Ban."

    # Désactiver SSH par root
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    systemctl restart sshd >> "$LOG_FILE" 2>&1
    check_success "SSH sécurisé." "Échec de la sécurisation SSH."

    # Configurer les mises à jour automatiques de sécurité
    log "INFO" "Configuration des mises à jour automatiques..."
    install_package "unattended-upgrades"
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESM:\${distro_codename}";
};
Unattended-Upgrade::Package-Blacklist {
    // Aucun paquet en liste noire
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

    check_success "Mises à jour automatiques configurées." "Échec de la configuration des mises à jour automatiques."
}

# Installation de Certbot pour les certificats SSL
# ==============================================

install_certbot() {
    log "INFO" "Installation de Certbot pour les certificats SSL..."
    
    install_package "snapd"
    snap install core >> "$LOG_FILE" 2>&1
    snap refresh core >> "$LOG_FILE" 2>&1
    snap install --classic certbot >> "$LOG_FILE" 2>&1
    ln -s /snap/bin/certbot /usr/bin/certbot >> "$LOG_FILE" 2>&1

    # Obtenir le certificat
    certbot certonly --standalone --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN" -d "$MAIL_SUBDOMAIN" -d "$NS1_SUBDOMAIN" >> "$LOG_FILE" 2>&1
    check_success "Certificat SSL obtenu pour $DOMAIN." "Échec de l'obtention du certificat SSL."

    # Configurer le renouvellement automatique
    (crontab -l 2>/dev/null; echo "0 0 * * * certbot renew --quiet --post-hook \"systemctl reload postfix dovecot\"") | crontab -
    check_success "Renouvellement automatique configuré." "Échec de la configuration du renouvellement automatique."
}

# Fonction principale
# ===================

main() {
    # Afficher le résumé de la configuration
    log "INFO" "Début de la configuration avec les paramètres suivants:"
    log "INFO" "Domaine: $DOMAIN"
    log "INFO" "Email admin: $EMAIL"
    log "INFO" "IP publique: $IP_PUBLIC"
    log "INFO" "Sous-domaine mail: $MAIL_SUBDOMAIN"
    log "INFO" "Serveur DNS 1: $NS1_SUBDOMAIN"
    log "INFO" "Port SSH: $SSH_PORT"
    log "INFO" "Fuseau horaire: $TIMEZONE"

    # Exécuter les différentes étapes
    install_dns_server
    install_certbot
    install_mail_stack
    configure_security

    # Afficher le résumé final
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    log "SUCCESS" "Configuration terminée avec succès en $((DURATION / 60)) minutes et $((DURATION % 60)) secondes."

    # Afficher les informations importantes
    echo -e "${GREEN}"
    echo "===================================================================="
    echo "Configuration du serveur terminée avec succès!"
    echo "===================================================================="
    echo -e "${NC}"
    echo "Informations importantes:"
    echo ""
    echo "1. DNS:"
    echo "   - Vérifier la configuration DNS:"
    echo "     dig $DOMAIN ANY @$NS1_SUBDOMAIN"
    echo "     dig $MAIL_SUBDOMAIN ANY @$NS1_SUBDOMAIN"
    echo ""
    echo "2. Email:"
    echo "   - Paramètres SMTP:"
    echo "     Serveur: $MAIL_SUBDOMAIN"
    echo "     Port: 587 (STARTTLS) ou 465 (SSL/TLS)"
    echo "     Authentification requise"
    echo "   - Paramètres IMAP:"
    echo "     Serveur: $MAIL_SUBDOMAIN"
    echo "     Port: 993 (SSL/TLS)"
    echo ""
    echo "3. DKIM:"
    echo "   - Ajouter l'enregistrement DKIM suivant à votre zone DNS:"
    cat /etc/opendkim/keys/"$DOMAIN"/"$DKIM_SELECTOR".txt
    echo ""
    echo "4. Sécurité:"
    echo "   - Pare-feu actif (UFW): ufw status"
    echo "   - Fail2Ban: fail2ban-client status"
    echo "   - Certificats SSL: certbot certificates"
    echo ""
    echo "5. Journal complet: $LOG_FILE"
    echo ""
    echo "===================================================================="
    echo -e "${YELLOW}Instructions post-installation:${NC}"
    echo "1. Configurer les enregistrements DNS chez votre registrar"
    echo "2. Tester la délivrabilité des emails (https://www.mail-tester.com)"
    echo "3. Configurer les comptes email dans votre client mail"
    echo "4. Surveiller les journaux pour détecter d'éventuels problèmes"
    echo "===================================================================="
}

# Exécuter la fonction principale
main