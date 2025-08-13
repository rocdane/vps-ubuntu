# Guide Technique pour Configurer un VPS Ubuntu 24.04 LTS - DNS & Mail Server

Ce guide fournit des instructions détaillées pour configurer un serveur VPS.

## Table des Matières

1. [Prérequis](#prérequis)
2. [Configuration Initiale](#configuration-initiale)
3. [Fonctionnalités clés](#fonctionnalités-clés)
4. [Script d'Installation](#script-dinstallation-automatisé)

## [Prérequis](prérequis)

- Un VPS fraîchement installé avec Ubuntu 24.04 LTS
- Un nom de domaine configurable
- Accès root au serveur
- Au moins 2GB de RAM recommandés

## [Configuration Initiale](configuration-initale)

Modifiez ces variables au début du script :

```bash
DOMAIN="example.com"               # Votre domaine principal
EMAIL="admin@example.com"          # Email administrateur
IP_PUBLIC=""                       # Laisser vide pour auto-détection
MX_PRIORITY=10                     # Priorité MX (10 par défaut)
DKIM_SELECTOR="mail"               # Sélecteur DKIM
TIMEZONE="Europe/Paris"            # Fuseau horaire
```

## [Fonctionnalités clés](fonctionnalités-clés)

Fonctionnalités clés

### DNS (Bind9) :

- Configuration automatique des zones directe et inverse
- DNSSEC intégré
- Gestion des enregistrements MX, SPF, DMARC

### Stack Email Complète :

- Postfix avec TLS obligatoire
- Dovecot pour IMAP/POP3 sécurisé
- OpenDKIM/OpenDMARC pour l'authentification
- SpamAssassin + ClamAV intégrés

### Sécurité :

- Certificats Let's Encrypt automatiques
- Pare-feu UFW préconfiguré
- Fail2Ban pour protection des services
- Configuration TLS sécurisée (1.2/1.3 uniquement)

### Autres caractéristiques :

- Journalisation détaillée avec couleurs
- Vérifications des dépendances
- Idempotence (peut être relancé sans erreur)
- Résumé final détaillé

## [Script d'installation](script-dinstallation-automatisé)

Ce script automatise la configuration complète d'un serveur VPS Ubuntu 24.04 LTS avec :

- Un serveur DNS (Bind9) avec DNSSEC
- Une stack email complète (Postfix + Dovecot)
- Des mesures de sécurité avancées (UFW, Fail2Ban, TLS)
- Des certificats SSL Let's Encrypt

## Support

![Bash](https://img.shields.io/badge/Bash-5.2-blue)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-orange)
![License](https://img.shields.io/badge/License-MIT-green)
