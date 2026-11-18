# Dissimulation

Dissimulation est une application de bureau open source pour Ubuntu qui aide à
comprendre et contrôler l'exposition réseau d'une machine. L'interface reste
avec les droits de l'utilisateur ; les écritures système confirmées utilisent
un helper éphémère autorisé par Polkit.

Le produit ne qualifie jamais une machine d'« invisible ». Une écoute locale,
un pare-feu actif et l'absence de réponse au ping réduisent certains signaux,
mais ne suppriment pas toutes les façons de détecter une machine.

## Démarrage rapide

Prérequis Ubuntu : Rust stable, Node.js 18+, npm et les dépendances système de
[Tauri 2 pour Debian/Ubuntu](https://v2.tauri.app/start/prerequisites/).

```bash
npm install
npm run tauri dev
```

Pour vérifier séparément les deux couches qui ne nécessitent pas WebKitGTK :

```bash
npm run check
npm run build
cargo test -p dissimulation-core
```

## État du MVP

- tableau de bord et alertes explicatives cliquables vers la section concernée ;
- sockets TCP/UDP, processus visibles, unité systemd et exposition estimée ;
- détection des publications Docker lorsque le démon est accessible ;
- interfaces et adresses MAC exposées par le système/NetworkManager ;
- UFW, ICMPv4/ICMPv6 et principaux mécanismes de découverte ;
- filtres, tri et vue détaillée des ports ;
- sessions TCP/UDP actualisées et capture courte de métadonnées et tailles via TShark/dumpcap, contenu chiffré compris ;
- historique local du nombre de paquets par application, avec graphiques par heure/jour et classement ;
- coupe-réseau TCP/UDP par application via nftables et correspondance exacte de son cgroup v2 ;
- filtres de blocage UFW structurés par direction, domaine/IP/CIDR, protocole et port ;
- randomisation MAC NetworkManager persistante pour le profil actif et les futurs réseaux ;
- inventaire systemd dynamique des services réseau installés, avec rôle expliqué et contrôle des unités autorisées ;
- lecture détaillée facultative des règles UFW avec une autorisation Polkit ponctuelle ;
- icône AppIndicator, surveillance en arrière-plan et instance unique sous Ubuntu/Wayland ;
- autostart XDG optionnel et notifications différentielles configurables ;
- barres de progression pour toutes les actions système, analyses, captures et sauvegardes ; étapes détaillées pour les profils ;
- aucune interface root permanente et aucun mot de passe administrateur conservé.

Voir [l'architecture](docs/ARCHITECTURE.md), les [maquettes](docs/MAQUETTES.md),
le [modèle de sécurité](docs/SECURITE.md) et le [guide d'installation](docs/INSTALLATION.md).

## Licence

GPL-3.0-or-later. Voir [LICENSE](LICENSE).
