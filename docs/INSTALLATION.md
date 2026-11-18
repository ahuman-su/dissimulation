# Installation et empaquetage

## Installer le paquet prêt à l'emploi

Depuis la racine du projet :

```bash
sudo apt install ./artifacts/Dissimulation_0.7.0_amd64.deb
```

APT installe les dépendances obligatoires, notamment NetworkManager, UFW, nftables et
Polkit. Lancez ensuite **Dissimulation** depuis le menu des applications. Le
premier lancement affiche la fenêtre ; les suivants démarrent en arrière-plan.

TShark est recommandé par le paquet. Docker reste entièrement optionnel et n'est
jamais installé automatiquement : sans TShark, l'analyse par application devient
indisponible ; sans Docker, seules les publications de ports des conteneurs ne sont
pas inventoriées.

### Autoriser la capture sans lancer TShark en root

Ubuntu n'autorise pas automatiquement la capture aux utilisateurs ordinaires.
Après l'installation de TShark :

```bash
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark "$USER"
```

Répondez **Oui** à la capture par les utilisateurs non privilégiés, puis fermez
et rouvrez entièrement la session graphique. Cette configuration donne les
capacités réseau à `dumpcap`, tandis que TShark et Dissimulation restent lancés
comme utilisateur normal.

L'analyse par application est activée par défaut avec un échantillon de quatre
secondes toutes les quinze minutes. Sa fréquence, sa durée et la conservation
des compteurs sont modifiables dans **Paramètres**. Pour la désactiver, coupez
**Trafic par application** ; la vue instantanée des sessions `ss` reste disponible.

Le bouton **Couper Internet** nécessite cgroup v2, nftables et une autorisation
Polkit ponctuelle. Il rejette les flux TCP/UDP IPv4/IPv6 du groupe de processus
courant. La règle n'est pas un service persistant et disparaît au redémarrage ;
HTTPS et QUIC sont couverts car le blocage intervient sous le chiffrement. Les
protocoles bruts comme ICMP ne sont pas couverts.

L'accès au socket Docker est équivalent à un privilège administrateur puissant ;
Dissimulation ne modifie pas les groupes système et ne contrôle aucun conteneur.

## Développement sur Ubuntu

Installez d'abord les dépendances Linux de Tauri 2 (la liste peut varier selon
la version d'Ubuntu) :

```bash
sudo apt update
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

Puis :

```bash
npm install
npm run tauri dev
```

Le collecteur utilise de préférence les outils Ubuntu courants `ss`, `ip`,
`systemctl`, `nmcli`, `ufw`, `nft`, `tshark` et `docker`. Leur absence ne bloque pas le lancement :
les sections concernées deviennent indisponibles.

## GNOME, AppIndicator et Wayland

Le paquet utilise le tray de Tauri 2, adossé à Ayatana AppIndicator sur Ubuntu.
Il fonctionne dans une session GNOME/Wayland sans forcer X11 ; l'emplacement de
l'icône est décidé par le panneau. Sur un GNOME non fourni par Ubuntu, une
extension compatible AppIndicator peut être nécessaire.

Les API tray de Tauri ne remontent actuellement ni les événements de clic ni les
infobulles sous Linux. L'application enregistre tout de même le basculement au
clic pour les plateformes compatibles ; sous Ubuntu/AppIndicator, un clic ouvre
le menu, dont la première action affiche le tableau de bord, et le résumé factuel
reste visible dans le menu.

L'option de lancement automatique est désactivée par défaut. Lorsqu'elle est
activée, elle crée une entrée sous `~/.config/autostart/` avec l'argument
`--hidden`. Elle ne crée ni unité systemd ni service root.

Les demandes Polkit ne concernent que les modifications explicitement
confirmées. Elles ne sont jamais déclenchées par l'autostart, la surveillance ou
la capture TShark. Le coupe-réseau par application
modifie nftables et demande donc une autorisation Polkit ponctuelle.

Si une action affiche un refus Polkit, vérifiez que le paquet `.deb` est installé
(la politique autorise précisément `/usr/bin/dissimulation`) et qu'un agent
d'authentification est actif dans la session graphique. Le code 126 correspond à
une boîte d'autorisation fermée ou annulée ; le code 127 indique que Polkit n'a
pas pu obtenir l'autorisation. Aucun mot de passe n'est transmis à Dissimulation.

## Tests

```bash
cargo test --workspace
npm run check
npm run build
```

## Paquet Debian

Une fois les dépendances natives présentes :

```bash
npm run tauri build -- --bundles deb
```

Le paquet est créé sous `target/release/bundle/deb/`. La configuration Tauri
installe automatiquement l'entrée de menu et les icônes du bundle.
Le paquet installe également la politique Polkit sous
`/usr/share/polkit-1/actions/` ; aucun service root résident n'est créé.

Pour produire le paquet dans un conteneur sans installer les bibliothèques de
développement sur l'hôte :

```bash
docker build --file packaging/Dockerfile.deb --target artifact \
  --output type=local,dest=artifacts .
```

Le résultat est alors copié dans `artifacts/`.
