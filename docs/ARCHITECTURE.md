# Architecture

## Frontière de privilèges

La consultation fonctionne sans privilèges quand Ubuntu le permet. Certaines
informations (PID d'un autre utilisateur, UFW ou Docker) peuvent donc être
indisponibles ; l'interface l'indique au lieu d'élever silencieusement ses droits.

```text
┌────────────────────────────────────────────────────────────┐
│ UI Svelte/TypeScript (jamais root)                         │
│ navigation, filtres, explications, prévisualisations       │
└───────────────────────┬────────────────────────────────────┘
                        │ commandes Tauri typées
┌───────────────────────▼────────────────────────────────────┐
│ Shell Tauri 2                                             │
│ cycle de vie, tray, instance unique, paramètres utilisateur│
└───────────────────────┬────────────────────────────────────┘
                        │ API Rust
┌───────────────────────▼────────────────────────────────────┐
│ dissimulation-core                                       │
│ collecteurs ─ modèles ─ classification ─ adaptateurs      │
└──────────────┬──────────────┬──────────────┬───────────────┘
               │              │              │
          /proc, /sys      ss/ip/tshark     systemctl, nmcli,
                                             ufw, docker

                        │ action confirmée + pkexec
┌────────────────────────────────────────────────────────────┐
│ Mode --privileged-helper, processus root éphémère         │
│ opérations fermées + paramètres validés, puis arrêt       │
└────────────────────────────────────────────────────────────┘
```

## Modules

- `crates/core/src/models.rs` : contrat sérialisable partagé avec l'interface.
- `crates/core/src/exposure.rs` : analyse pure des adresses et niveaux d'exposition.
- `crates/core/src/collectors/` : adaptateurs système, sans shell et sans écriture.
- `src-tauri/src/runtime.rs` : surveillance périodique, transitions et notifications.
- `src-tauri/src/tray.rs` : AppIndicator, menu factuel et icônes d'état.
- `src-tauri/src/settings.rs` : paramètres utilisateur et écriture atomique locale.
- `src-tauri/src/traffic.rs` : sessions `ss`, identité `/proc` et échantillon TShark borné.
- `src-tauri/src/app_traffic.rs` : corrélation paquet/socket, agrégats horaires et rétention locale.
- `src-tauri/src/app_control.rs` : inventaire des cgroups applicatifs et registre des blocages.
- `src-tauri/src/filters.rs` : registre utilisateur des règles UFW possédées.
- `src-tauri/src/privileged.rs` : protocole fermé, validation et helper Polkit.
- `src/lib/` : types TypeScript, accès IPC et composants de présentation.
- `src/lib/ActionPreview.svelte` : contrat visuel commun avant chaque écriture.

Les collecteurs lancent des exécutables avec `std::process::Command` et des
arguments séparés. Il n'y a ni `sh -c`, ni concaténation envoyée à un shell.

## Flux d'analyse

1. inventorier les interfaces dans `/sys/class/net` et avec `ip`/`nmcli` ;
2. analyser `ss -H -lntup` et enrichir les PID via `/proc` ;
3. corréler les ports publiés remontés par Docker ;
4. consulter UFW, ICMP, les unités associées aux sockets et les services réseau installés connus ;
5. produire un instantané immutable et horodaté ;
6. classifier l'exposition sans conclure à la malveillance ni à l'invisibilité.

## Processus et cycle de vie

Le processus Tauri et son indicateur s'exécutent uniquement avec les droits de
l'utilisateur. La fenêtre est créée masquée, sauf au premier lancement. Sa
fermeture la masque ; le thread de surveillance continue avec un intervalle
configurable (15 minutes par défaut). Une demande manuelle lance une analyse sans
créer de second moniteur.

Le même moniteur déclenche, lorsque l'option est active, une capture de quatre
secondes toutes les quinze minutes par défaut. Les métadonnées TCP/UDP sont
corrélées aux tuples de sockets remontés par `ss` avant et après l'échantillon.
Seuls les compteurs paquets/octets par application et tranche horaire sont
enregistrés ; l'attribution est explicitement marquée comme partielle quand un
socket trop bref n'est plus visible.

Le plugin d'instance unique utilise le bus de session sous Linux. Une seconde
invocation est arrêtée et demande à l'instance existante d'afficher sa fenêtre.
L'arrêt complet signale le moniteur, attend sa fin, puis quitte la boucle Tauri ;
les configurations système observées restent intactes.

L'autostart est désactivé par défaut. Son activation crée une entrée XDG au niveau
utilisateur et ajoute `--hidden`, sans service root. Les notifications sont
produites uniquement par une transition entre deux instantanés et sont soumises
à une temporisation par type d'événement.

## Flux d'écriture

Les pages Services, Interfaces, Pare-feu, Filtres et Profils construisent un plan
d'action explicite. Après confirmation, Rust sérialise une variante de l'enum
`SystemAction` et lance le même binaire en mode helper avec `pkexec`. Le helper
revalide toutes les valeurs et n'interprète jamais la liste d'opérations affichée
par l'interface.

La politique Polkit lie ce mode à `/usr/bin/dissimulation` et à l'argument
`--privileged-helper`. `auth_admin` est utilisé sans conservation permanente de
l'autorisation. L'autostart n'appelle jamais cette branche.

Depuis la page Interfaces, la MAC Wi-Fi est enregistrée dans le profil actif et
comme défaut NetworkManager pour les futures connexions ; les autres profils
existants restent intacts. Les profils de sécurité peuvent, eux, appliquer leur
mode à tous les profils Wi-Fi. Une interface active n'est reconnectée qu'après
confirmation. Les filtres utilisent UFW et sont
refusés si le service nftables natif est actif. Une cible DNS est résolue avant
la prévisualisation puis de nouveau dans le backend au moment de l'application ;
les IP obtenues sont enregistrées avec la règle sans prétendre suivre le DNS.

Le quatrième profil retire les fichiers de surcharge appartenant à
Dissimulation, remet les profils Wi-Fi au comportement NetworkManager non défini
et peut réappliquer les presets systemd fournisseur. Sa remise à zéro UFW est
volontairement complète et supprimera aussi toute règle UFW créée hors de
l'application ; l'interface l'indique avant l'autorisation.

Le helper renvoie pendant l'application d'un profil un flux JSONL d'étapes ; le
processus utilisateur le transforme en événements Tauri affichés dans la barre
de progression, sans nouvelle autorisation entre les étapes.

Le coupe-réseau par application suit un flux distinct : le backend revalide le
PID et son heure de démarrage, puis le helper vérifie que le processus appartient
à l'UID appelant fourni par Polkit. Il ajoute dans une table nftables isolée une
exactement chaque niveau nommé du chemin avec `socket cgroupv2`, puis ajoute une
règle TCP/UDP marquée `Dissimulation:app:<id>`. La suppression recherche
le marqueur exact et supprime uniquement son handle. Aucun démon root ne reste
actif et la règle n'est pas rendue persistante au redémarrage.
