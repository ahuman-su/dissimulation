# Modèle de sécurité

## Garanties

- L'interface et le processus Tauri ne sont jamais lancés en root.
- Les commandes de consultation restent sans élévation de privilèges par défaut.
  La lecture UFW détaillée peut être relancée volontairement avec une autorisation
  Polkit ponctuelle lorsque les règles sont masquées à l'utilisateur courant.
- L'indicateur, la surveillance et l'autostart ne démarrent aucun service système.
- Les écritures passent par `pkexec` et le mode `--privileged-helper` du binaire,
  qui se termine dès l'action achevée. L'interface ne devient jamais root.
- Le helper n'accepte qu'une enum fermée : MAC Wi-Fi, unités réseau autorisées,
  politique et lecture UFW, Echo IPv4, profils connus, règles de blocage validées et
  contrôle d'un cgroup applicatif appartenant à l'utilisateur Polkit.
- Les processus externes sont lancés directement avec des arguments séparés ;
  aucun texte saisi n'est envoyé à un shell.
- Aucun mot de passe, jeton, corps de paquet ou clé privée n'est journalisé.
- Les arguments de processus ressemblant à des secrets sont masqués avant de quitter le collecteur.
- Les erreurs montrées dans l'interface sont résumées et ne contiennent pas les sorties brutes sensibles.
- Une information inaccessible devient `inconnu`, jamais une affirmation rassurante inventée.
- Les notifications comparent deux instantanés, ne contiennent pas de secret et
  sont désactivables par catégorie avec une temporisation anti-répétition.
- Une règle de blocage exige direction, protocole, domaine/IP/CIDR et port. Un
  domaine est résolu avec le DNS système au moment de la confirmation, puis une
  règle est créée pour chaque IP obtenue. Toutes reçoivent le même commentaire
  `Dissimulation:<id>` et seules les règles portant cet identifiant peuvent être
  supprimées par l'application.
- TShark n'est jamais lancé avec Polkit. L'accès brut reste isolé dans `dumpcap`,
  selon la séparation de privilèges de Wireshark. La capture explicite est bornée
  à quatre secondes, cent paquets et 256 octets ; les échantillons statistiques
  durent de 2 à 15 secondes, au plus 2 000 paquets et 96 octets. Aucun fichier
  pcap n'est créé. Seuls des compteurs paquets/octets agrégés par heure sont
  conservés, au maximum 90 jours. Les tailles complètes indiquées par `frame.len`
  sont comptées même quand la charge utile HTTPS ou QUIC est chiffrée.
- Le coupe-réseau revalide l'UID propriétaire, le PID, son heure de démarrage et
  le cgroup v2 après l'élévation. Il compare chaque composant nommé du chemin
  cgroup avec `socket cgroupv2`, utilise une table nftables dédiée, un
  commentaire possédé par Dissimulation et ne conserve aucune autorisation.

## Limites

Un port en écoute ne prouve ni une compromission ni une accessibilité depuis
Internet. L'exposition finale dépend aussi du routage, du pare-feu, du point
d'accès, d'un VPN, d'un namespace réseau et de règles Docker/nftables.

La commande `ss` masque parfois les processus d'autres utilisateurs. UFW peut
exiger des privilèges pour afficher son état. Docker n'est interrogé que si
l'utilisateur courant peut joindre son démon.

L'accès au socket Docker est généralement équivalent à un accès root. Dissimulation
se limite à observer les publications de ports lorsque Docker est déjà accessible ;
elle ne démarre, n'arrête, ne crée et ne supprime aucun conteneur.

Le contenu HTTPS/QUIC reste chiffré. L'application peut afficher une IP, un port,
un nom DNS, une requête HTTP non chiffrée ou un SNI TLS visible, mais ne promet
pas d'identifier ni de bloquer une requête applicative chiffrée précise.
Un filtre par domaine bloque l'instantané des adresses IP résolues ; il ne suit
pas automatiquement les changements DNS, CDN ou équilibrage de charge et peut
donc englober d'autres domaines partageant les mêmes IP.

L'attribution par application est une estimation par corrélation entre les
paquets et les sockets visibles avant/après une capture courte. Un flux ouvert et
fermé entièrement entre ces deux lectures peut rester « Non attribué ». Le
blocage applicatif couvre TCP et UDP (donc le Web classique et QUIC) du cgroup
courant, mais pas les sockets bruts tels qu'ICMP. Il vise aussi tous les processus
du même cgroup. Les règles sont intentionnellement non persistantes au redémarrage.

Les paramètres sont enregistrés dans le dossier de configuration de l'utilisateur.
Aucun mot de passe administrateur, jeton ou résultat complet d'analyse n'y est
stocké. L'état système appliqué n'est pas annulé lors de la fermeture de
l'application. Une erreur au milieu d'un profil peut laisser les étapes déjà
réussies en place ; le résultat est signalé. Le profil « Réglages Ubuntu » retire
les surcharges créées par Dissimulation. Son option UFW exécute une remise à zéro
complète : elle supprime aussi les règles UFW personnelles, remet les politiques
d'installation puis désactive UFW. Cette opération est annoncée avant confirmation.

Le helper refuse les unités essentielles ou inconnues et le mélange automatique
avec un service nftables natif. Les fichiers système gérés sont écrits
atomiquement dans `/etc/NetworkManager/conf.d/`, `/etc/sysctl.d/` et
`/etc/systemd/resolved.conf.d/`.

Signaler une vulnérabilité en privé aux mainteneurs plutôt que dans un ticket public.
