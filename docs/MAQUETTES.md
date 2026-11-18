# Maquettes textuelles

Ces maquettes précèdent l'implémentation et fixent la hiérarchie de l'information.

## Tableau de bord

```text
┌──────────────┬────────────────────────────────────────────────────────┐
│ Dissimulation│ Exposition réseau                     [Analyser ↻]     │
│              │ Dernière analyse : aujourd'hui 14:32                  │
│ Tableau bord ├────────────┬────────────┬────────────┬─────────────────┤
│ Ports        │ 12 écoutes │ 3 exposés │ 9 locaux  │ UFW actif       │
│ Services     └────────────┴────────────┴────────────┴─────────────────┘
│ Interfaces   ┌────────────────────────────────────────────────────────┐
│ Pare-feu     │ ! Deux services écoutent sur toutes les interfaces   │
│ Profils      └────────────────────────────────────────────────────────┘
│ Historique   Analyse rapide                                            │
│ Paramètres   • Ping IPv4 : répond    • Ping IPv6 : répond             │
│              • Wi-Fi : MAC stable   • Docker : 1 publication          │
└──────────────┴────────────────────────────────────────────────────────┘
```

## Ports et panneau de détails

```text
┌──────────────┬────────────────────────────────────────────────────────┐
│ navigation   │ Ports en écoute  [recherche] [TCP/UDP] [exposition]   │
│              ├─────┬───────────────┬──────────┬─────────────┬────────┤
│              │ TCP │ 0.0.0.0:3000  │ node     │ toutes      │ exposé │
│              │ TCP │ 127.0.0.1:631 │ cupsd    │ local       │ local  │
│              └─────┴───────────────┴──────────┴─────────────┴────────┘
│              ┌────────────────────────────────────────────────────────┐
│              │ Port 3000 · node                                     │
│              │ Écoute sur toutes les interfaces IPv4. Cela augmente │
│              │ l'exposition potentielle, sans indiquer que le       │
│              │ processus est malveillant.                           │
│              │ PID · utilisateur · commande · unité · conteneur     │
│              └────────────────────────────────────────────────────────┘
└──────────────┴────────────────────────────────────────────────────────┘
```

## Réglage avec privilèges

```text
État actuel       Réponse au ping IPv4 : activée
Explication       Les requêtes Echo peuvent recevoir une réponse.
Impact            Désactiver Echo ne bloque pas tout ICMP et ne rend pas invisible.
Aperçu             /proc/sys/net/ipv4/icmp_echo_ignore_all : 0 → 1
Avertissement      Le diagnostic réseau sera moins pratique.
                  [Annuler] [Confirmer avec Polkit]
Retour arrière     [Restaurer la valeur précédente]
```

Cette confirmation est active pour les actions systemd autorisées,
NetworkManager, UFW, ICMPv4 et les profils. Ubuntu affiche une demande Polkit ;
le composant privilégié se termine aussitôt l'opération achevée.

Les écrans supplémentaires présentent les sessions TCP/UDP, une capture TShark
courte et des filtres UFW structurés.
La page Trafic contient aussi deux graphiques (chronologie heure/jour et
classement par application), un sélecteur 24 h/7 j/30 j et la liste des
applications connectées. Chaque ligne propose **Couper Internet** ou **Rétablir**
avec confirmation de la portée cgroup et demande Polkit ponctuelle.

## Icône et menu d'arrière-plan

```text
● Dissimulation
  Ouvrir le tableau de bord
  Actualiser l'analyse réseau
  ─────────────────────────────
  Dissimulation — 2 ports potentiellement exposés
  Ports potentiellement exposés : 2
  Pare-feu UFW : actif
  MAC pseudonymisée : 1/1 interface
  ─────────────────────────────
  Activer un profil de sécurité…
  Paramètres
  ─────────────────────────────
  Quitter complètement
```

La couleur de `●` devient verte, orange, rouge ou grise selon les données
observées. La formulation reste factuelle et n'emploie jamais « sécurisé » ou
« invisible ».
