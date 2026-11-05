# WireVault — Writeup reformulé

- **Challenge :** WireVault
- **Catégorie :** web
- **Statut :** résolu
- **Flag :** `CTF{REDACTED}`

## Chaîne d'exploitation

La résolution repose sur une course conditionnelle autour du cache et de la consommation du crédit.

L'endpoint `/api/admin/status` exposait un indice de cache. Les requêtes anonymes retournaient d'abord `401` avec `X-Cache: MISS`. En sondant périodiquement l'endpoint, une fenêtre `200` avec `X-Cache: HIT` permettait de récupérer temporairement le code de règlement généré pour ops.

Le transfert vérifiait puis enregistrait la consommation du code en deux opérations non atomiques. Un compte ordinaire pouvait donc présenter le même code sur plusieurs connexions synchronisées. Les chemins avec des casses différentes contournaient la clé du limiteur OpenResty, alors qu'Express les routait vers le même handler.

Le PoC local est [wirevault_exploit.py](../wirevault_exploit.py). Il crée un compte, attend le cache-hit, conserve le cookie de session, libère le dernier octet de 60 requêtes simultanément, vérifie le solde et achète `platinum_pass`.

## Validation observée

- Cache-hit obtenu sur l'endpoint admin.
- Course réussie : 39 règlements concurrents.
- Solde observé : 195000 cents.
- Achat de `platinum_pass` accepté et champ `flag` retourné.

Le vrai flag n'est pas conservé dans le dépôt.
