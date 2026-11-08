# WireVault — course sur le crédit

**Auteur :** Le_Geek  
**Résultat :** accès au produit protégé et flag récupéré.

## Analyse

L’endpoint d’administration révèle parfois un code lorsqu’il répond depuis le cache. La validation
du code et sa consommation sont deux opérations séparées. Le limiteur de requêtes, lui, normalise
différemment certaines variantes de chemin.

## Exploitation

Je crée un compte ordinaire, attends une réponse `HIT`, puis envoie le même code sur des requêtes
concurrentes dont les chemins diffèrent uniquement par leur casse. Plusieurs requêtes franchissent
la vérification avant que le solde ne soit débité.

Le solde obtenu permet d’acheter le produit premium. La réponse de l’achat contient le flag.

## Correctif

La vérification et la consommation doivent être atomiques, le code doit être lié à l’utilisateur et
le limiteur doit travailler sur une route canonique après normalisation unique.
