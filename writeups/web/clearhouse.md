# ClearHouse — chaîne GraphQL vers RCE

**Auteur :** Le_Geek

## Reconnaissance

L’API GraphQL expose une lecture d’objets par identifiant sans vérifier que l’objet appartient à la
session courante. Cette IDOR donne accès aux données internes et aux chemins utilisés par le service
de génération de rapports.

## Chaîne d’exploitation

Le champ de chemin accepte une traversée après normalisation incomplète. La lecture d’un fichier de
configuration fournit le jeton attendu par le service interne. Une requête GraphQL peut alors appeler
le générateur de rapport avec ce jeton.

Le générateur utilise une version vulnérable de `js-yaml` et accepte un objet YAML dont la conversion
`toJSON` exécute du JavaScript. Le payload combine l’IDOR, la traversée et cette désérialisation pour
obtenir l’exécution de commandes côté serveur.

## Résultat

La commande exécutée lit le fichier de flag dans le conteneur. Chaque étape est nécessaire : l’IDOR
fournit le contexte, la traversée récupère le secret interne et le parseur YAML transforme le secret
en exécution.
