# VULN#006 — FreeType BDF

**Auteur :** Le_Geek  
**Catégorie :** vuln research

## Observation

Le service inspecte une police BDF avec FreeType. La piste utile se trouve dans le lecteur BDF, où
des valeurs issues de la table de propriétés sont utilisées pour calculer la taille d’une copie.
Le chemin d’erreur ne vérifie pas que la longueur calculée reste dans la table courante.

## Exploit

Une police minimale suffit : elle déclare une propriété avec une longueur qui dépasse la zone allouée,
mais conserve des en-têtes BDF acceptés par FreeType. Lors du chargement, le service lit alors des
octets après la table et les renvoie dans la sortie de diagnostic.

## Correctif

Les longueurs doivent être validées contre la taille restante de la table avant le calcul de l’adresse
de lecture. La validation doit aussi refuser les additions qui débordent un `size_t`.
