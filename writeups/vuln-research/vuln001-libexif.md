# VULN#001 — libexif MakerNote

**Auteur :** Le_Geek  
**Catégorie :** vuln research

## Analyse

Le service accepte une image JPEG et transmet ses métadonnées à libexif. La version fournie permet
de relire le code exact, ce qui rend le chemin MakerNote plus intéressant que les parseurs JPEG
généraux. Dans `exif-data.c`, la taille annoncée par une entrée peut être décrémentée avant que la
borne de la section ne soit vérifiée.

Avec une taille de section minimale, la soustraction produit une longueur énorme et le parseur lit
au-delà du buffer alloué. Le résultat est une lecture hors limites contrôlée par le contenu de la
balise, observable dans la réponse du service.

## Reproduction

J’ai construit un JPEG valide contenant une APP1 EXIF, puis une chaîne MakerNote dont la longueur
force le chemin de sous-débordement. Le fichier passe le décodage JPEG mais déclenche la lecture
hors limites dans le parseur MakerNote.

## Conclusion

Le correctif consiste à vérifier la longueur avant toute soustraction et à refuser une section dont
la taille est inférieure à l’en-tête consommé. L’intérêt du challenge vient du fait que l’arbre source
fourni suffit à localiser la faille sans analyse de binaire.
