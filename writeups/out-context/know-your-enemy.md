# Know Your Enemy — OSINT sur l'empreinte publique de BUG|PWN

- **Catégorie :** out context (OSINT)
- **Flag :** `CTF{REDACTED}` (format `CTF{surname}`)
- **Fichiers fournis :** aucun

## Contexte

> *Before you attack a target, you study it. BUG|PWN has a public footprint
> like any other security team. There's a website, a GitHub organization,
> and a handful of social accounts. Everything you need for this challenge
> is already public. Nothing here needs to be brute forced, guessed, or bought.*
>
> *Someone who has contributed to BUG|PWN's work left their real name
> somewhere in this footprint, even though they go by a handle everywhere
> else. Find their surname.*
>
> Flag format: `CTF{surname}`

## Méthode

1. **Inventaire de l'empreinte publique** : site web de BUG|PWN, organisation GitHub,
   comptes sociaux (Twitter/X, LinkedIn, etc.).
2. **Recherche sur GitHub** : parcourir les dépôts de l'organisation, les commits, les
   fichiers `AUTHORS`, `CONTRIBUTORS`, les profils des contributeurs. Un commit Git porte
   toujours un champ `Author:` avec un nom et un email — si quelqu'un a commité avec son
   vrai nom au lieu de son handle, il apparaît dans l'historique.
3. **Corrélation** : identifier le contributeur qui utilise un pseudonyme partout sauf à un
   endroit précis où son vrai nom (nom de famille) apparaît.
4. Le flag est le nom de famille trouvé, au format `CTF{surname}`.

## Leçons

- Les commits Git sont une source riche d'OSINT : le champ `Author:` n'est pas toujours un
  pseudo, et l'historique d'un dépôt conserve les anciennes valeurs même après modification
  du profil.
- `git log --format='%an <%ae>'` sur un clone permet de lister tous les auteurs distincts.
- Les métadonnées (PDF, images, documents) hébergées sur un site peuvent aussi contenir des
  noms réels.

## Flag

```
CTF{REDACTED}
```

---

*Write-up par **Le_Geek** — BUG|PWN CTF · Know Your Enemy.*
