# PWN#Beta — Vault MIPS o32

**Auteur :** Le_Geek  
**Cible :** TCP/5005  
**Résultat :** shell root obtenu avec une chaîne `execve` MIPS.

## Fuite initiale

Le premier `read` accepte 65 octets dans un buffer de 64 octets. Le dernier octet remplace le NUL
du canary ; `printf("Hello, %s")` continue alors sur la pile et divulgue les trois octets restants
du canary, le frame pointer et une partie du retour.

Le canary est reconstruit avec son octet bas nul. Le frame pointer divulgué permet de calculer
l’adresse du buffer, stable sur le service distant.

## Double payload

Le second `read` ne suffit pas à placer directement toute la chaîne : il faut d’abord détourner
l’épilogue vers une seconde lecture. Le premier message restaure le canary, forge le frame pointer et
renvoie vers le code qui recharge `$gp` puis relance `read` à l’intérieur du buffer.

La seconde lecture recouvre les registres sauvegardés de cette nouvelle frame. À son retour, elle
charge l’adresse d’un gadget qui prépare `$v0`, `$a0`, `$a1`, `$a2` et `$t9` avant un `jalr`.

## Appel système

Le gadget reçoit `SYS_execve`, l’adresse de `/bin/sh`, un tableau argv nul et un environnement nul.
`$t9` pointe vers une instruction `syscall` située dans la partie application, ce qui évite de
dépendre du décalage de la libc statique.

Après `execve`, le socket devient l’entrée/sortie du shell. La commande `cat /flag/flag.txt` fournit
le flag.

## Points à retenir

- l’overflow d’un octet sert uniquement à casser le terminateur du canary ;
- le pivot `$fp` est aussi important que le contrôle de `$ra` ;
- les adresses libc et application n’ont pas le même décalage d’exécution.
