# Déploiement sécurisé

## Préparer un nouveau serveur

Les exemples ci-dessous supposent Debian ou Ubuntu, Apache/PHP, un site servi dans `/var/www/html` et le compte PHP `www-data`. Adapter le nom du compte et les chemins si le serveur utilise une autre configuration.

### 1. Installer les composants nécessaires

```sh
sudo apt update
sudo apt install apache2 php libapache2-mod-php php-sqlite3 sqlite3
php -m | grep -i '^pdo_sqlite$'
```

La dernière commande doit afficher `pdo_sqlite`. Déployer ensuite les fichiers du site dans `/var/www/html` avec un compte de déploiement, sans copier de fichiers de développement ou de sauvegarde dans le dossier public.

### 2. Créer l’espace privé et la configuration

La base et sa configuration doivent se trouver dans `/var/www/private`, à côté de `html`, et non dans un dossier servi par le web. Créer le dossier avec des droits limités :

```sh
sudo install -d -o www-data -g www-data -m 0700 /var/www/private
```

Le processus PHP doit pouvoir écrire dans ce dossier, pas seulement dans le fichier `.sqlite` : SQLite y crée aussi ses fichiers temporaires de journalisation.

Créer un nouveau mot de passe administrateur unique et fort. Générer son hash sans afficher le mot de passe saisi :

```sh
read -rsp 'Nouveau mot de passe administrateur : ' ADMIN_PASSWORD
printf '\n'
export ADMIN_PASSWORD
php -r 'echo password_hash(getenv("ADMIN_PASSWORD"), PASSWORD_DEFAULT), PHP_EOL;'
unset ADMIN_PASSWORD
```

Enregistrer le hash produit dans `/var/www/private/questionnaire.php` (pas le mot de passe en clair) :

```sh
sudoedit /var/www/private/questionnaire.php
```

Y placer le contenu suivant en remplaçant le texte entre apostrophes par le hash généré :

```php
<?php
return [
    'admin_password_hash' => 'COLLER_ICI_LE_HASH_PRODUIT',
];
```

Protéger ce fichier :

```sh
sudo chown root:www-data /var/www/private/questionnaire.php
sudo chmod 0640 /var/www/private/questionnaire.php
```

### 3. Créer une base vide ou restaurer les réponses

**Pour une nouvelle installation sans anciennes réponses**, l’API crée automatiquement `questionnaires.sqlite` et son schéma à sa première requête, dès lors que la configuration privée existe et que PHP peut écrire dans `/var/www/private`. Aucun fichier SQL séparé n’est nécessaire. Après le premier appel au site, contrôler la présence de la base et appliquer les droits :

```sh
sudo chown www-data:www-data /var/www/private/questionnaires.sqlite
sudo chmod 0600 /var/www/private/questionnaires.sqlite
```

**Pour conserver les réponses de l’ancien serveur**, sauvegarder la base depuis celui-ci avec SQLite (cela produit une copie cohérente même si le site est en service), puis transférer cette copie par SSH :

```sh
sudo -u www-data sh -c \
  'umask 077; sqlite3 /var/www/private/questionnaires.sqlite ".backup /tmp/questionnaires.sqlite"'
sudo chown UTILISATEUR:UTILISATEUR /tmp/questionnaires.sqlite
chmod 0600 /tmp/questionnaires.sqlite
sqlite3 /tmp/questionnaires.sqlite 'PRAGMA integrity_check;'
ssh UTILISATEUR@NOUVEAU_SERVEUR \
  'sudo install -d -o UTILISATEUR -g UTILISATEUR -m 0700 /var/tmp/questionnaire-transfer'
scp /tmp/questionnaires.sqlite \
  UTILISATEUR@NOUVEAU_SERVEUR:/var/tmp/questionnaire-transfer/questionnaires.sqlite
```

Remplacer `UTILISATEUR` par un compte de transfert autorisé sur les deux machines. Le contrôle doit répondre `ok`. Sur le nouveau serveur, installer la base privée :

```sh
sudo install -o www-data -g www-data -m 0600 \
  /var/tmp/questionnaire-transfer/questionnaires.sqlite \
  /var/www/private/questionnaires.sqlite
sudo -u www-data sqlite3 /var/www/private/questionnaires.sqlite \
  'PRAGMA integrity_check;'
sudo -u www-data sqlite3 /var/www/private/questionnaires.sqlite \
  'SELECT count(*) FROM responses;'
```

Le contrôle d’intégrité doit répondre `ok`; noter le nombre de réponses et le comparer à celui obtenu sur l’ancien serveur avec la même commande `SELECT count(*) FROM responses;`. L’API complète au besoin les colonnes et index attendus. Après vérification sur le nouveau serveur, supprimer les copies temporaires des deux serveurs et conserver une sauvegarde protégée. Ne transférez pas les réponses par courriel ni par un lien de téléchargement public.

Si les anciennes réponses ne sont pas nécessaires, ne transférez pas l’ancienne base : laissez l’API créer une base vide.

### 4. Vérifier la mise en service

1. Configurer le nom de domaine et HTTPS (par exemple avec Certbot/Let’s Encrypt). Rediriger HTTP vers HTTPS.
2. Vérifier que le site et l’API répondent, que la connexion administrateur fonctionne et que les réponses sont consultables.
3. Vérifier que `/var/www/private` n’est pas accessible depuis le navigateur : la base SQLite et `questionnaire.php` ne doivent jamais être servis par Apache.
4. Si une base a été restaurée, comparer le nombre de réponses avant/après, puis refaire `PRAGMA integrity_check;`.
5. Tester une sauvegarde et sa restauration avant d’effacer ou de mettre hors ligne l’ancien serveur.

## Configuration privée

L’API cherche `questionnaire.php` dans le dossier `private` placé à côté du document root, jamais sous `html`. Sur cette installation, le chemin est `/var/www/private/`. Le fichier doit retourner un tableau avec uniquement `admin_password_hash`, généré comme indiqué à l’étape 2 ci-dessus.

Le code admin historique ayant déjà été présent dans le fichier public, il doit être changé avant toute ouverture réelle du service.

## Droits des fichiers

Le code du site doit être en lecture seule pour le processus PHP; seul `/var/www/private` est inscriptible par `www-data`. Sur cette installation, appliquer `0755` aux dossiers publics et `0644` aux fichiers publics après chaque déploiement. Ne placez aucune sauvegarde, configuration, export ou donnée privée dans `/var/www/html`.

Le compte qui exécute PHP (souvent `www-data` sous Apache) doit pouvoir écrire dans `private/` et dans SQLite. Avec les commandes ci-dessus, le dossier est détenu par `www-data` en mode `0700`, la configuration par `root:www-data` en mode `0640` et la base par `www-data` en mode `0600`. L’API applique également le mode `0600` à la base et active les réglages SQLite de suppression sécurisée, de schéma de confiance désactivé, de synchronisation complète et d’attente en cas de verrou. Adapter le compte au processus PHP réellement utilisé.

La première requête API déplace automatiquement une ancienne base `html/data/questionnaires.sqlite` vers `private/questionnaires.sqlite`, si le serveur a les droits nécessaires sur les deux dossiers. Vérifier que `/data/questionnaires.sqlite` répond ensuite en 404 et que le nombre d’enregistrements est conservé.

L’API exige PHP avec PDO SQLite. L’accès administrateur est une session HTTPOnly; le site doit être servi en HTTPS en production.

## Protection Apache de ce serveur

Le virtual host de ce serveur utilise `/etc/apache2/conf-available/zz-questionnaire-security.conf` : indexation des dossiers désactivée, fichiers cachés et documents de déploiement/sauvegardes refusés, réduction de la bannière serveur, et en-têtes de sécurité. Après toute modification de configuration Apache, valider avec `sudo apachectl configtest`, puis recharger avec `sudo systemctl reload apache2`. Garder le webroot non inscriptible par `www-data`.

L’API accepte uniquement GET/POST et JSON, contrôle l’origine des requêtes navigateur, limite les requêtes à 64 Kio et bloque les tentatives de connexion administrateur excessives par adresse source. HTTP reste activé pour les essais techniques sans données réelles. En HTTP, mots de passe et réponses peuvent être interceptés ou modifiés sur le réseau : n’utiliser que des données fictives et un accès de test; activer HTTPS avant toute collecte réelle ou utilisation d’un vrai code administrateur.

Tailwind CSS est servi localement depuis `vendor/tailwindcss-3.4.17.js` et SheetJS depuis `vendor/xlsx.full.min.js`. Les polices Google externes ont été retirées au profit des polices système, et les politiques CSP n’autorisent plus ces domaines. Conserver la version Tailwind épinglée et vérifier les licences/comportements de sécurité avant toute mise à jour.

Le questionnaire psychosocial utilise la version 2 de l’échelle d’accord à quatre niveaux. Les réponses antérieures restent en version 1 et gardent leur interprétation initiale; la version est conservée par réponse. Les affirmations positives listées dans `resultat.html` sont inversées pour le score indicatif. Ce recodage est descriptif et ne constitue pas un diagnostic clinique.

## Mesures de sécurité à maintenir

- Garder le système, PHP, Apache et les dépendances à jour. Désactiver les modules et services inutilisés et limiter le pare-feu aux ports nécessaires (généralement SSH, HTTP et HTTPS); limiter aussi SSH aux comptes et clés autorisés.
- Utiliser HTTPS uniquement pour l’administration et la collecte. Ne jamais envoyer de mots de passe, de hash ou de réponses dans les journaux, tickets ou dépôts de code.
- Ne pas rendre `/var/www/private` accessible par HTTP. Conserver le dossier en `0700`, la configuration en `0640` et la base en `0600`, avec un propriétaire limité au compte PHP; ne pas utiliser `0777`.
- SQLite standard ne chiffre pas le contenu de la base. Utiliser un stockage serveur chiffré, chiffrer les sauvegardes hors serveur et limiter strictement leurs accès; les permissions de fichiers ne remplacent pas le chiffrement au repos.
- Utiliser un mot de passe administrateur unique, long et non réutilisé. Régénérer son hash en cas de changement ou de suspicion de divulgation; limiter l’accès administrateur aux personnes qui en ont besoin.
- Sauvegarder régulièrement la base via l’outil SQLite `.backup`, chiffrer les sauvegardes hors serveur, limiter leurs accès et leur durée de conservation, et vérifier périodiquement leur restauration. Une sauvegarde non testée n’est pas une stratégie de restauration.
- Surveiller les mises à jour, les erreurs et les accès administrateur sans enregistrer les données des questionnaires dans les journaux. Prévoir une procédure de réponse en cas de perte ou d’accès non autorisé.
- Avant une collecte réelle, faire valider la base légale, les accès, la durée de conservation et la procédure d’exercice des droits par le responsable de traitement/DPO. Les réponses peuvent révéler des données de santé.

## Données et consentement

La politique décrit les données de santé et les articles RGPD envisagés. En contexte professionnel, un consentement salarié n’est pas automatiquement considéré comme libre. Avant toute collecte réelle, le responsable de traitement/DPO doit confirmer la base légale applicable, le caractère volontaire, la durée exacte de conservation et les informations de contact à publier.
