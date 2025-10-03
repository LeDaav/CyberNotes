
# 🛠️ Gobuster – Directory, File & DNS Brute Forcing Tool

**Gobuster v3.6**  
🔗 [Site officiel](https://github.com/OJ/gobuster)

---

## 📌 Syntaxe de base

```bash
gobuster [mode] -u <URL> -w <wordlist> [options]

---

## 🎯 Modes principaux

- **dir** : Brute force de répertoires/fichiers sur un serveur web
- **dns** : Brute force de sous-domaines DNS
- **vhost** : Brute force de virtual hosts HTTP
- **s3** : Brute force de buckets Amazon S3
- **fuzz** : Fuzzing générique (remplacement de FUZZ dans l’URL)

---

## 🌐 Exemple de base

```bash
bash

gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

_Scan de répertoires/fichiers sur un site web_

---

## ⚙️ Options générales

- `-u <URL>` : URL cible (ex: `http://site.com/`)
- `-w <wordlist>` : Fichier de wordlist à utiliser
- `-t <threads>` : Nombre de threads (par défaut: 10)
- `-o <output.txt>` : Fichier de sortie
- `-q` : Mode silencieux (quiet)
- `-e` : Affiche les extensions trouvées
- `-k` : Ignore la vérification du certificat SSL
- `-s <codes>` : Affiche uniquement les codes HTTP spécifiés (ex: `200,204,301,302,307,401,403`)
- `-x <ext>` : Extensions à tester (ex: `php,txt,html`)
- `-l` : Suit les redirections
- `-a <agent>` : User-Agent personnalisé
- `--timeout <sec>` : Timeout de requête (en secondes)

---

## 📁 Mode Directory/File (`dir`)

- `-u <URL>` : Cible (ex: `http://site.com/`)
- `-w <wordlist>` : Wordlist à utiliser
- `-x <ext>` : Extensions à tester (ex: `php,txt,html`)
- `-s <codes>` : Codes HTTP à afficher (ex: `200,204,301,302,307,401,403`)
- `--wildcard` : Détection de wildcard (pages personnalisées pour 404)
- `-b` : Ignore les réponses de taille identique

### Exemple

```bash
bash

gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html -s 200,204,301,302,307,403
```

---

## 🌍 Mode DNS (`dns`)

- `-d <domain>` : Domaine cible (ex: `example.com`)
- `-w <wordlist>` : Wordlist de sous-domaines
- `-t <threads>` : Threads
- `-o <output.txt>` : Fichier de sortie
- `-i` : Ignore les adresses IP non résolues

### Exemple

```bash
bash

gobuster dns -d example.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt
```

---

## 🏠 Mode VHOST (`vhost`)

- `-u <URL>` : URL cible
- `-w <wordlist>` : Wordlist de virtual hosts
- `-t <threads>` : Threads

### Exemple

```bash
bash

gobuster vhost -u http://target.com -w /usr/share/wordlists/vhosts.txt
```

---

## 🧪 Mode Fuzz (`fuzz`)

- Remplacez `FUZZ` dans l’URL par les mots de la wordlist

### Exemple

```bash
bash

gobuster fuzz -u http://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

---

## 🧾 Options de sortie

- `-o <output.txt>` : Sauvegarder les résultats dans un fichier
- `-q` : Mode silencieux
- `-z` : Désactive la barre de progression

---

## 📦 Exemples étendus

### 🔍 Enumération de répertoires

```bash
bash

gobuster dir -u http://site.com/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 50
```

_Recherche de répertoires/fichiers avec extensions et 50 threads_

### 🌐 Enumération de sous-domaines

```bash
bash

gobuster dns -d example.com -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt -t 20
```

_Recherche de sous-domaines avec 20 threads_

### 🏠 Enumération de virtual hosts

```bash
bash

gobuster vhost -u http://site.com -w /usr/share/wordlists/vhosts.txt -t 30
```

_Recherche de virtual hosts avec 30 threads_

### 🧪 Fuzzing générique

```bash
bash

gobuster fuzz -u http://site.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```