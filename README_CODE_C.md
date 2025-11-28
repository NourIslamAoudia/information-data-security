# 🔐 Documentation du Code C - Système d'Authentification Sécurisé

## 📋 Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Architecture du code](#architecture-du-code)
3. [Structures de données](#structures-de-données)
4. [Fonctions principales](#fonctions-principales)
5. [Implémentation SHA-256](#implémentation-sha-256)
6. [Système de sécurité](#système-de-sécurité)
7. [Flux d'exécution](#flux-dexécution)
8. [Compilation et exécution](#compilation-et-exécution)

---

## 🎯 Vue d'ensemble

Ce programme implémente un **système d'authentification sécurisé** en langage C avec les fonctionnalités suivantes :

- ✅ Inscription avec validation stricte des identifiants
- ✅ Connexion avec hashage SHA-256 + salt
- ✅ Protection contre les attaques par force brute
- ✅ Système de blocage temporaire progressif
- ✅ Bannissement permanent après tentatives excessives
- ✅ Persistance des données dans des fichiers

---

## 🏗️ Architecture du code

Le code est organisé en plusieurs sections :

```
code.c
├── Includes et définitions
├── Structures de données
├── Prototypes de fonctions
├── Implémentation SHA-256 (lignes ~52-160)
├── Fonctions du système d'authentification (lignes ~161-625)
└── Fonction main
```

### 📚 Bibliothèques utilisées

```c
#include <stdio.h>      // Entrées/sorties standard
#include <stdlib.h>     // Fonctions générales (system, malloc, etc.)
#include <string.h>     // Manipulation de chaînes
#include <time.h>       // Gestion du temps (blocages)
#include <ctype.h>      // Tests de caractères (isalpha, islower, etc.)
#include <windows.h>    // Sleep() pour Windows
#include <stdint.h>     // Types entiers de taille fixe pour SHA-256
```

### 🔢 Constantes définies

```c
#define MAX_USERNAME 6          // Taille max nom d'utilisateur (5 + '\0')
#define MAX_PASSWORD 256        // Taille max mot de passe
#define MAX_LINE 512            // Taille max ligne fichier
#define SALT_LENGTH 5           // Longueur du salt (5 chiffres)
#define SHA256_HASH_SIZE 32     // Taille hash SHA-256 en bytes
```

---

## 📊 Structures de données

### Structure `UserData`

Stocke les informations d'un utilisateur :

```c
typedef struct {
    char username[MAX_USERNAME];    // Nom d'utilisateur (5 lettres)
    char salt[SALT_LENGTH + 1];     // Salt aléatoire (5 chiffres)
    char hash[65];                  // Hash SHA-256 en hexadécimal (64 chars + '\0')
} UserData;
```

### Structure `AuthenticationSystem`

Gère l'état du système d'authentification :

```c
typedef struct {
    char password_file[256];              // Nom du fichier des mots de passe
    int failed_attempts[100];             // Compteur d'échecs par utilisateur
    char usernames_tracked[100][MAX_USERNAME];  // Liste des utilisateurs suivis
    time_t lock_times[100];               // Temps de déblocage par utilisateur
    int tracked_count;                    // Nombre d'utilisateurs suivis
    char banned_users[100][MAX_USERNAME]; // Liste des utilisateurs bannis
    int banned_count;                     // Nombre d'utilisateurs bannis
} AuthenticationSystem;
```

---

## 🔧 Fonctions principales

### 1️⃣ **Initialisation**

#### `init_auth_system()`

```c
void init_auth_system(AuthenticationSystem *auth);
```

- Initialise la structure `AuthenticationSystem`
- Définit le fichier de mots de passe : `password.txt`
- Réinitialise tous les compteurs à 0
- Charge les utilisateurs bannis depuis `banned_users.txt`

#### `load_banned_users()`

```c
void load_banned_users(AuthenticationSystem *auth);
```

- Lit le fichier `banned_users.txt`
- Charge tous les noms d'utilisateurs bannis dans la mémoire

---

### 2️⃣ **Validation des données**

#### `validate_username()`

```c
int validate_username(const char *username, char *message);
```

**Règles de validation :**

- ✅ Exactement **5 caractères**
- ✅ Uniquement des **lettres minuscules** (a-z)
- ❌ Pas de chiffres, majuscules ou caractères spéciaux

**Retourne :** `1` si valide, `0` sinon

#### `validate_password()`

```c
int validate_password(const char *password, char *message);
```

**Règles de validation :**

- ✅ Minimum **8 caractères**
- ✅ Au moins **1 lettre minuscule**
- ✅ Au moins **1 lettre majuscule**
- ✅ Au moins **1 chiffre**

**Retourne :** `1` si valide, `0` sinon

---

### 3️⃣ **Cryptographie**

#### `generate_salt()`

```c
void generate_salt(char *salt);
```

- Génère un salt aléatoire de **5 chiffres** (ex: "42857")
- Utilise `rand()` initialisé avec `time(NULL)`

#### `hash_password()`

```c
void hash_password(const char *password, const char *salt, char *output);
```

- Concatène le mot de passe et le salt : `password + salt`
- Calcule le hash SHA-256
- Convertit le résultat en hexadécimal (64 caractères)

**Exemple :**

```
Mot de passe : "Test1234"
Salt : "12345"
Données hashées : "Test123412345"
Hash SHA-256 : "a3f8b9c2d1e4..."  (64 caractères hex)
```

#### `sha256_hash_string()`

```c
void sha256_hash_string(const char *string, char outputBuffer[65]);
```

- Fonction wrapper pour le hashage SHA-256
- Convertit le hash binaire en chaîne hexadécimale

---

### 4️⃣ **Gestion des utilisateurs**

#### `user_exists()`

```c
int user_exists(const char *username);
```

- Vérifie si un utilisateur existe dans `password.txt`
- Parcourt le fichier ligne par ligne
- **Retourne :** `1` si existe, `0` sinon

#### `is_account_banned()`

```c
int is_account_banned(AuthenticationSystem *auth, const char *username);
```

- Vérifie si l'utilisateur est dans la liste des bannis
- Affiche un message d'erreur si banni
- **Retourne :** `1` si banni, `0` sinon

#### `is_account_locked()`

```c
int is_account_locked(AuthenticationSystem *auth, const char *username);
```

- Vérifie si le compte est temporairement bloqué
- Compare l'heure actuelle avec `lock_times[index]`
- Affiche le temps restant avant déblocage
- **Retourne :** `1` si bloqué, `0` si débloqué

---

### 5️⃣ **Inscription (Sign Up)**

#### `signup()`

```c
void signup(AuthenticationSystem *auth);
```

**Processus d'inscription :**

1. **Saisie du nom d'utilisateur**

   - Demande 5 lettres minuscules
   - Validation du format
   - Vérification de l'unicité
   - Option `exit` pour quitter

2. **Saisie du mot de passe**

   - Demande min 8 caractères
   - Validation des critères (majuscule, minuscule, chiffre)
   - Option `exit` pour quitter

3. **Enregistrement**
   - Génération d'un salt aléatoire (5 chiffres)
   - Hashage du mot de passe avec SHA-256
   - Sauvegarde dans `password.txt` au format :
     ```
     username:salt:hash
     ```

**Exemple de ligne dans `password.txt` :**

```
alice:12345:a3f8b9c2d1e4567890abcdef12345678...
```

---

### 6️⃣ **Connexion (Sign In)**

#### `signin()`

```c
void signin(AuthenticationSystem *auth);
```

**Processus de connexion :**

1. **Saisie du nom d'utilisateur**

   - Validation du format
   - Vérification si banni (→ refus définitif)
   - Vérification si bloqué (→ affichage temps restant)
   - Vérification si existe dans `password.txt`

2. **Tentatives de mot de passe** (3 par itération)

   - Hashage du mot de passe saisi avec le salt stocké
   - Comparaison avec le hash enregistré
   - Option `exit` pour changer d'utilisateur

3. **Gestion des échecs** (voir section Système de sécurité)

---

## 🔐 Système de sécurité

### Mécanisme de protection anti-brute force

Le système utilise un **blocage progressif** avec 4 itérations :

| Itération | Tentatives totales | Échecs requis | Durée de blocage | Action finale    |
| --------- | ------------------ | ------------- | ---------------- | ---------------- |
| **1**     | 1-3                | 3             | **5 secondes**   | Continue         |
| **2**     | 4-6                | 6             | **10 secondes**  | Continue         |
| **3**     | 7-9                | 9             | **15 secondes**  | Continue         |
| **4**     | 10-12              | 10+           | **20 secondes**  | **BANNISSEMENT** |

### Détails d'implémentation

```c
int attempt_in_iteration = 0;  // Compteur par itération (0-3)
int failed_count = auth->failed_attempts[user_index];  // Total des échecs

// Après chaque tentative échouée
attempt_in_iteration++;
auth->failed_attempts[user_index]++;

// Si 3 tentatives dans l'itération atteintes
if (attempt_in_iteration >= 3) {
    // Déterminer la durée de blocage selon le total d'échecs
    if (failed_count <= 3)        lock_duration = 5;
    else if (failed_count <= 6)   lock_duration = 10;
    else if (failed_count <= 9)   lock_duration = 15;
    else if (failed_count >= 10) {
        lock_duration = 20;
        // BANNISSEMENT après 20s
    }

    // Blocage avec compte à rebours
    for (int i = lock_duration; i > 0; i--) {
        printf("Temps restant: %d secondes\r", i);
        Sleep(1000);  // Pause 1 seconde
    }

    // Réinitialiser pour la prochaine itération
    attempt_in_iteration = 0;
}
```

### Bannissement permanent

Après 10+ tentatives échouées :

1. Blocage de 20 secondes
2. Message de bannissement
3. Ajout à `banned_users.txt`
4. Impossible de se reconnecter même avec le bon mot de passe

---

## 🔒 Implémentation SHA-256

Le code inclut une **implémentation complète de SHA-256** (environ 110 lignes).

### Structures et constantes

```c
typedef struct {
    uint8_t data[64];           // Buffer de données
    uint32_t datalen;           // Longueur des données
    unsigned long long bitlen;  // Longueur en bits
    uint32_t state[8];          // État interne du hash
} SHA256_CTX;

// 64 constantes K pour SHA-256
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, ...
};
```

### Fonctions SHA-256

#### `sha256_init()`

- Initialise le contexte SHA-256
- Définit les valeurs initiales de l'état

#### `sha256_update()`

- Traite les données par blocs de 512 bits
- Accumule les données dans le buffer

#### `sha256_transform()`

- Applique l'algorithme SHA-256 sur un bloc de 512 bits
- Utilise les opérations : `CH`, `MAJ`, `EP0`, `EP1`, `SIG0`, `SIG1`

#### `sha256_final()`

- Ajoute le padding final
- Finalise le calcul du hash
- Retourne le hash de 256 bits (32 bytes)

### Opérations bit à bit utilisées

```c
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))  // Rotation droite
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))            // Choose
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))  // Majority
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
```

---

## 🎮 Flux d'exécution

### Diagramme de flux principal

```
main()
  ↓
demonstrate_system()  // Message de bienvenue
  ↓
init_auth_system()    // Initialisation
  ↓
run()                 // Boucle principale
  ↓
┌─────────────────────┐
│   Menu principal    │
│  1. S'inscrire      │
│  2. Se connecter    │
│  3. Quitter         │
└─────────────────────┘
       ↓
    Choix ?
     ↙   ↓   ↘
  1     2     3
  ↓     ↓     ↓
signup() signin() exit
```

### Flux d'inscription (signup)

```
1. Saisir nom d'utilisateur
   ├─→ Valider format (5 lettres minuscules)
   ├─→ Vérifier si existe déjà
   └─→ exit ? → retour menu

2. Saisir mot de passe
   ├─→ Valider format (8+ chars, maj, min, chiffre)
   └─→ exit ? → retour menu

3. Générer salt (5 chiffres aléatoires)

4. Hasher mot de passe + salt (SHA-256)

5. Sauvegarder dans password.txt
   Format: "username:salt:hash\n"

6. Afficher confirmation ✅
```

### Flux de connexion (signin)

```
1. Saisir nom d'utilisateur
   ├─→ Valider format
   ├─→ Banni ? → refuser ❌
   ├─→ Bloqué ? → afficher temps → continuer
   ├─→ Existe ? → charger user_data
   └─→ exit ? → retour menu

2. Boucle de tentatives (3 par itération)
   │
   ├─→ Saisir mot de passe
   │   └─→ exit ? → changer utilisateur
   │
   ├─→ Hasher avec salt stocké
   │
   ├─→ Comparer avec hash stocké
   │   ├─→ ✅ Correct ? → Connexion réussie !
   │   └─→ ❌ Incorrect ? → Incrémenter compteurs
   │
   └─→ 3 tentatives échouées ?
       ├─→ Bloquer selon itération (5s/10s/15s/20s)
       ├─→ Compte à rebours avec Sleep()
       ├─→ 10+ tentatives totales ? → BANNIR
       └─→ Réinitialiser compteur itération → continuer
```

---

## ⚙️ Compilation et exécution

### Compilation Windows (avec GCC/MinGW)

```bash
gcc code.c -o auth_system.exe -lws2_32
```

### Compilation Linux/Mac

```bash
# Remplacer windows.h par unistd.h et Sleep() par sleep()
gcc code.c -o auth_system
```

### Exécution

```bash
# Windows
.\auth_system.exe

# Linux/Mac
./auth_system
```

---

## 📁 Fichiers générés

### `password.txt`

Format : `username:salt:hash`

```
alice:12345:a3f8b9c2d1e4567890abcdef1234567890abcdef1234567890abcdef12345678
bobby:67890:f1e2d3c4b5a6978685746352413029181716151413121110090807060504030201
```

### `banned_users.txt`

Un nom d'utilisateur par ligne :

```
alice
bobby
```

---

## 🔍 Points techniques importants

### 1. Gestion de la mémoire

- Utilisation de tableaux statiques (pas de `malloc`)
- Limite : 100 utilisateurs suivis/bannis simultanément

### 2. Sécurité du salt

- Salt unique pour chaque utilisateur
- Généré aléatoirement à l'inscription
- Stocké en clair (nécessaire pour vérifier le mot de passe)

### 3. Stockage des mots de passe

- ❌ **Jamais** en clair
- ✅ Toujours hashés avec SHA-256
- ✅ Avec salt unique par utilisateur

### 4. Protection contre le timing attack

- Non implémenté (comparaison de chaînes simple)
- Pour une meilleure sécurité : utiliser `memcmp()` constant-time

### 5. Portabilité

- `windows.h` et `Sleep()` → Windows uniquement
- Pour Linux/Mac : remplacer par `unistd.h` et `sleep()`
- `system("cls")` → Windows | `system("clear")` → Linux/Mac

---

## 🛡️ Améliorations possibles

1. **Sécurité renforcée**

   - Utiliser `bcrypt` ou `argon2` au lieu de SHA-256
   - Ajouter un délai constant contre timing attacks
   - Chiffrer le fichier `password.txt`

2. **Fonctionnalités supplémentaires**

   - Changement de mot de passe
   - Récupération de compte
   - Authentification à deux facteurs (2FA)
   - Log des connexions

3. **Code**

   - Allocation dynamique pour plus d'utilisateurs
   - Portabilité multi-plateforme
   - Gestion d'erreurs plus robuste
   - Interface graphique

4. **Performance**
   - Hash table pour recherche O(1) au lieu de O(n)
   - Cache des utilisateurs en mémoire
   - Fichiers indexés

---

## 📊 Résumé des fonctions

| Fonction              | Lignes | Rôle                            |
| --------------------- | ------ | ------------------------------- |
| `sha256_*`            | ~110   | Implémentation SHA-256          |
| `init_auth_system()`  | ~15    | Initialisation du système       |
| `validate_username()` | ~20    | Validation nom d'utilisateur    |
| `validate_password()` | ~25    | Validation mot de passe         |
| `generate_salt()`     | ~10    | Génération salt aléatoire       |
| `hash_password()`     | ~5     | Hash mot de passe + salt        |
| `signup()`            | ~80    | Inscription utilisateur         |
| `signin()`            | ~150   | Connexion + gestion blocages    |
| `is_account_locked()` | ~20    | Vérification blocage temporaire |
| `is_account_banned()` | ~15    | Vérification bannissement       |
| `ban_user()`          | ~10    | Bannissement permanent          |

---

## 📝 Exemples d'utilisation

### Exemple 1 : Inscription réussie

```
INSCRIPTION (tapez 'exit' pour quitter)
==================================================
Nom d'utilisateur (5 lettres minuscules): alice
Mot de passe (min 8 caractères, avec majuscule, minuscule, chiffre): Test1234

√ Compte créé avec succès!
ò Salt généré: 42857
þ Hash stocké: a3f8b9c2d1e456789...
```

### Exemple 2 : Connexion avec blocages

```
CONNEXION (tapez 'exit' pour quitter)
==================================================
Nom d'utilisateur: alice
Mot de passe : wrong1
û Mot de passe incorrect.

Mot de passe : wrong2
û Mot de passe incorrect.

Mot de passe : wrong3
û Mot de passe incorrect.
þ Compte bloqué pendant 5 secondes...
Temps restant: 5 secondes
Temps restant: 4 secondes
...
Compte débloqué! Vous pouvez réessayer.
```

---

## 🎓 Conclusion

Ce programme démontre :

- ✅ Gestion sécurisée des mots de passe
- ✅ Implémentation de SHA-256 from scratch
- ✅ Protection contre les attaques par force brute
- ✅ Persistance des données
- ✅ Gestion d'états complexe (blocages, bannissements)

**Idéal pour comprendre** :

- Cryptographie basique
- Gestion de fichiers en C
- Structures de données
- Logique de sécurité

---

_Documentation créée le 28 novembre 2025_
