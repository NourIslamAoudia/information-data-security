#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <windows.h>

// Pour le hashage SHA-256, on utilise OpenSSL ou une implémentation simple
// Ici, on va inclure une implémentation SHA-256 basique
#include <stdint.h>

#define MAX_USERNAME 6
#define MAX_PASSWORD 256
#define MAX_LINE 512
#define SALT_LENGTH 5
#define SHA256_HASH_SIZE 32

// Structure pour stocker les informations utilisateur
typedef struct {
    char username[MAX_USERNAME];
    char salt[SALT_LENGTH + 1];
    char hash[65]; // SHA-256 en hexadécimal = 64 caractères + '\0'
} UserData;

// Structure pour le système d'authentification
typedef struct {
    char password_file[256];
    int failed_attempts[100]; // Tableau pour stocker les tentatives échouées
    char usernames_tracked[100][MAX_USERNAME]; // Noms d'utilisateurs suivis
    time_t lock_times[100]; // Temps de déblocage pour chaque utilisateur
    int tracked_count; // Nombre d'utilisateurs suivis
    char banned_users[100][MAX_USERNAME]; // Liste des utilisateurs bannis
    int banned_count; // Nombre d'utilisateurs bannis
} AuthenticationSystem;

// Prototypes de fonctions
void init_auth_system(AuthenticationSystem *auth);
void load_banned_users(AuthenticationSystem *auth);
void save_banned_user(AuthenticationSystem *auth, const char *username);
void ban_user(AuthenticationSystem *auth, const char *username);
void clear_screen();
int validate_username(const char *username, char *message);
int validate_password(const char *password, char *message);
void generate_salt(char *salt);
void sha256_hash_string(const char *string, char outputBuffer[65]);
void hash_password(const char *password, const char *salt, char *output);
int user_exists(const char *username);
int is_account_banned(AuthenticationSystem *auth, const char *username);
int is_account_locked(AuthenticationSystem *auth, const char *username);
void signup(AuthenticationSystem *auth);
void signin(AuthenticationSystem *auth);
void display_menu();
void run(AuthenticationSystem *auth);
void demonstrate_system();
int get_user_index(AuthenticationSystem *auth, const char *username);
int add_user_tracking(AuthenticationSystem *auth, const char *username);

// Implémentation SHA-256 simplifiée
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    uint32_t i;
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen; ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16; ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32; ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48; ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

void sha256_hash_string(const char *string, char outputBuffer[65]) {
    uint8_t hash[SHA256_HASH_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (uint8_t*)string, strlen(string));
    sha256_final(&ctx, hash);
    for (int i = 0; i < SHA256_HASH_SIZE; i++)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    outputBuffer[64] = 0;
}

void init_auth_system(AuthenticationSystem *auth) {
    strcpy(auth->password_file, "password.txt");
    auth->tracked_count = 0;
    auth->banned_count = 0;
    for (int i = 0; i < 100; i++) {
        auth->failed_attempts[i] = 0;
        auth->lock_times[i] = 0;
        strcpy(auth->usernames_tracked[i], "");
        strcpy(auth->banned_users[i], "");
    }
    load_banned_users(auth);
}

void load_banned_users(AuthenticationSystem *auth) {
    FILE *file = fopen("banned_users.txt", "r");
    if (file == NULL) return;
    
    char line[MAX_USERNAME];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\n")] = 0; // Retirer le \n
        if (strlen(line) > 0 && auth->banned_count < 100) {
            strcpy(auth->banned_users[auth->banned_count], line);
            auth->banned_count++;
        }
    }
    fclose(file);
}

void save_banned_user(AuthenticationSystem *auth, const char *username) {
    if (auth->banned_count < 100) {
        strcpy(auth->banned_users[auth->banned_count], username);
        auth->banned_count++;
    }
    
    FILE *file = fopen("banned_users.txt", "a");
    if (file != NULL) {
        fprintf(file, "%s\n", username);
        fclose(file);
    }
}

void ban_user(AuthenticationSystem *auth, const char *username) {
    printf("\n%c COMPTE BANNI DEFINITIVEMENT - Trop de tentatives echouees\n", 251);
    save_banned_user(auth, username);
    printf("Appuyez sur Entree pour continuer...");
    getchar();
}

void clear_screen() {
    system("cls");
}

int validate_username(const char *username, char *message) {
    int len = strlen(username);
    
    if (len != 5) {
        strcpy(message, "Le nom d'utilisateur doit contenir exactement 5 caracteres");
        return 0;
    }
    
    for (int i = 0; i < len; i++) {
        if (!isalpha(username[i]) || !islower(username[i])) {
            strcpy(message, "Le nom d'utilisateur doit contenir uniquement des lettres minuscules");
            return 0;
        }
    }
    
    strcpy(message, "Nom d'utilisateur valide");
    return 1;
}

int validate_password(const char *password, char *message) {
    int len = strlen(password);
    
    if (len < 8) {
        strcpy(message, "Le mot de passe doit contenir au moins 8 caracteres");
        return 0;
    }
    
    int has_lower = 0, has_upper = 0, has_digit = 0;
    for (int i = 0; i < len; i++) {
        if (islower(password[i])) has_lower = 1;
        if (isupper(password[i])) has_upper = 1;
        if (isdigit(password[i])) has_digit = 1;
    }
    
    if (!has_lower || !has_upper || !has_digit) {
        strcpy(message, "Le mot de passe doit contenir au moins une minuscule, une majuscule et un chiffre");
        return 0;
    }
    
    strcpy(message, "Mot de passe valide");
    return 1;
}

void generate_salt(char *salt) {
    srand(time(NULL));
    for (int i = 0; i < SALT_LENGTH; i++) {
        salt[i] = '0' + (rand() % 10);
    }
    salt[SALT_LENGTH] = '\0';
}

void hash_password(const char *password, const char *salt, char *output) {
    char salted_password[MAX_PASSWORD + SALT_LENGTH + 1];
    sprintf(salted_password, "%s%s", password, salt);
    sha256_hash_string(salted_password, output);
}

int user_exists(const char *username) {
    FILE *file = fopen("password.txt", "r");
    if (file == NULL) return 0;
    
    char line[MAX_LINE];
    char file_username[MAX_USERNAME];
    
    while (fgets(line, sizeof(line), file) != NULL) {
        sscanf(line, "%[^:]", file_username);
        if (strcmp(file_username, username) == 0) {
            fclose(file);
            return 1;
        }
    }
    
    fclose(file);
    return 0;
}

int is_account_banned(AuthenticationSystem *auth, const char *username) {
    for (int i = 0; i < auth->banned_count; i++) {
        if (strcmp(auth->banned_users[i], username) == 0) {
            printf("\n%c COMPTE BANNI DEFINITIVEMENT - Acces refuse\n", 251);
            return 1;
        }
    }
    return 0;
}

int get_user_index(AuthenticationSystem *auth, const char *username) {
    for (int i = 0; i < auth->tracked_count; i++) {
        if (strcmp(auth->usernames_tracked[i], username) == 0) {
            return i;
        }
    }
    return -1;
}

int add_user_tracking(AuthenticationSystem *auth, const char *username) {
    if (auth->tracked_count < 100) {
        strcpy(auth->usernames_tracked[auth->tracked_count], username);
        auth->failed_attempts[auth->tracked_count] = 0;
        auth->lock_times[auth->tracked_count] = 0;
        return auth->tracked_count++;
    }
    return -1;
}

int is_account_locked(AuthenticationSystem *auth, const char *username) {
    int index = get_user_index(auth, username);
    if (index == -1) return 0;
    
    time_t current_time = time(NULL);
    if (auth->lock_times[index] > current_time) {
        int remaining_time = (int)(auth->lock_times[index] - current_time);
        printf("\n%c Compte temporairement bloque. Temps restant: %d secondes\n", 254, remaining_time);
        return 1;
    } else if (auth->lock_times[index] > 0) {
        auth->lock_times[index] = 0;
    }
    
    return 0;
}

void signup(AuthenticationSystem *auth) {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char message[256];
    char salt[SALT_LENGTH + 1];
    char hashed_password[65];
    
    printf("\n");
    for (int i = 0; i < 50; i++) printf("=");
    printf("\nINSCRIPTION (tapez 'exit' pour quitter)\n");
    for (int i = 0; i < 50; i++) printf("=");
    printf("\n");
    
    // Nom d'utilisateur
    while (1) {
        printf("Nom d'utilisateur (5 lettres minuscules): ");
        scanf("%s", username);
        getchar(); // Consommer le \n
        
        if (strcmp(username, "exit") == 0) {
            printf("\n%c Retour au menu principal...\n", 238);
            return;
        }
        
        if (!validate_username(username, message)) {
            printf("\n%c Erreur: %s\n", 251, message);
            continue;
        }
        
        if (user_exists(username)) {
            printf("\n%c Erreur: Ce nom d'utilisateur existe deja\n", 251);
            continue;
        }
        
        break;
    }
    
    // Mot de passe
    while (1) {
        printf("Mot de passe (min 8 caracteres, avec majuscule, minuscule, chiffre): ");
        scanf("%s", password);
        getchar(); // Consommer le \n
        
        if (strcmp(password, "exit") == 0) {
            printf("\n%c Retour au menu principal...\n", 238);
            return;
        }
        
        if (!validate_password(password, message)) {
            printf("\n%c Erreur: %s\n", 251, message);
            continue;
        }
        
        break;
    }
    
    // Génération du salt et hashage
    generate_salt(salt);
    hash_password(password, salt, hashed_password);
    
    // Sauvegarde dans le fichier
    FILE *file = fopen(auth->password_file, "a");
    if (file != NULL) {
        fprintf(file, "%s:%s:%s\n", username, salt, hashed_password);
        fclose(file);
        
        printf("\n%c Compte cree avec succes!\n", 251);
        printf("%c Salt genere: %s\n", 237, salt);
        printf("%c Hash stocke: %s\n", 254, hashed_password);
        printf("Appuyez sur Entree pour continuer...");
        getchar();
    }
}

void signin(AuthenticationSystem *auth) {
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char message[256];
    UserData user_data;
    int user_found;
    
    printf("\n");
    for (int i = 0; i < 50; i++) printf("=");
    printf("\nCONNEXION (tapez 'exit' pour quitter)\n");
    for (int i = 0; i < 50; i++) printf("=");
    printf("\n");
    
    while (1) {
        // Nom d'utilisateur
        printf("Nom d'utilisateur: ");
        scanf("%s", username);
        getchar(); // Consommer le \n
        
        if (strcmp(username, "exit") == 0) {
            printf("\n%c Retour au menu principal...\n", 238);
            return;
        }
        
        // Vérification du format du nom d'utilisateur
        if (!validate_username(username, message)) {
            printf("\n%c %s\n", 251, message);
            continue;
        }
        
        // Vérification si le compte est banni
        if (is_account_banned(auth, username)) {
            printf("Appuyez sur Entree pour continuer...");
            getchar();
            return;
        }
        
        // Vérification si le compte est bloqué temporairement
        if (is_account_locked(auth, username)) {
            printf("Appuyez sur Entree pour continuer...");
            getchar();
            continue;
        }
        
        // Vérification si l'utilisateur existe
        user_found = 0;
        FILE *file = fopen(auth->password_file, "r");
        if (file == NULL) {
            printf("\n%c Aucun utilisateur enregistre\n", 251);
            printf("Appuyez sur Entree pour continuer...");
            getchar();
            return;
        }
        
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), file) != NULL) {
            char temp_username[MAX_USERNAME];
            char temp_salt[SALT_LENGTH + 1];
            char temp_hash[65];
            
            if (sscanf(line, "%[^:]:%[^:]:%s", temp_username, temp_salt, temp_hash) == 3) {
                if (strcmp(temp_username, username) == 0) {
                    strcpy(user_data.username, temp_username);
                    strcpy(user_data.salt, temp_salt);
                    strcpy(user_data.hash, temp_hash);
                    user_found = 1;
                    break;
                }
            }
        }
        fclose(file);
        
        if (!user_found) {
            printf("\n%c Utilisateur non trouve\n", 251);
            continue;
        }
        
        // Obtenir ou créer l'index de suivi pour cet utilisateur
        int user_index = get_user_index(auth, username);
        if (user_index == -1) {
            user_index = add_user_tracking(auth, username);
        }
        
        // Gestion des tentatives de mot de passe
        while (1) {
            printf("Mot de passe : ");
            scanf("%s", password);
            getchar(); // Consommer le \n
            
            if (strcmp(password, "exit") == 0) {
                printf("\n%c Changement d'utilisateur...\n", 254);
                break;
            }
            
            // Calcul du hash pour vérification
            char calculated_hash[65];
            hash_password(password, user_data.salt, calculated_hash);
            
            if (strcmp(calculated_hash, user_data.hash) == 0) {
                // Connexion réussie
                printf("\n%c Connexion reussie!\n", 251);
                auth->failed_attempts[user_index] = 0;
                printf("Appuyez sur Entree pour continuer...");
                getchar();
                return;
            } else {
                // Mot de passe incorrect
                auth->failed_attempts[user_index]++;
                int failed_count = auth->failed_attempts[user_index];
                
                printf("\n%c Mot de passe incorrect.\n", 251);
                
                int lock_duration = 0;
                if (failed_count == 3) {
                    lock_duration = 5;
                } else if (failed_count == 5) {
                    lock_duration = 10;
                } else if (failed_count == 6) {
                    lock_duration = 15;
                } else if (failed_count >= 7) {
                    lock_duration = 20;
                    printf("%c Compte bloque pendant 20 secondes...\n", 254);
                    auth->lock_times[user_index] = time(NULL) + lock_duration;
                    
                    // Attente du déblocage
                    for (int i = lock_duration; i > 0; i--) {
                        printf("Temps restant: %d secondes\r", i);
                        Sleep(1000);
                    }
                    printf("\n\n%c COMPTE BANNI DEFINITIVEMENT - Trop de tentatives echouees\n", 251);
                    ban_user(auth, username);
                    return;
                }
                
                if (failed_count >= 3) {
                    printf("%c Compte bloque pendant %d secondes...\n", 254, lock_duration);
                    auth->lock_times[user_index] = time(NULL) + lock_duration;
                    
                    // Attente du déblocage
                    for (int i = lock_duration; i > 0; i--) {
                        printf("Temps restant: %d secondes\r", i);
                        Sleep(1000);
                    }
                    printf("\nCompte debloque! Vous pouvez reessayer.\n");
                }
                
                continue;
            }
        }
    }
}

void display_menu() {
    clear_screen();
    printf("%c SYSTEME D'AUTHENTIFICATION SECURISE\n", 254);
    for (int i = 0; i < 40; i++) printf("=");
    printf("\n1. S'inscrire (Sign Up)\n");
    printf("2. Se connecter (Sign In)\n");
    printf("3. Quitter (Exit)\n");
    for (int i = 0; i < 40; i++) printf("=");
    printf("\n");
}

void run(AuthenticationSystem *auth) {
    char choice[10];
    
    while (1) {
        display_menu();
        printf("Choisissez une option (1-3) ou 'exit' pour quitter: ");
        scanf("%s", choice);
        getchar(); // Consommer le \n
        
        if (strcmp(choice, "exit") == 0) {
            printf("\n%c Au revoir!\n", 238);
            break;
        }
        
        if (strcmp(choice, "1") == 0) {
            signup(auth);
        } else if (strcmp(choice, "2") == 0) {
            signin(auth);
        } else if (strcmp(choice, "3") == 0) {
            printf("\n%c Au revoir!\n", 238);
            break;
        } else {
            printf("\n%c Option invalide. Veuillez choisir 1, 2, 3 ou 'exit'.\n", 251);
            printf("Appuyez sur Entree pour continuer...");
            getchar();
        }
    }
}

void demonstrate_system() {
    printf("Bienvenue dans le systeme d'authentification securise!\n");
    printf("\nAppuyez sur Entree pour lancer le systeme...");
    getchar();
}

int main() {
    demonstrate_system();
    
    AuthenticationSystem auth;
    init_auth_system(&auth);
    run(&auth);
    
    return 0;
}
