import hashlib
import os
import time
import random
import string

class AuthenticationSystem:
    def __init__(self):
        self.password_file = "password.txt"
        self.failed_attempts = {}
        self.lock_times = {}
        self.banned_users = set()
        self.load_banned_users()
    
    def load_banned_users(self):
        """Charge les utilisateurs bannis depuis un fichier"""
        try:
            with open("banned_users.txt", "r") as file:
                for line in file:
                    self.banned_users.add(line.strip())
        except FileNotFoundError:
            pass
    
    def save_banned_user(self, username):
        """Sauvegarde l'utilisateur banni dans un fichier"""
        self.banned_users.add(username)
        with open("banned_users.txt", "a") as file:
            file.write(username + "\n")
    
    def ban_user(self, username):
        """Bannit définitivement l'utilisateur"""
        print("🚫 COMPTE BANNI DÉFINITIVEMENT - Trop de tentatives échouées")
        self.save_banned_user(username)
        input("Appuyez sur Entrée pour continuer...")
    
    def clear_screen(self):
        """Nettoie l'écran de la console"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def validate_username(self, username):
        """
        Valide le nom d'utilisateur selon les critères:
        - Exactement 5 caractères
        - Lettres minuscules uniquement
        """
        if len(username) != 5:
            return False, "Le nom d'utilisateur doit contenir exactement 5 caractères"
        
        if not username.isalpha() or not username.islower():
            return False, "Le nom d'utilisateur doit contenir uniquement des lettres minuscules"
        
        return True, "Nom d'utilisateur valide"
    
    def validate_password(self, password):
        """
        Valide le mot de passe selon les critères:
        - Minimum 8 caractères
        - Contient au moins une minuscule, une majuscule et un chiffre
        """
        if len(password) < 8:
            return False, "Le mot de passe doit contenir au moins 8 caractères"
        
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        
        if not (has_lower and has_upper and has_digit):
            return False, "Le mot de passe doit contenir au moins une minuscule, une majuscule et un chiffre"
        
        return True, "Mot de passe valide"
    
    def generate_salt(self):
        """Génère un salt aléatoire de 5 chiffres"""
        return ''.join(random.choices(string.digits, k=5))
    
    def hash_password(self, password, salt):
        """
        Hash le mot de passe avec le salt en utilisant SHA-256
        Format: hash = SHA256(password + salt)
        """
        salted_password = password + salt
        return hashlib.sha256(salted_password.encode()).hexdigest()
    
    def user_exists(self, username):
        """Vérifie si l'utilisateur existe déjà dans le fichier"""
        try:
            with open(self.password_file, 'r') as file:
                for line in file:
                    if line.startswith(username + ":"):
                        return True
            return False
        except FileNotFoundError:
            return False
    
    def is_account_banned(self, username):
        """Vérifie si le compte est banni définitivement"""
        if username in self.banned_users:
            print("🚫 COMPTE BANNI DÉFINITIVEMENT - Accès refusé")
            return True
        return False
    
    def is_account_locked(self, username):
        """Vérifie si le compte est temporairement bloqué"""
        if username in self.lock_times:
            remaining_time = self.lock_times[username] - time.time()
            if remaining_time > 0:
                print(f"🔒 Compte temporairement bloqué. Temps restant: {int(remaining_time)} secondes")
                return True
            else:
                # Débloquer le compte si le temps est écoulé
                del self.lock_times[username]
        return False

    def signup(self):
        """Fonction d'inscription avec possibilité de quitter"""
        print("\n" + "="*50)
        print("INSCRIPTION (tapez 'exit' pour quitter)")
        print("="*50)
        
        # Nom d'utilisateur
        while True:
            username = input("Nom d'utilisateur (5 lettres minuscules): ").strip()
            if username.lower() == 'exit':
                print("🚪 Retour au menu principal...")
                return
            
            is_valid, message = self.validate_username(username)
            
            if not is_valid:
                print(f"❌ Erreur: {message}")
                continue
            
            if self.user_exists(username):
                print("❌ Erreur: Ce nom d'utilisateur existe déjà")
                continue
            
            break
        
        # Mot de passe
        while True:
            password = input("Mot de passe (min 8 caractères, avec majuscule, minuscule, chiffre): ").strip()
            if password.lower() == 'exit':
                print("🚪 Retour au menu principal...")
                return
            
            is_valid, message = self.validate_password(password)
            
            if not is_valid:
                print(f"❌ Erreur: {message}")
                continue
            
            break
        
        # Génération du salt et hashage
        salt = self.generate_salt()
        hashed_password = self.hash_password(password, salt)
        
        # Sauvegarde dans le fichier
        with open(self.password_file, 'a') as file:
            file.write(f"{username}:{salt}:{hashed_password}\n")
        
        print("✅ Compte créé avec succès!")
        print(f"📝 Salt généré: {salt}")
        print(f"🔒 Hash stocké: {hashed_password}")
        input("Appuyez sur Entrée pour continuer...")

    def signin(self):
        """Fonction de connexion avec possibilité de quitter et continuation après blocage"""
        print("\n" + "="*50)
        print("CONNEXION (tapez 'exit' pour quitter)")
        print("="*50)
        
        while True:
            # Nom d'utilisateur
            username = input("Nom d'utilisateur: ").strip()
            if username.lower() == 'exit':
                print("🚪 Retour au menu principal...")
                return
            
            # Vérification du format du nom d'utilisateur
            is_valid, message = self.validate_username(username)
            if not is_valid:
                print(f"❌ {message}")
                continue
            
            # Vérification si le compte est banni
            if self.is_account_banned(username):
                input("Appuyez sur Entrée pour continuer...")
                return
            
            # Vérification si le compte est bloqué temporairement
            if self.is_account_locked(username):
                input("Appuyez sur Entrée pour continuer...")
                continue  # Continue la boucle pour réessayer après déblocage
            
            # Vérification si l'utilisateur existe
            user_data = None
            try:
                with open(self.password_file, 'r') as file:
                    for line in file:
                        parts = line.strip().split(':')
                        if len(parts) == 3 and parts[0] == username:
                            user_data = {
                                'username': parts[0],
                                'salt': parts[1],
                                'hash': parts[2]
                            }
                            break
            except FileNotFoundError:
                print("❌ Aucun utilisateur enregistré")
                input("Appuyez sur Entrée pour continuer...")
                return
            
            if not user_data:
                print("❌ Utilisateur non trouvé")
                continue  # Continue pour réessayer avec un autre username
            
            # Gestion des tentatives de mot de passe
            while True:
                password = input("Mot de passe : ").strip()
                
                if password.lower() == 'exit':
                    print("🔄 Changement d'utilisateur...")
                    break  # Sort de la boucle mot de passe pour changer d'username
                
                # Calcul du hash pour vérification
                calculated_hash = self.hash_password(password, user_data['salt'])
                
                if calculated_hash == user_data['hash']:
                    # Connexion réussie
                    print("✅ Connexion réussie!")
                    self.failed_attempts[username] = 0  # Réinitialiser les tentatives échouées
                    input("Appuyez sur Entrée pour continuer...")
                    return
                else:
                    # Mot de passe incorrect
                    self.failed_attempts[username] = self.failed_attempts.get(username, 0) + 1
                    failed_count = self.failed_attempts[username]
                    
                    print(f"❌ Mot de passe incorrect.")
                    
                    # Déterminer la durée de blocage selon le nombre total d'échecs
                    if failed_count == 3:  # 3ème erreur
                        lock_duration = 5
                    elif failed_count == 5:  # 4ème erreur
                        lock_duration = 10
                    elif failed_count == 6:  # 5ème erreur
                        lock_duration = 15
                    elif failed_count >= 7:  # 6ème erreur et plus
                        lock_duration = 20
                        print("🔒 Compte bloqué pendant 20 secondes...")
                        self.lock_times[username] = time.time() + lock_duration
                        # Attente du déblocage
                        for i in range(lock_duration, 0, -1):
                            print(f"Temps restant: {i} secondes", end='\r')
                            time.sleep(1)
                        print("\n🚫 COMPTE BANNI DÉFINITIVEMENT - Trop de tentatives échouées")
                        self.ban_user(username)
                        return
                    
                    if failed_count >= 3:  # Blocage à partir de la 3ème erreur
                        print(f"🔒 Compte bloqué pendant {lock_duration} secondes...")
                        self.lock_times[username] = time.time() + lock_duration
                        
                        # Attente du déblocage
                        for i in range(lock_duration, 0, -1):
                            print(f"Temps restant: {i} secondes", end='\r')
                            time.sleep(1)
                        print("\nCompte débloqué! Vous pouvez réessayer.")
                    
                    # Continue automatiquement après déblocage avec le même username
                    continue

    def display_menu(self):
        """Affiche le menu principal"""
        self.clear_screen()
        print("🔐 SYSTÈME D'AUTHENTIFICATION SÉCURISÉ")
        print("="*40)
        print("1. S'inscrire (Sign Up)")
        print("2. Se connecter (Sign In)")
        print("3. Quitter (Exit)")
        print("="*40)
    
    def run(self):
        """Boucle principale du programme"""
        while True:
            self.display_menu()
            choice = input("Choisissez une option (1-3) ou 'exit' pour quitter: ").strip().lower()
            
            if choice == 'exit':
                print("👋 Au revoir!")
                break
                
            if choice == '1':
                self.signup()
            elif choice == '2':
                self.signin()
            elif choice == '3':
                print("👋 Au revoir!")
                break
            else:
                print("❌ Option invalide. Veuillez choisir 1, 2, 3 ou 'exit'.")
                input("Appuyez sur Entrée pour continuer...")

# Fonction de démonstration du système
def demonstrate_system():
    print("Bienvenue dans le système d'authentification sécurisé!")
    
    input("\nAppuyez sur Entrée pour lancer le système...")

# Point d'entrée principal
if __name__ == "__main__":
    demonstrate_system()
    
    # Lancement du système d'authentification
    auth_system = AuthenticationSystem()
    auth_system.run()