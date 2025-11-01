# Analyse de Sécurité - Code Malveillant MySpace (Samy Worm)

## 📋 Vue d'ensemble

Ce document analyse un code JavaScript malveillant historique connu sous le nom de **"Samy Worm"**, l'un des premiers vers XSS (Cross-Site Scripting) qui s'est propagé sur MySpace en 2005.

---

## 🚨 Vulnérabilités Identifiées

### 1. **Cross-Site Scripting (XSS)**

**Sévérité : CRITIQUE** 🔴

#### Description

Le code exploite une vulnérabilité XSS pour injecter du code JavaScript malveillant dans les profils MySpace.

#### Technique utilisée

```javascript
<div id=mycode style="BACKGROUND: url()">
<script>eval(document.all.mycode.expr);</script>
```

- Utilisation de la balise `<div>` avec un attribut `style` pour contourner les filtres
- Injection de code via `eval()` qui exécute du code dynamique
- Exploitation de `document.all` pour accéder aux éléments DOM

#### Impact

- Exécution de code arbitraire dans le navigateur de la victime
- Vol de sessions utilisateur
- Propagation automatique du ver

---

### 2. **Injection de Code via eval()**

**Sévérité : CRITIQUE** 🔴

#### Description

Utilisation extensive de `eval()` pour exécuter du code dynamiquement construit.

#### Exemples dans le code

```javascript
eval('var x=new ActiveXObject(\'Microsoft.XMLHTTP\')');
eval('l.xmlHttp2.onr'+eadyStatechange=...);
```

#### Dangers

- Permet l'exécution de code arbitraire
- Contourne les mécanismes de sécurité
- Rend le code difficile à analyser statiquement
- Ouvre la porte à l'injection de code malveillant

---

### 3. **Obfuscation de Code**

**Sévérité : ÉLEVÉE** 🟠

#### Techniques d'obfuscation utilisées

##### a) Construction dynamique de chaînes

```javascript
var R = String.fromCharCode(34); // Guillemet double (")
var A = String.fromCharCode(39); // Apostrophe (')
```

##### b) Concaténation complexe

```javascript
eval('l.xmlHttp2.onr'+eadyStatechange=...);
```

##### c) Syntaxe intentionnellement cassée

- Code JavaScript invalide pour tromper les analyseurs
- Utilisation de syntaxe ambiguë pour échapper aux filtres

#### Impact

- Difficile à détecter par les outils de sécurité
- Contourne les filtres basés sur des signatures
- Complique l'analyse forensique

---

### 4. **Requêtes AJAX Non Sécurisées**

**Sévérité : ÉLEVÉE** 🟠

#### Description

Utilisation de XMLHttpRequest pour effectuer des requêtes HTTP en arrière-plan sans validation appropriée.

#### Code concerné

```javascript
var X=XMLHttpRequest();
httpSend(BH,BI,BJ,BK){
    var x=new ActiveXObject('Microsoft.XMLHTTP');
    x.setRequestHeader('Content-Type','application/x-www-form-urlencoded');
    x.send(BH);
}
```

#### Actions malveillantes

- Modification du profil utilisateur (`profile.processInterests`)
- Ajout automatique d'amis (`invite.addFriend.process`)
- Envoi de données sans consentement

---

### 5. **Manipulation du DOM**

**Sévérité : MOYENNE** 🟡

#### Techniques utilisées

```javascript
document.body.createTextRange();
document.body.inner += "HTML";
document.location = "http://www.myspace.com" + location.pathName;
```

#### Risques

- Modification non autorisée du contenu de la page
- Redirection automatique des utilisateurs
- Injection de contenu malveillant dans le DOM

---

### 6. **Vol de Tokens et Données Sensibles**

**Sévérité : CRITIQUE** 🔴

#### Méthode d'extraction

```javascript
function getFromURL(BF,BG){
    if(BG=='Mytoken'){
        T=B[else]{T='&var U=BG+'&';
        var V=BF.indexOf(U)+U.length;
        var W=BF.substring(V,v.1024)
    }
}
```

#### Données ciblées

- `Mytoken` : Token d'authentification MySpace
- `friend1` : ID de l'utilisateur
- `hashcode` : Code de validation pour les actions

#### Impact

- Usurpation d'identité
- Actions non autorisées au nom de l'utilisateur
- Propagation automatique du ver

---

### 7. **Auto-Propagation (Worm Behavior)**

**Sévérité : CRITIQUE** 🔴

#### Mécanisme de propagation

1. **Infection initiale** : Le code s'injecte dans le profil de la victime
2. **Extraction de données** : Récupération du token d'authentification
3. **Modification du profil** : Ajout du message "but most of all, samy is my hero"
4. **Ajout d'ami automatique** : Ajout de l'utilisateur "Samy" (ID: 8581639)
5. **Propagation** : Quand un utilisateur visite le profil infecté, il est infecté à son tour

```javascript
AS['friendID']=l.as(l.8581639)  // ID de Samy
AS['submit']='Add to friends';
```

---

## 🛡️ Techniques de Survie Utilisées

### 1. **Contournement de Filtres**

- Utilisation de `String.fromCharCode()` pour construire des caractères spéciaux
- Syntaxe JavaScript invalide pour tromper les parseurs
- Encodage et obfuscation multiples

### 2. **Persistance**

- Modification permanente du profil utilisateur
- Injection dans la section "Heroes" du profil

### 3. **Propagation Virale**

- Ajout automatique comme ami
- Infection de tous les visiteurs du profil

---

## 📊 Techniques de Propagation Détaillées

### Flux d'exécution

```
1. Utilisateur visite un profil infecté
   ↓
2. Code JavaScript malveillant s'exécute
   ↓
3. Extraction du token d'authentification
   ↓
4. Modification du profil de la victime
   ↓
5. Ajout de "Samy" comme ami
   ↓
6. Profil infecté → Prochain visiteur infecté
```

### Payload principal

```javascript
AS["interest"] = "but most of all, samy is my hero";
```

---

## 🔒 Mesures de Protection Recommandées

### Pour les Développeurs

1. **Validation et Échappement des Entrées**

   - Valider toutes les entrées utilisateur côté serveur
   - Échapper les caractères HTML spéciaux (`<`, `>`, `"`, `'`, `&`)
   - Utiliser des bibliothèques de sanitization (DOMPurify, OWASP Java Encoder)

2. **Content Security Policy (CSP)**

   ```http
   Content-Security-Policy: default-src 'self'; script-src 'self'
   ```

   - Bloquer l'exécution de scripts inline
   - Restreindre les sources de scripts autorisées

3. **Interdire eval() et constructions dangereuses**

   ```javascript
   // ❌ DANGEREUX
   eval(userInput);

   // ✅ SÉCURISÉ
   JSON.parse(userInput);
   ```

4. **HttpOnly et Secure Cookies**

   ```http
   Set-Cookie: sessionId=abc123; HttpOnly; Secure; SameSite=Strict
   ```

5. **Validation des Tokens CSRF**
   - Implémenter des tokens anti-CSRF pour toutes les actions sensibles
   - Vérifier l'origine des requêtes

### Pour les Utilisateurs

1. **Ne jamais faire confiance au code inconnu**
2. **Maintenir le navigateur à jour**
3. **Utiliser des extensions de sécurité** (NoScript, uBlock Origin)
4. **Se méfier des contenus suspects** dans les profils

---

## 📚 Faille Exploitée

### Vulnérabilité MySpace (2005)

**Type** : Stored XSS (XSS persistant)

**Cause racine** :

- MySpace permettait HTML limité dans les profils
- Filtrage insuffisant des balises et attributs
- Pas de validation du contenu des attributs CSS
- Absence de CSP

**Vecteur d'attaque** :

```html
<div id="mycode" style="BACKGROUND: url()"></div>
```

Le filtre MySpace ne bloquait pas les attributs CSS vides, permettant l'injection de code.

---

## 📈 Impact Historique

### Statistiques du Samy Worm

- **Date** : 4 octobre 2005
- **Durée** : ~20 heures
- **Victimes** : Plus d'1 million de profils infectés
- **Propagation** : Exponentielle (plus rapide ver de l'histoire à l'époque)
- **Conséquence** : Arrêt temporaire de MySpace

---

## 🎓 Leçons Apprises

1. **La validation côté client n'est pas suffisante**
2. **L'obfuscation n'est pas de la sécurité**
3. **Les filtres basés sur des listes noires sont inefficaces**
4. **La défense en profondeur est essentielle**
5. **Les vulnérabilités XSS peuvent avoir un impact massif**

---

## ⚠️ Avertissement Légal

Ce code est présenté **uniquement à des fins éducatives** pour comprendre les vulnérabilités de sécurité web.

**L'utilisation de ce code ou de techniques similaires pour:**

- Accéder à des systèmes sans autorisation
- Modifier des données sans consentement
- Propager des logiciels malveillants

**Est illégale et punissable par la loi.**

---

## 📖 Références

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Samy Worm - Histoire et analyse](<https://en.wikipedia.org/wiki/Samy_(computer_worm)>)

---

## 👨‍💻 Analyse Réalisée

**Date** : 1 novembre 2025  
**Contexte** : Analyse de sécurité à des fins éducatives  
**Classification** : Code malveillant historique (Worm/XSS)

---

**Note** : Ce document fait partie d'un exercice de sécurité informatique visant à comprendre les vulnérabilités web et les techniques d'exploitation pour mieux s'en protéger.
