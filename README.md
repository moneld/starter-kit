# Documentation de l'API Backend

Cette documentation fournit une vue d'ensemble complète de l'API backend, y compris son architecture, ses fonctionnalités, et les bonnes pratiques de sécurité qui ont été implémentées.

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Architecture](#architecture)
3. [Modèles de données](#modèles-de-données)
4. [Sécurité](#sécurité)
5. [Authentification](#authentification)
6. [Endpoints API](#endpoints-api)
7. [Gestion des erreurs](#gestion-des-erreurs)
8. [Journalisation](#journalisation)
9. [Configuration](#configuration)
10. [Déploiement](#déploiement)

## Vue d'ensemble

Cette API backend est construite avec NestJS, un framework Node.js progressif qui favorise une architecture modulaire, extensible et maintenable. Elle est conçue pour servir d'interface sécurisée entre les clients frontend et la base de données, en fournissant des fonctionnalités robustes d'authentification et d'autorisation.

### Technologies principales

- **Framework**: NestJS v11
- **Runtime**: Node.js
- **Base de données**: PostgreSQL avec Prisma ORM
- **Authentification**: JWT (JSON Web Tokens)
- **Serveur HTTP**: Fastify
- **Documentation API**: Swagger/OpenAPI
- **Journalisation**: Pino/Winston

## Architecture

L'application est structurée suivant l'architecture modulaire de NestJS, avec une séparation claire des responsabilités.

### Structure des dossiers

```
├── src/
│   ├── app.module.ts             # Module racine de l'application
│   ├── main.ts                   # Point d'entrée de l'application
│   ├── common/                   # Utilitaires et services communs
│   │   ├── modules/              # Modules communs (ex: logging)
│   │   └── services/             # Services communs (ex: crypto)
│   ├── config/                   # Configuration de l'application
│   ├── modules/                  # Modules fonctionnels
│   │   ├── auth/                 # Module d'authentification
│   │   ├── users/                # Module de gestion des utilisateurs
│   │   ├── mail/                 # Module d'envoi d'emails
│   │   └── prisma/               # Module d'accès à la base de données
├── prisma/                       # Schéma et migrations Prisma
│   ├── schema.prisma             # Définition des modèles de données
│   └── migrations/               # Migrations de base de données

```

### Modules principaux

1. **AppModule**: Module racine qui coordonne tous les autres modules.
2. **AuthModule**: Gère l'authentification, les tokens JWT, et l'autorisation.
3. **UsersModule**: Gère la création, mise à jour et suppression des utilisateurs.
4. **PrismaModule**: Gère la connexion à la base de données.
5. **MailModule**: Gère l'envoi d'emails.

## Modèles de données

### Principaux modèles

Les modèles de données sont définis dans le fichier `prisma/schema.prisma`:

#### User

Modèle principal pour les utilisateurs du système.

```prisma
model User {
  id                  String    @id @default(uuid())
  email               String    @unique
  password            String
  firstName           String?   @map("first_name")
  lastName            String?   @map("last_name")
  role                UserRole  @default(USER)
  isActive            Boolean   @default(false) @map("is_active")
  isEmailVerified     Boolean   @default(false) @map("is_email_verified")
  createdAt           DateTime  @default(now()) @map("created_at")
  updatedAt           DateTime  @updatedAt @map("updated_at")
  failedLoginAttempts Int       @default(0) @map("failed_login_attempts")
  lockedUntil         DateTime? @map("locked_until")
  lastLoginAt         DateTime? @map("last_login_at")
  isTwoFactorEnabled  Boolean   @default(false) @map("is_two_factor_enabled")
  twoFactorSecret     String?   @map("two_factor_secret")
  twoFactorRecoveryCodes String? @map("two_factor_recovery_codes")
  
  // Relations
  verificationToken   VerificationToken?
  passwordResetToken  PasswordResetToken?
  refreshToken        RefreshToken?
  
  @@index([email])
  @@map("users")
}
```

#### Tokens

Plusieurs modèles de tokens pour différentes fonctionnalités:

```prisma
model VerificationToken {
  id        String   @id @default(uuid())
  token     String   @unique
  expiresAt DateTime @map("expires_at")
  createdAt DateTime @default(now()) @map("created_at")
  userId    String   @unique @map("user_id")
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([token])
  @@map("verification_tokens")
}

model PasswordResetToken {
  id        String   @id @default(uuid())
  token     String   @unique
  expiresAt DateTime @map("expires_at")
  createdAt DateTime @default(now()) @map("created_at")
  userId    String   @unique @map("user_id") 
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([token])
  @@map("password_reset_tokens")
}

model RefreshToken {
  id        String   @id @default(uuid())
  token     String   @unique
  expiresAt DateTime @map("expires_at")
  createdAt DateTime @default(now()) @map("created_at")
  userAgent String?  @map("user_agent")
  ipAddress String?  @map("ip_address")
  isRevoked Boolean  @default(false) @map("is_revoked")
  userId    String   @unique @map("user_id")
  user      User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([token])
  @@map("refresh_tokens")
}
```

#### Clés de chiffrement

```prisma
model EncryptionKey {
  id        String    @id @default(uuid())
  version   Int       @unique
  key       String
  isActive  Boolean   @default(true)
  createdAt DateTime  @default(now()) @map("created_at")
  expiresAt DateTime? @map("expires_at")
  
  @@map("encryption_keys")
}
```

## Sécurité

L'API implémente de nombreuses fonctionnalités de sécurité pour protéger les données sensibles et prévenir les attaques courantes.

### Chiffrement des données sensibles

Le système utilise un chiffrement robuste pour protéger les données sensibles:

1. **Algorithme**: AES-256-GCM (Advanced Encryption Standard avec Galois/Counter Mode)
2. **Hiérarchie des clés**:
    - Une clé racine principale (`MASTER_ENCRYPTION_KEY`) stockée dans les variables d'environnement
    - Des clés de chiffrement de données générées dynamiquement et stockées chiffrées dans la base de données

#### Données chiffrées

Les données sensibles suivantes sont chiffrées:
- Secrets d'authentification à deux facteurs (`twoFactorSecret`)
- Codes de récupération pour l'authentification à deux facteurs (`twoFactorRecoveryCodes`)

#### Rotation des clés

Un système automatisé de rotation des clés est implémenté pour renforcer la sécurité:
- Rotation périodique configurable (par défaut tous les 90 jours)
- Rechiffrement automatique des données avec les nouvelles clés
- Gestion des versions de clés pour garantir la continuité

### Hachage des mots de passe

Les mots de passe sont hachés en utilisant Argon2id, un algorithme de hachage moderne recommandé pour sa résistance aux attaques:

- **Algorithme**: Argon2id
- **Paramètres configurables**:
    - `ARGON2_MEMORY_COST`: Coût mémoire (par défaut: 65536)
    - `ARGON2_TIME_COST`: Coût temporel (par défaut: 3)
    - `ARGON2_PARALLELISM`: Niveau de parallélisme (par défaut: 4)
    - `ARGON2_SALT_LENGTH`: Longueur du sel (par défaut: 16)

### Protection contre les attaques

1. **Limitation de débit (Rate Limiting)**:
    - Protection contre les attaques par force brute
    - Configuration: `RATE_LIMIT_TTL` et `RATE_LIMIT_MAX`

2. **Verrouillage de compte**:
    - Après un nombre configurable de tentatives de connexion échouées
    - Configuration: `ACCOUNT_LOCKOUT_MAX_ATTEMPTS` et `ACCOUNT_LOCKOUT_DURATION`

3. **En-têtes de sécurité HTTP**:
    - Headers Helmet pour la protection contre les attaques XSS, clickjacking, etc.
    - Configuration CORS avec options personnalisables
    - Headers Content-Security-Policy, X-XSS-Protection, etc.

4. **Validation des entrées**:
    - Validation stricte de toutes les entrées utilisateur avec class-validator
    - Filtrage des propriétés non déclarées (`whitelist: true`)
    - Rejet des requêtes avec des propriétés non déclarées (`forbidNonWhitelisted: true`)

### Journalisation sécurisée

Le système de journalisation est configuré pour éviter la fuite d'informations sensibles:
- Redaction automatique des données sensibles (mots de passe, tokens, etc.)
- Rotation et compression des fichiers de logs
- Séparation des logs d'erreur pour une meilleure visibilité

## Authentification

Le système d'authentification offre de multiples niveaux de sécurité:

### Flux d'authentification

1. **Inscription**:
    - Validation de l'email et du mot de passe
    - Envoi d'un email de vérification
    - Confirmation du compte via un lien unique

2. **Connexion**:
    - Authentification par email/mot de passe
    - Vérification du statut du compte (actif, verrouillé, vérifié)
    - Authentification à deux facteurs (si activée)
    - Génération de tokens JWT (accès et rafraîchissement)

3. **Rafraîchissement du token**:
    - Vérification du token de rafraîchissement
    - Génération de nouveaux tokens
    - Révocation des tokens précédents

4. **Déconnexion**:
    - Révocation des tokens de rafraîchissement
    - Option pour déconnecter toutes les sessions

### Authentification à deux facteurs (2FA)

Le système prend en charge l'authentification à deux facteurs basée sur TOTP (Time-based One-Time Password):

1. **Activation**:
    - Génération d'un secret unique
    - QR code pour configuration dans des applications comme Google Authenticator
    - Vérification initiale du code pour confirmation
    - Génération de codes de récupération d'urgence

2. **Connexion avec 2FA**:
    - Première étape: vérification de l'email/mot de passe
    - Seconde étape: vérification du code TOTP ou code de récupération
    - Génération des tokens JWT seulement après validation des deux étapes

3. **Gestion 2FA**:
    - Désactivation avec confirmation par mot de passe
    - Régénération des codes de récupération
    - Chiffrement des secrets et codes de récupération dans la base de données

### Gestion des tokens JWT

- **Token d'accès**: courte durée (15min par défaut)
- **Token de rafraîchissement**: longue durée (7 jours par défaut)
- **Stockage sécurisé**: les tokens de rafraîchissement sont stockés en base avec contexte (IP, User-Agent)
- **Invalidation**: possibilité de révoquer des tokens spécifiques ou tous les tokens d'un utilisateur

## Endpoints API

L'API expose les endpoints suivants, principalement regroupés sous le préfixe `/auth`:

### Inscription et vérification

- `POST /auth/register`: Inscription d'un nouvel utilisateur
- `GET /auth/verify-email`: Vérification d'un compte par token d'email
- `POST /auth/resend-verification-email`: Renvoie l'email de vérification

### Connexion et gestion de session

- `POST /auth/login`: Authentification utilisateur
- `POST /auth/logout`: Déconnexion (un seul appareil)
- `POST /auth/logout-all`: Déconnexion de toutes les sessions
- `POST /auth/refresh-token`: Rafraîchissement du token d'accès

### Authentification à deux facteurs

- `POST /auth/verify-2fa`: Vérification du code 2FA
- `POST /auth/recovery-code`: Connexion avec un code de récupération
- `GET /auth/2fa/generate`: Génération d'un secret 2FA
- `POST /auth/2fa/enable`: Activation de la 2FA
- `POST /auth/2fa/disable`: Désactivation de la 2FA
- `POST /auth/2fa/recovery-codes`: Régénération des codes de récupération

### Gestion de mot de passe

- `POST /auth/forgot-password`: Demande de réinitialisation de mot de passe
- `POST /auth/reset-password`: Réinitialisation du mot de passe avec token
- `POST /auth/change-password`: Changement de mot de passe (utilisateur connecté)

### Administration

- `POST /auth/users/:id/activate`: Activation d'un compte (admin)
- `POST /auth/users/:id/deactivate`: Désactivation d'un compte (admin)
- `POST /auth/users/:id/unlock`: Déverrouillage d'un compte (admin)

## Gestion des erreurs

L'API utilise un système centralisé de gestion des erreurs pour garantir des réponses cohérentes et sécurisées:

### Types d'erreurs gérées

1. **Erreurs HTTP standards**: BadRequestException, UnauthorizedException, etc.
2. **Erreurs JWT**: TokenExpiredError, JsonWebTokenError, etc.
3. **Erreurs Prisma**: Erreurs de base de données avec codes spécifiques
4. **Erreurs d'authentification**: Erreurs liées à Passport.js

### Format des réponses d'erreur

```json
{
  "statusCode": 400,
  "message": "Description de l'erreur",
  "error": "Type d'erreur",
  "timestamp": "2023-05-21T12:00:00.000Z",
  "path": "/auth/login",
  "requestId": "req-123456"
}
```

### Sanitisation des erreurs

En production, les messages d'erreur sont sanitisés pour éviter la divulgation d'informations sensibles:
- Pas de détails techniques pour les erreurs 500
- Pas d'informations sur la structure de la base de données
- Messages génériques pour les erreurs de sécurité

## Journalisation

Le système de journalisation est basé sur Pino/Winston avec des fonctionnalités avancées:

### Configuration

- **Niveaux de log**: error, warn, info, debug (configurable via `LOG_LEVEL`)
- **Rotation des logs**: taille maximale et période de rétention configurables
- **Compression**: compression gzip des anciens logs
- **Séparation**: logs généraux et logs d'erreur dans des fichiers distincts

### Redaction des données sensibles

Les données sensibles sont automatiquement masquées dans les logs:
- Tokens d'authentification
- Mots de passe
- Cookies
- Autres informations sensibles (configurable)

### Format des logs

En développement:
- Format lisible avec colorisation
- Affichage en ligne unique pour faciliter la lecture

En production:
- Format JSON pour faciliter l'intégration avec des outils d'analyse
- Métadonnées enrichies (niveau, timestamp, requestId, etc.)

## Configuration

La configuration de l'application est gérée par des variables d'environnement, avec des valeurs par défaut raisonnables:

### Fichier .env

```
# Configuration de base
NODE_ENV=development
APP_NAME="Backend"
PORT=3000
FRONTEND_URL=""

# Base de données PostgreSQL
DATABASE_URL=postgresql://username:password@localhost:5432/your_db_name?schema=public

# JWT
JWT_ACCESS_SECRET=your_very_strong_jwt_access_secret_key_here
JWT_ACCESS_EXPIRATION=15m
JWT_REFRESH_SECRET=your_very_strong_jwt_refresh_secret_key_here
JWT_REFRESH_EXPIRATION=7d

# Chiffrement
MASTER_ENCRYPTION_KEY=votre_clé_racine_très_sécurisée_de_32_caractères
ENCRYPTION_KEY_ROTATION_INTERVAL=90

# Argon2
ARGON2_MEMORY_COST=65536
ARGON2_TIME_COST=3
ARGON2_PARALLELISM=4
ARGON2_SALT_LENGTH=16
RATE_LIMIT_TTL=60000 # en millisecondes, 1 minute
RATE_LIMIT_MAX=5     # tentatives max avant blocage

# Authentification à deux facteurs
TWO_FACTOR_APP_NAME=$APP_NAME
TWO_FACTOR_RECOVERY_CODE_LENGTH=10
TWO_FACTOR_RECOVERY_CODES_COUNT=8

# Email
MAIL_HOST=smtp.example.com
MAIL_PORT=587
MAIL_USER=your_email@example.com
MAIL_PASSWORD=your_email_password
MAIL_FROM=noreply@your-domain.com
MAIL_ENCRYPTION=ssl

# Logging
LOG_DIR=logs
LOG_LEVEL=info # (error, warn, info, debug)
LOG_MAX_SIZE=20m
LOG_MAX_FILES=14d # conservation 14 jours

# Verrouillage de compte
ACCOUNT_LOCKOUT_MAX_ATTEMPTS=5
ACCOUNT_LOCKOUT_DURATION=15m # durée de blocage après X tentatives échouées

# Cors
CORS_ORIGIN="*"
```

### Configuration modulaire

La configuration est organisée en modules dans le dossier `src/config/`:
- `app.config.ts`: Paramètres généraux de l'application
- `security.config.ts`: Paramètres de sécurité (JWT, chiffrement, etc.)
- Autres modules selon les besoins

## Déploiement

### Prérequis

- Node.js 18+ (de préférence Node.js 20+)
- PostgreSQL 13+
- Un serveur SMTP pour l'envoi d'emails

### Installation

1. Cloner le dépôt
2. Installer les dépendances: `npm install`
3. Configurer les variables d'environnement: copier `.env.example` vers `.env` et modifier selon les besoins
4. Exécuter les migrations: `npx prisma migrate deploy`
5. Construire l'application: `npm run build`
6. Démarrer l'application: `npm run start:prod`

### Configuration pour la production

Pour un déploiement en production, assurez-vous de:

1. Définir `NODE_ENV=production`
2. Utiliser des secrets JWT forts et uniques
3. Configurer une clé de chiffrement maître sécurisée
4. Limiter les origines CORS aux domaines de confiance
5. Configurer correctement le transport SMTP
6. Utiliser un reverse proxy comme Nginx
7. Activer HTTPS avec des certificats valides

### Monitoring et maintenance

- **Rotation des clés**: Système automatisé de rotation des clés de chiffrement
- **Backup**: Planifier des sauvegardes régulières de la base de données
- **Logs**: Analyser régulièrement les logs pour détecter les anomalies