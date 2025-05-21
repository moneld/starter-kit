#!/bin/bash

# Couleurs pour les messages
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Configuration de l'environnement de développement ===${NC}"

# Vérifier si le fichier .env existe
if [ ! -f .env ]; then
    echo -e "${YELLOW}Le fichier .env n'existe pas. Création à partir de .env.example...${NC}"

    # Vérifier si .env.example existe
    if [ ! -f .env.example ]; then
        echo -e "${YELLOW}Erreur: .env.example n'existe pas. Création d'un fichier .env vide...${NC}"
        touch .env
    else
        cp .env.example .env
        echo -e "${GREEN}Le fichier .env a été créé avec succès.${NC}"
    fi
else
    echo -e "${GREEN}Le fichier .env existe déjà.${NC}"
fi

# Fonction pour générer une chaîne aléatoire sécurisée
generate_secure_key() {
    openssl rand -base64 64 | tr -d '\n'
}

# Fonction pour mettre à jour ou ajouter une variable dans le fichier .env
update_env_var() {
    local key=$1
    local value=$2

    # Vérifie si la variable existe dans le fichier
    if grep -q "^${key}=" .env; then
        # Remplacer la valeur existante
        sed -i.bak "s|^${key}=.*|${key}=${value}|" .env && rm .env.bak
        echo -e "${GREEN}Variable ${key} mise à jour.${NC}"
    else
        # Ajouter la nouvelle variable
        echo "${key}=${value}" >>.env
        echo -e "${GREEN}Variable ${key} ajoutée.${NC}"
    fi
}

echo -e "${BLUE}Génération des clés de sécurité...${NC}"

# Générer et configurer JWT_ACCESS_SECRET
JWT_ACCESS_SECRET=$(generate_secure_key)
update_env_var "JWT_ACCESS_SECRET" "${JWT_ACCESS_SECRET}"

# Générer et configurer JWT_REFRESH_SECRET
JWT_REFRESH_SECRET=$(generate_secure_key)
update_env_var "JWT_REFRESH_SECRET" "${JWT_REFRESH_SECRET}"

# Générer et configurer MASTER_ENCRYPTION_KEY
MASTER_ENCRYPTION_KEY=$(generate_secure_key)
update_env_var "MASTER_ENCRYPTION_KEY" "${MASTER_ENCRYPTION_KEY}"

# Générer et configurer CSRF_SECRET_KEY
CSRF_SECRET_KEY=$(generate_secure_key)
update_env_var "CSRF_SECRET_KEY" "${CSRF_SECRET_KEY}"

echo -e "${GREEN}Configuration terminée avec succès !${NC}"
echo -e "${BLUE}Les variables suivantes ont été configurées:${NC}"
echo -e "  - JWT_ACCESS_SECRET"
echo -e "  - JWT_REFRESH_SECRET"
echo -e "  - MASTER_ENCRYPTION_KEY"
echo -e "  - CSRF_SECRET_KEY"

echo -e "${YELLOW}Note: Assurez-vous que le fichier .env contient toutes les autres variables nécessaires à votre application.${NC}"
