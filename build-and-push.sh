#!/bin/bash

# Configuration
IMAGE_NAME="prognose-backend"
REGISTRY="docker.io/prognosepolito"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Extract version from pom.xml
echo -e "${YELLOW}Extracting version from pom.xml...${NC}"
if [ ! -f pom.xml ]; then
    echo -e "${RED}Error: pom.xml not found${NC}"
    exit 1
fi

VERSION=$(sed -n 's/.*<version>\(.*\)<\/version>.*/\1/p' pom.xml | head -1)
if [ -z "$VERSION" ]; then
    echo -e "${RED}Error: Could not extract version from pom.xml${NC}"
    echo -e "${YELLOW}Using default version: 1.0.0${NC}"
    VERSION="1.0.0"
else
    echo -e "${GREEN}Found version: $VERSION${NC}"
fi

# Define database types to build
DB_TYPES=("postgres" "oracle")

# Build and push for each database type
for db_type in "${DB_TYPES[@]}"; do
    # Define tags for this db type
    VERSION_TAG="$REGISTRY/$IMAGE_NAME:$VERSION-$db_type"
    LATEST_TAG="$REGISTRY/$IMAGE_NAME:latest-$db_type"
    
    echo -e "\n${GREEN}Building Docker image for database type: $db_type...${NC}"
    docker build \
        --build-arg DB_TYPE=$db_type \
        -t $VERSION_TAG \
        -t $LATEST_TAG .
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}Successfully built images for $db_type:${NC}"
        echo -e "  - $VERSION_TAG"
        echo -e "  - $LATEST_TAG"
        
        echo -e "${GREEN}Pushing images to registry: $REGISTRY${NC}"
        
        # Push version tag
        echo -e "${YELLOW}Pushing $VERSION_TAG...${NC}"
        docker push $VERSION_TAG
        VERSION_PUSH_STATUS=$?
        
        # Push latest tag
        echo -e "${YELLOW}Pushing $LATEST_TAG...${NC}"
        docker push $LATEST_TAG
        LATEST_PUSH_STATUS=$?
        
        if [ $VERSION_PUSH_STATUS -eq 0 ] && [ $LATEST_PUSH_STATUS -eq 0 ]; then
            echo -e "${GREEN}Successfully pushed images for $db_type${NC}"
        else
            echo -e "${RED}Failed to push one or more images for $db_type${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Failed to build images for $db_type${NC}"
        exit 1
    fi
done

echo -e "\n${GREEN}All images have been built and pushed successfully${NC}"
echo -e "${GREEN}Images are now available at:${NC}"
for db_type in "${DB_TYPES[@]}"; do
    echo -e "  - $REGISTRY/$IMAGE_NAME:$VERSION-$db_type"
    echo -e "  - $REGISTRY/$IMAGE_NAME:latest-$db_type"
done