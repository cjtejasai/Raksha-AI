#!/bin/bash
# Quick Publish Script for Raksha
# Usage: ./publish.sh [git|pypi|both]

set -e  # Exit on error

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}         Raksha Publishing Helper Script${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Function to publish to Git
publish_git() {
    echo -e "${YELLOW}📦 Publishing to Git...${NC}"

    # Check if remote exists
    if ! git remote get-url origin &>/dev/null; then
        echo -e "${RED}❌ No git remote 'origin' configured!${NC}"
        echo -e "${YELLOW}Run: git remote add origin https://github.com/USERNAME/raksha.git${NC}"
        exit 1
    fi

    # Stage changes
    echo "  → Staging changes..."
    git add .

    # Check if there are changes
    if git diff --staged --quiet; then
        echo -e "${GREEN}✅ No changes to commit${NC}"
    else
        # Get commit message
        echo ""
        echo "Enter commit message (or press Enter for default):"
        read -r commit_msg

        if [ -z "$commit_msg" ]; then
            commit_msg="Update Raksha SDK"
        fi

        echo "  → Committing: $commit_msg"
        git commit -m "$commit_msg"

        echo "  → Pushing to GitHub..."
        git push

        echo -e "${GREEN}✅ Successfully pushed to GitHub!${NC}"
    fi
}

# Function to build package
build_package() {
    echo -e "${YELLOW}🔨 Building package...${NC}"

    # Check if build tools are installed
    if ! python -m build --version &>/dev/null; then
        echo "  → Installing build tools..."
        pip install --upgrade build twine
    fi

    # Clean old builds
    echo "  → Cleaning old builds..."
    rm -rf build/ dist/ *.egg-info src/*.egg-info

    # Build
    echo "  → Building distribution files..."
    python -m build

    echo -e "${GREEN}✅ Package built successfully!${NC}"
    echo "  Created:"
    ls -lh dist/
}

# Function to publish to PyPI
publish_pypi() {
    local repo=$1

    if [ "$repo" = "test" ]; then
        echo -e "${YELLOW}🧪 Publishing to TestPyPI...${NC}"
        python -m twine upload --repository testpypi dist/*
        echo -e "${GREEN}✅ Published to TestPyPI!${NC}"
        echo -e "${BLUE}Test install: pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ raksha${NC}"
    else
        echo -e "${YELLOW}🚀 Publishing to PyPI...${NC}"
        echo -e "${RED}⚠️  This will publish to the REAL PyPI!${NC}"
        echo "Continue? (yes/no)"
        read -r confirm

        if [ "$confirm" != "yes" ]; then
            echo "Cancelled."
            exit 0
        fi

        python -m twine upload dist/*
        echo -e "${GREEN}✅ Published to PyPI!${NC}"
        echo -e "${BLUE}Install: pip install raksha${NC}"
    fi
}

# Main script
case ${1:-both} in
    git)
        publish_git
        ;;
    pypi)
        build_package
        publish_pypi "real"
        ;;
    testpypi)
        build_package
        publish_pypi "test"
        ;;
    both)
        publish_git
        echo ""
        build_package
        echo ""
        echo -e "${YELLOW}Ready to publish to PyPI!${NC}"
        echo "Choose:"
        echo "  1) TestPyPI (recommended first)"
        echo "  2) Real PyPI"
        echo "  3) Skip PyPI"
        read -p "Enter choice (1-3): " choice

        case $choice in
            1)
                publish_pypi "test"
                ;;
            2)
                publish_pypi "real"
                ;;
            3)
                echo "Skipped PyPI upload"
                ;;
            *)
                echo "Invalid choice"
                exit 1
                ;;
        esac
        ;;
    *)
        echo "Usage: $0 [git|pypi|testpypi|both]"
        echo ""
        echo "Options:"
        echo "  git       - Only push to GitHub"
        echo "  pypi      - Only publish to PyPI"
        echo "  testpypi  - Only publish to TestPyPI"
        echo "  both      - Push to GitHub and publish to PyPI (default)"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}                  🎉 All Done!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"