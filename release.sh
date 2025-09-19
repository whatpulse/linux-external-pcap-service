#!/bin/bash
set -e

# External PCap Service Release Helper Script
# Usage: ./release.sh <version> [--push] [--force]

VERSION="$1"
PUSH_FLAG=""
FORCE_FLAG=""

# Parse arguments
shift
while [[ $# -gt 0 ]]; do
    case $1 in
        --push)
            PUSH_FLAG="--push"
            shift
            ;;
        --force)
            FORCE_FLAG="--force"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> [--push] [--force]"
    echo ""
    echo "Examples:"
    echo "  $0 1.0.1                    # Prepare release (update version, commit, create tag)"
    echo "  $0 1.0.1 --push             # Prepare and push to trigger GitHub Actions"
    echo "  $0 1.0.1 --force            # Force overwrite existing version/tag"
    echo "  $0 1.0.1 --push --force     # Force overwrite and push immediately"
    echo ""
    echo "Options:"
    echo "  --push   Push changes and tag to remote repository immediately"
    echo "  --force  Overwrite existing version/tag, force push if needed"
    echo ""
    exit 1
fi

# Validate version format (semantic versioning)
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in semantic version format (e.g., 1.0.1)"
    exit 1
fi

echo "🚀 Preparing External PCap Service release v$VERSION"
echo ""

# Check if we're in the right directory
if [ ! -f "pcapservice.h" ]; then
    echo "Error: Please run this script from the repository root"
    exit 1
fi

# Get current version from source
CURRENT_VERSION=$(grep '#define PCAP_SERVICE_VERSION ' pcapservice.h | awk -F '"' '{print $2}')
echo "Current version in source: $CURRENT_VERSION"
echo "Target version: $VERSION"

if [ "$CURRENT_VERSION" = "$VERSION" ] && [ -z "$FORCE_FLAG" ]; then
    echo "⚠️  Version is already set to $VERSION in source code"
    echo "    Use --force to overwrite existing version"
    exit 1
elif [ "$CURRENT_VERSION" = "$VERSION" ] && [ -n "$FORCE_FLAG" ]; then
    echo "⚠️  Version is already set to $VERSION in source code (--force specified, continuing)"
else
    echo "📝 Updating version in source code..."
    sed -i.bak "s/#define PCAP_SERVICE_VERSION \".*\"/#define PCAP_SERVICE_VERSION \"$VERSION\"/" pcapservice.h
    rm pcapservice.h.bak
    echo "✅ Updated PCAP_SERVICE_VERSION to $VERSION"
fi

# Check if there are uncommitted changes
if ! git diff --quiet pcapservice.h; then
    echo "📦 Committing version update..."
    git add pcapservice.h
    if [ -n "$FORCE_FLAG" ]; then
        # Force commit even if there might be conflicts
        git commit -m "bump version to $VERSION" || git commit --amend -m "bump version to $VERSION"
    else
        git commit -m "bump version to $VERSION"
    fi
    echo "✅ Version update committed"
else
    echo "ℹ️  No changes to commit"
fi

# Create tag
TAG_NAME="v$VERSION"
if git rev-parse "$TAG_NAME" >/dev/null 2>&1; then
    if [ -n "$FORCE_FLAG" ]; then
        echo "⚠️  Tag $TAG_NAME already exists (--force specified, recreating)"
        git tag -d "$TAG_NAME"  # Delete local tag
        git tag -a "$TAG_NAME" -m "External PCap Service v$VERSION"
        echo "✅ Tag $TAG_NAME recreated"
    else
        echo "⚠️  Tag $TAG_NAME already exists"
        echo "    Use --force to overwrite existing tag"
        exit 1
    fi
else
    echo "🏷️  Creating tag $TAG_NAME..."
    git tag -a "$TAG_NAME" -m "External PCap Service v$VERSION"
    echo "✅ Tag $TAG_NAME created"
fi

echo ""
echo "📋 Release preparation complete!"
echo ""

if [ "$PUSH_FLAG" = "--push" ]; then
    echo "🚢 Pushing changes and tag to trigger GitHub Actions..."

    if [ -n "$FORCE_FLAG" ]; then
        echo "   Using --force push for tag (will overwrite remote tag if exists)"
        git push origin HEAD
        git push origin "$TAG_NAME" --force
    else
        git push origin HEAD
        git push origin "$TAG_NAME"
    fi

    echo ""
    echo "✅ Changes pushed! GitHub Actions will now build and release."
    echo "   View progress at: https://github.com/whatpulse/linux-external-pcap-service/actions"
else
    echo "Next steps:"
    echo "1. Review the changes: git log --oneline -n 2"

    if [ -n "$FORCE_FLAG" ]; then
        echo "2. Push to trigger release (with force): git push origin HEAD && git push origin $TAG_NAME --force"
        echo "   Or run: $0 $VERSION --push --force"
    else
        echo "2. Push to trigger release: git push origin HEAD && git push origin $TAG_NAME"
        echo "   Or run: $0 $VERSION --push"
    fi

    echo ""
    echo "The GitHub Actions workflow will automatically:"
    echo "• Build the service for Linux"
    echo "• Create packages (deb, rpm, binary)"
    echo "• Generate checksums"
    echo "• Create GitHub release with all assets"

    if [ -n "$FORCE_FLAG" ]; then
        echo ""
        echo "⚠️  Force mode enabled - this will overwrite existing releases!"
    fi
fi

echo ""
echo "🔗 After release, packages will be available at:"
echo "   https://github.com/whatpulse/linux-external-pcap-service/releases/tag/$TAG_NAME"
