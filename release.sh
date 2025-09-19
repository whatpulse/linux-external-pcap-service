#!/bin/bash
set -e

# External PCap Service Release Helper Script
# Usage: ./release.sh <version> [--push]

VERSION="$1"
PUSH_FLAG="$2"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> [--push]"
    echo ""
    echo "Examples:"
    echo "  $0 1.0.1         # Prepare release (update version, commit, create tag)"
    echo "  $0 1.0.1 --push  # Prepare and push to trigger GitHub Actions"
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

if [ "$CURRENT_VERSION" = "$VERSION" ]; then
    echo "⚠️  Version is already set to $VERSION in source code"
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
    git commit -m "bump version to $VERSION"
    echo "✅ Version update committed"
else
    echo "ℹ️  No changes to commit"
fi

# Create tag
TAG_NAME="v$VERSION"
if git rev-parse "$TAG_NAME" >/dev/null 2>&1; then
    echo "⚠️  Tag $TAG_NAME already exists"
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
    git push origin HEAD
    git push origin "$TAG_NAME"
    echo ""
    echo "✅ Changes pushed! GitHub Actions will now build and release."
    echo "   View progress at: https://github.com/whatpulse/linux-external-pcap-service/actions"
else
    echo "Next steps:"
    echo "1. Review the changes: git log --oneline -n 2"
    echo "2. Push to trigger release: git push origin HEAD && git push origin $TAG_NAME"
    echo "   Or run: $0 $VERSION --push"
    echo ""
    echo "The GitHub Actions workflow will automatically:"
    echo "• Build the service for Linux"
    echo "• Create packages (deb, rpm, binary)"
    echo "• Generate checksums"
    echo "• Create GitHub release with all assets"
fi

echo ""
echo "🔗 After release, packages will be available at:"
echo "   https://github.com/whatpulse/linux-external-pcap-service/releases/tag/$TAG_NAME"
