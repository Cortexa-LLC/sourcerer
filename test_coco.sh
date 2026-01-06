#!/bin/bash
# Test CoCo platform support with ZAXXON.BIN

DISK_PATH="/Users/bryanw/Downloads/Zaxxon (Datasoft)/ZAXXON.DSK"
OUTPUT_DIR="./test_output"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Testing CoCo 6809 Platform Support${NC}"
echo "===================================="
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Test 1: List files on disk
echo -e "${GREEN}Test 1: Listing files on ZAXXON.DSK${NC}"
/usr/local/bin/cocofs "$DISK_PATH" ls
echo ""

# Test 2: Disassemble ZAXXON.BIN
echo -e "${GREEN}Test 2: Disassembling ZAXXON.BIN${NC}"
./build/sourcerer \
  --cpu 6809 \
  --platform coco \
  --format edtasm \
  --disk \
  --file ZAXXON.BIN \
  --input "$DISK_PATH" \
  --output "$OUTPUT_DIR/zaxxon.asm" \
  --verbose

# Check if output was created
if [ -f "$OUTPUT_DIR/zaxxon.asm" ]; then
  echo ""
  echo -e "${GREEN}✓ Success!${NC} Disassembly created at $OUTPUT_DIR/zaxxon.asm"
  echo ""
  echo "First 30 lines of output:"
  echo "-------------------------"
  head -30 "$OUTPUT_DIR/zaxxon.asm"
  echo "..."
  echo ""
  echo "File size: $(wc -l < "$OUTPUT_DIR/zaxxon.asm") lines"
else
  echo -e "${RED}✗ Failed${NC} - Output file not created"
  exit 1
fi
