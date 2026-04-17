#!/bin/bash
set +H
SUBSET=/work/syzdirect_workdir/tpa/case_4/bitcode_subset
BITCODE=/work/syzdirect_workdir/bitcode/case_4
EXCLUDE=/tmp/drivers_exclude.txt
INCLUDE=/tmp/drivers_block.txt

rm -f "$SUBSET"/*.llbc 2>/dev/null
mkdir -p "$SUBSET"

for f in "$BITCODE"/*.llbc; do
    bn=$(basename "$f")
    # Skip drivers files that are NOT in drivers/block
    if grep -qxF "$bn" "$EXCLUDE"; then
        if ! grep -qxF "$bn" "$INCLUDE"; then
            continue
        fi
    fi
    ln -sf "$f" "$SUBSET/$bn"
done

echo "Subset files: $(ls "$SUBSET" | wc -l)"
