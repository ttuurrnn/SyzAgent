#!/bin/bash
set -e

BIN="/work/SyzDirect/source/syzdirect/syzdirect_kernel_analysis/build/lib/target_analyzer"
BITCODE_DIR="/work/syzdirect_workdir/bcs/case_0"
INTERFACE_FILE="/work/syzdirect_workdir/interfaces/case_0/kernelCode2syscall.json"
TPA_DIR="/work/syzdirect_workdir/tpa/case_0"
CHUNK_BASE="/work/syzdirect_workdir/tpa/case_0/chunks"

mkdir -p "$CHUNK_BASE"

# Collect all .llbc files
mapfile -t ALL_FILES < <(find "$BITCODE_DIR" -name "*.llbc" -type f | sort)
TOTAL=${#ALL_FILES[@]}
CHUNK_SIZE=100
NUM_CHUNKS=$(( (TOTAL + CHUNK_SIZE - 1) / CHUNK_SIZE ))

echo "Total .llbc files: $TOTAL"
echo "Chunk size: $CHUNK_SIZE"
echo "Number of chunks: $NUM_CHUNKS"
echo ""

# Create chunk input directories with symlinks
for ((c=0; c<NUM_CHUNKS; c++)); do
    CNAME=$(printf "chunk_%03d" $c)
    CDIR="$CHUNK_BASE/$CNAME"
    mkdir -p "$CDIR"
    rm -f "$CDIR"/*.llbc

    START=$((c * CHUNK_SIZE))
    END=$((START + CHUNK_SIZE))
    if [ $END -gt $TOTAL ]; then END=$TOTAL; fi

    IDX=0
    for ((j=START; j<END; j++)); do
        FNAME=$(printf "file_%06d.llbc" $IDX)
        ln -sf "${ALL_FILES[$j]}" "$CDIR/$FNAME"
        IDX=$((IDX + 1))
    done
done

echo "Created $NUM_CHUNKS chunk directories"
echo ""

# Run target_analyzer on each chunk
FAILED_CHUNKS=()
for ((c=0; c<NUM_CHUNKS; c++)); do
    CNAME=$(printf "chunk_%03d" $c)
    CDIR="$CHUNK_BASE/$CNAME"
    WDIR="$CHUNK_BASE/work_$CNAME"
    mkdir -p "$WDIR"

    FILE_COUNT=$(ls "$CDIR"/*.llbc 2>/dev/null | wc -l)
    echo "=== $CNAME ($FILE_COUNT files) ==="

    cd "$WDIR"
    if timeout 600 "$BIN" --verbose-level=4 \
        -kernel-interface-file="$INTERFACE_FILE" \
        "$CDIR" > log 2>&1; then
        echo "  done $CNAME"
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            echo "  TIMEOUT $CNAME"
        else
            echo "  FAILED $CNAME (exit=$EXIT_CODE)"
        fi
        FAILED_CHUNKS+=("$CNAME")
    fi

    # Show what was produced
    for f in CompactOutput.json target_functions_info.txt duplicate_points.txt; do
        if [ -f "$WDIR/$f" ] && [ -s "$WDIR/$f" ]; then
            echo "  -> produced $f ($(wc -c < "$WDIR/$f") bytes)"
        fi
    done
done

echo ""
echo "=== Summary ==="
echo "Total chunks: $NUM_CHUNKS"
echo "Failed chunks: ${#FAILED_CHUNKS[@]}"
if [ ${#FAILED_CHUNKS[@]} -gt 0 ]; then
    echo "Failed: ${FAILED_CHUNKS[*]}"
fi

# Merge CompactOutput.json from all chunks
echo ""
echo "Merging results..."
python3 - "$CHUNK_BASE" "$TPA_DIR" "$NUM_CHUNKS" <<'PYEOF'
import json, sys, os

chunk_base = sys.argv[1]
tpa_dir = sys.argv[2]
num_chunks = int(sys.argv[3])

merged = []
target_funcs = []

for c in range(num_chunks):
    cname = f"chunk_{c:03d}"
    wdir = os.path.join(chunk_base, f"work_{cname}")

    co = os.path.join(wdir, "CompactOutput.json")
    if os.path.exists(co) and os.path.getsize(co) > 0:
        try:
            with open(co) as f:
                data = json.load(f)
            if isinstance(data, list):
                merged.extend(data)
            elif isinstance(data, dict):
                merged.append(data)
            print(f"  {cname}: loaded CompactOutput.json")
        except Exception as e:
            print(f"  {cname}: error loading CompactOutput.json: {e}")

    tf = os.path.join(wdir, "target_functions_info.txt")
    if os.path.exists(tf) and os.path.getsize(tf) > 0:
        with open(tf) as f:
            target_funcs.extend(f.readlines())

if merged:
    out_co = os.path.join(tpa_dir, "CompactOutput.json")
    with open(out_co, "w") as f:
        json.dump(merged, f, indent=2)
    print(f"\nMerged CompactOutput.json: {len(merged)} entries -> {out_co}")
else:
    print("\nNo CompactOutput.json entries found from any chunk")

if target_funcs:
    out_tf = os.path.join(tpa_dir, "target_functions_info.txt")
    with open(out_tf, "w") as f:
        f.writelines(target_funcs)
    print(f"Merged target_functions_info.txt: {len(target_funcs)} lines")

PYEOF

echo "Done!"
