#!/bin/bash
set -e

BIN="/work/SyzDirect/source/syzdirect/syzdirect_function_model/build/lib/interface_generator"
CHUNK_DIR="/work/syzdirect_workdir/interfaces/case_0/chunks/chunk_034"
OUT_BASE="/work/syzdirect_workdir/interfaces/case_0/chunks"
MERGED_SIG="/work/syzdirect_workdir/interfaces/case_0/chunks/work_chunk_034/kernel_signature_full"
MERGED_SIG_INFO="/work/syzdirect_workdir/interfaces/case_0/chunks/work_chunk_034/kernel_signature_with_info_full"

# Get all .llbc files sorted
mapfile -t ALL_FILES < <(ls "$CHUNK_DIR"/*.llbc | sort)
TOTAL=${#ALL_FILES[@]}
CHUNK_SIZE=10
echo "Total files in chunk_034: $TOTAL, splitting into chunks of $CHUNK_SIZE"

# Clear previous output
> "$MERGED_SIG"
> "$MERGED_SIG_INFO"

SUB_IDX=0
for ((i=0; i<TOTAL; i+=CHUNK_SIZE)); do
    SUB_NAME=$(printf "sub_034_%03d" $SUB_IDX)
    SUB_INPUT="$OUT_BASE/$SUB_NAME"
    SUB_WORK="$OUT_BASE/work_$SUB_NAME"

    # Create sub-chunk input directory with symlinks
    mkdir -p "$SUB_INPUT"
    rm -f "$SUB_INPUT"/*.llbc
    for ((j=i; j<i+CHUNK_SIZE && j<TOTAL; j++)); do
        ln -sf "${ALL_FILES[$j]}" "$SUB_INPUT/"
    done

    FILE_COUNT=$(ls "$SUB_INPUT"/*.llbc 2>/dev/null | wc -l)
    echo "=== $SUB_NAME ($FILE_COUNT files) ==="

    # Create working directory
    mkdir -p "$SUB_WORK"

    # Run interface_generator
    cd "$SUB_WORK"
    if timeout 300 "$BIN" --verbose-level=4 "$SUB_INPUT" > log 2>&1; then
        echo "  done $SUB_NAME"
    else
        EXIT_CODE=$?
        if [ $EXIT_CODE -eq 124 ]; then
            echo "  TIMEOUT $SUB_NAME"
        else
            echo "  FAILED $SUB_NAME (exit=$EXIT_CODE)"
        fi
    fi

    # Merge results
    if [ -f "$SUB_WORK/kernel_signature_full" ] && [ -s "$SUB_WORK/kernel_signature_full" ]; then
        cat "$SUB_WORK/kernel_signature_full" >> "$MERGED_SIG"
        LINES=$(wc -l < "$SUB_WORK/kernel_signature_full")
        echo "  -> $LINES signatures collected"
    fi
    if [ -f "$SUB_WORK/kernel_signature_with_info_full" ] && [ -s "$SUB_WORK/kernel_signature_with_info_full" ]; then
        cat "$SUB_WORK/kernel_signature_with_info_full" >> "$MERGED_SIG_INFO"
    fi

    SUB_IDX=$((SUB_IDX + 1))
done

# Now merge chunk_034's results into the main kernel_signature_full
MAIN_SIG="/work/syzdirect_workdir/interfaces/case_0/kernel_signature_full"
if [ -s "$MERGED_SIG" ]; then
    NEW_LINES=$(wc -l < "$MERGED_SIG")
    echo ""
    echo "chunk_034 produced $NEW_LINES new signatures"
    cat "$MERGED_SIG" >> "$MAIN_SIG"
    TOTAL_LINES=$(wc -l < "$MAIN_SIG")
    echo "Total kernel_signature_full now: $TOTAL_LINES lines"
else
    echo ""
    echo "chunk_034 produced no additional signatures"
fi

echo "Done!"
