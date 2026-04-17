#!/bin/bash
# Interface analysis for case_2 in chunks

BIN=/work/SyzDirect/source/syzdirect/syzdirect_function_model/build/lib/interface_generator
INPUT=/work/syzdirect_workdir/bitcode/case_2
OUTPUT=/work/syzdirect_workdir/interfaces/case_2
TOTAL=$(ls "$INPUT"/*.llbc 2>/dev/null | wc -l)
CHUNK_SIZE=200
CHUNKS=$(( (TOTAL + CHUNK_SIZE - 1) / CHUNK_SIZE ))

echo "Total $TOTAL file(s), $CHUNKS chunks of $CHUNK_SIZE"

all_sigs=0
failed_chunks=""
n_failed=0

for c in $(seq 0 $((CHUNKS-1))); do
    cname=$(printf "chunk_%03d" $c)
    CDIR="$OUTPUT/$cname"
    WDIR="$OUTPUT/work_$cname"
    mkdir -p "$CDIR" "$WDIR"

    # Create symlinks for this chunk
    rm -f "$CDIR"/*.llbc
    ls "$INPUT"/*.llbc | sort | tail -n +$((c*CHUNK_SIZE+1)) | head -n $CHUNK_SIZE | while read f; do
        ln -sf "$f" "$CDIR/$(basename $f)"
    done

    # Run interface_generator from working directory
    cd "$WDIR"
    if timeout 600 "$BIN" --verbose-level=4 "$CDIR" > log 2>&1; then
        sigs=0
        if [ -f "$WDIR/kernel_signature_full" ]; then
            sigs=$(wc -l < "$WDIR/kernel_signature_full")
        fi
        echo "done $cname ($sigs sigs)"
        all_sigs=$((all_sigs + sigs))
    else
        rc=$?
        echo "FAILED $cname (exit=$rc)" >&2
        failed_chunks="$failed_chunks $cname"
        n_failed=$((n_failed + 1))
    fi
done

echo ""
echo "=== Results ==="
echo "Total signatures: $all_sigs"
if [ -n "$failed_chunks" ]; then
    echo "Failed chunks: $n_failed"
    echo "Failed:$failed_chunks"
fi

# Merge all signatures
MERGED="$OUTPUT/kernel_signature_full"
MERGED_INFO="$OUTPUT/kernel_signature_with_info_full"
> "$MERGED"
> "$MERGED_INFO"
for c in $(seq 0 $((CHUNKS-1))); do
    cname=$(printf "chunk_%03d" $c)
    WDIR="$OUTPUT/work_$cname"
    if [ -f "$WDIR/kernel_signature_full" ] && [ -s "$WDIR/kernel_signature_full" ]; then
        cat "$WDIR/kernel_signature_full" >> "$MERGED"
    fi
    if [ -f "$WDIR/kernel_signature_with_info_full" ] && [ -s "$WDIR/kernel_signature_with_info_full" ]; then
        cat "$WDIR/kernel_signature_with_info_full" >> "$MERGED_INFO"
    fi
done
echo "Merged signatures: $(wc -l < "$MERGED")"
