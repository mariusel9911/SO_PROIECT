#!/bin/bash

# Verifică dacă există un argument în linia de comandă
if [ $# -eq 0 ]; then
    echo "Nu s-a furnizat niciun argument."
    exit 1
fi

# Numele fișierului de căutat
file="$1"

# Caută cuvintele în fișier
if grep -q -E 'corrupted|dangerous|risk|attack|malware|malicious' "$file" || grep -q -P '[^\x00-\x7F]' "$file"; then
    #echo "problem"
    exit 1
else
    #echo "ok"
    exit 0
fi
