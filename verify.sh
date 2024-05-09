#!/bin/bash

# Verifică dacă există un argument în linia de comandă
if [ $# -eq 0 ]; then
    echo "Nu s-a furnizat niciun argument."
    exit -1
fi

# Numele fișierului de căutat
file="$1"

# ii dam permisiuni ca sa il putem verifica
chmod 777 "$file"

# Utilizam wc pentru a număra linii, caractere și cuvinte în fișier
# și memoram rezultatele în variabile

counts=$(wc "$file")
lines=$(echo "$counts" | awk '{print $1}')
words=$(echo "$counts" | awk '{print $2}')
characters=$(echo "$counts" | awk '{print $3}')

#echo "Numărul de linii: $lines"
#echo "Numărul de cuvinte: $words"
#echo "Numărul de caractere: $characters"

#Testam conditii de fiser malitios - Criteriu I

if [ "$lines" -le 3 ] && [ "$words" -gt 1000 ] && [ "$charcters" -gt 2000 ]; then
    echo -n "$1"
    chmod 444 "$file"
    exit 1
fi

# Caută cuvintele în fișier - Criteriu II

if grep -q -E 'corrupted|dangerous|risk|attack|malware|malicious' "$file" || grep -q -P '[^\x00-\x7F]' "$file"; then
    chmod 444 "$file"
    echo -n "$1"
    exit 1
else
    chmod 444 "$file"
    echo -n "SAFE"
    exit 0
fi
