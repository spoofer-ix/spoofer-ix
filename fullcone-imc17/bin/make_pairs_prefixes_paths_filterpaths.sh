#!/bin/bash
set -o pipefail

BGPDUMP=./bin/bgpdump
SCRIPT=./bin/gzipped_prefixes_pairs_from_stdin_filterpaths.py
BGPLOG=~/tmp/log/bgpdumps-filterpaths-$(date +%s)-${$}.log
SOURCEDIR=/path/to/data/dir
PYTHON=/usr/bin/python3

#SOURCEDIR="/mnt/data/florian/rawdata/"


ORGS=$(ls -F $SOURCEDIR | grep -E "/$" | sed -e 's/.$//')

DATE=$1
ORG=$2
RRC=$3
FLAG=$4
TMP=$(ls ${SOURCEDIR}/${ORG}/${RRC}/*/*.${DATE}.* | grep $FLAG "update" | head -n 1)
if [ -z $TMP ]
then
    exit 0
fi
UPDATE=$(echo $TMP | grep "update" >/dev/null && echo "-updates")
OUT="$(echo $TMP | grep -Eo '(ripe|routeviews)')-${RRC}${UPDATE}-${DATE}"
if [ ! -f "pairs_filterpaths/$OUT.gz" ] || [ $(find "${SOURCEDIR}/${ORG}/${RRC}" -cnewer "pairs/$OUT.gz" -type f -name "*${DATE}.*" | wc -l) != 0 ] || [ ! -f "prefixes/${OUT}.gz" ] || [ ! -f "paths/${OUT}.gz" ]
then
    for INFILE in $(ls ${SOURCEDIR}/${ORG}/${RRC}/*/*.${DATE}.* | grep $FLAG "update")
    do
	#echo "working on $INFILE" >> $LOGFILE
	if ! nice $BGPDUMP -v -m $INFILE 2>> $BGPLOG
	then
	    echo "bgpdump failed for $INFILE ($OUT)" >> $BGPLOG
	    exit 255
	fi
    done | nice $PYTHON $SCRIPT $OUT || exit 255
else
    echo "nothing to do for $OUT" 1>&2
fi

if [ ! -s $BGPLOG ]
then
    rm -v $BGPLOG
fi
