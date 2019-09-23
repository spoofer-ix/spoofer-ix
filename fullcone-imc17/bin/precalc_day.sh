#!/bin/bash
set -o pipefail

PYTHON=/usr/bin/python3
FIXPAIRS=./bin/breakup_sets.py
FIXPREFIXES=./bin/fix_prefixes.py
FIXPATHS=./bin/fix_paths.py

build_cone() {
    DATE=$1
    PICKLE="pickle/${DATE}.gz"
    PAIRS="pairs/${DATE}.gz"
    PREFIXES="prefixes/${DATE}.gz"
    PATHS="paths/${DATE}.gz"
    TODO=0
    # DISABLED trie for paths
    if [ ! -f $PICKLE ] || [ $(find 'pairs/' 'prefixes/' 'paths/' -cnewer $PICKLE -type f -name "*${DATE}.gz" | wc -l) != 0 ]
    #if [ ! -f $PICKLE ] || [ $(find 'pairs/' 'prefixes/' -cnewer $PICKLE -type f -name "*${DATE}.gz" | wc -l) != 0 ]
    then

	if [ ! -f $PAIRS ]
	then
	    for P in $(find 'pairs/' -type f -name "*${DATE}.gz" | sort)
	    do
		zcat $P || exit 1
		#echo $pairs
	    done | nice sort -n -t' ' -k1 -S8G | uniq | $PYTHON $FIXPAIRS | nice gzip > ${PAIRS}.tmp && mv -v ${PAIRS}.tmp ${PAIRS}
	fi
	echo "zpairs ${PAIRS}" &
	if [ ! -f $PREFIXES ]
	then
	    for P in $(find 'prefixes/' -type f -name "*${DATE}*.gz" | sort)
	    do
		zcat $P || exit 1
		#echo $prefixes
	    done | nice sort -n -t':' -k1 -S8G | uniq | $PYTHON $FIXPREFIXES | nice sort -t':' -k1 -n -S8G | uniq | $PYTHON $FIXPREFIXES | nice gzip > ${PREFIXES}.tmp && mv -v ${PREFIXES}.tmp ${PREFIXES}
	fi
	echo "zprefixes ${PREFIXES}" &
	#DISABLED trie for paths
	if [ ! -f $PATHS ]
	then
	    for P in $(find 'paths/' -type f -name "*${DATE}*.gz" | sort)
	    do
		zcat $P || exit 1
		#echo $paths
	    done | nice sort -n -t':' -k1 -S8G | uniq | $PYTHON $FIXPATHS | nice gzip > ${PATHS}.tmp && mv -v ${PATHS}.tmp ${PATHS}
	fi
	wait
	echo "zpaths ${PATHS}"
	echo "pickle $PICKLE"
	echo "exit"
	#mv -v $PICKLE.tmp $PICKLE
    fi
}

DATE=$1
build_cone $DATE #| nice python3 build_cone2.py >/dev/null


