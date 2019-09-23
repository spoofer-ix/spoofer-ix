#!/bin/bash
#set -o pipefail

PREPARESCRIPT=./bin/make_pairs_prefixes_paths.sh
#PREPARESCRIPT=echo
#CONESCRIPT=./bin/precalc_day.sh
SOURCEDIR="/path/to/data/"

ORGS=$(ls -F $SOURCEDIR | grep -E "/$" | sed -e 's/.$//')
LOGFILE=/tmp/log/parallelized-$1-$2-$(date +%s).log
#LOGFILE=/dev/stderr


for DATE in $(seq $1 $2)
do
    for ORG in $ORGS
    do
	RRCS=$(ls $SOURCEDIR/$ORG)
	for RRC in $RRCS
	do
    	    for FLAG in "-v" ""
	    do
		echo $PREPARESCRIPT $DATE $ORG $RRC $FLAG
	    done
	done
    done
	#echo $CONESCRIPT $DATE
done | xargs -d'\n' -n 1 -P 32 bash -c 2>> $LOGFILE

#for DATE in $(seq $1 $2)
#do
#    echo $CONESCRIPT $DATE
#done | xargs -d '\n' -n1 -P 16 bash -c 2>> $LOGFILE
