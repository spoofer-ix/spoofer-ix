#!/usr/bin/env bash

set -o pipefail

PAIRS="./pairs"
PREFIXES="./prefixes"
PATHS="./paths"
ORIGINS="./origins"
PICKLE="./pickle"
RAW="./raw_cones"
PYTHON="/usr/bin/python3"
FIXPAIRS="bin/breakup_sets.py"
FIXPREFS="bin/fix_prefixes.py"
FIXPATHS="bin/fix_paths.py"
CONESCRIPT="build_cone.py"

echoerr() {
    echo "$@" 1>&2
    exit 1
}

mkpairs() {
    OUT="${PAIRS}/${1}.gz"
    shift
    for I in $@
    do
	# if we haven't generated the pairsfile yet or if we have a sourcefile that's newer than the aggregate
	if [ ! -f $OUT ] || [ $(find $PAIRS -cnewer $OUT -type f -name "*-${I}.gz" | wc -l) != 0 ]
	then
	    for I in $@
	    do
		find $PAIRS -name "*-${I}.gz" | xargs zcat || echoerr $I  #exit 1
	    done | sort -t' ' -k1 -n -S25G | uniq | $PYTHON $FIXPAIRS | sort -t' ' -k1 -n -S25G | uniq | gzip > $OUT.tmp && mv -v $OUT.tmp $OUT
	    # break out of the outer loop, since we've processed everything
	    break
	fi
    done
}

mkprefixes() {
    OUT="${PREFIXES}/${1}.gz"
    shift
    for I in $@
    do
	if [ ! -f $OUT ] || [ $(find $PREFIXES -cnewer $OUT -type f -name "*-${I}.gz" | wc -l) != 0 ]
	then
	    for I in $@
	    do
		find $PREFIXES -name "*-${I}.gz" | xargs zcat || echoerr $I #exit 1
	    done | sort -t':' -k1 -n -S25G | uniq | $PYTHON $FIXPREFS | sort -t':' -k1 -n -S25G | uniq | $PYTHON $FIXPREFS | gzip > $OUT.tmp && mv -v $OUT.tmp $OUT
	    break
	fi
    done
}


mkpaths() {
    OUT="${PATHS}/${1}.gz"
    shift
    for I in $@
    do
	if [ ! -f $OUT ] || [ $(find $PATHS -cnewer $OUT -type f -name "*-${I}.gz" | wc -l) != 0 ]
	then
	    for I in $@
	    do
		find $PATHS -name "*-${I}.gz" | xargs zcat || echoerr $I #exit 1
	    done | sort -n -t':' -k1 -S96G --parallel=20 | uniq | $PYTHON $FIXPATHS | gzip > $OUT.tmp && mv -v $OUT.tmp $OUT
	    break
	fi
    done
}


mkweek() {
    WEEK=${1}
    shift
    mkpairs $WEEK $@
    mkprefixes $WEEK $@
    #mkpaths $WEEK $@ &
    wait && echo -e "zpairs ${PAIRS}/${WEEK}.gz\nzprefixes ${PREFIXES}/${WEEK}.gz\npickle ${PICKLE}/${WEEK}.gz\ncones ${RAW}/${WEEK}.gz\norigins ${ORIGINS}/${WEEK}.gz" | $PYTHON $CONESCRIPT 
}


mkweek week_2016-02-01 $(seq 20160201 20160208) &

wait
