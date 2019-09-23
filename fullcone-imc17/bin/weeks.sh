#!/usr/bin/env bash

set -o pipefail

PAIRS="./pairs"
PREFIXES="./prefixes"
PATHS="./paths"
PYTHON="/usr/bin/python"
FIXPAIRS="bin/breakup_sets.py"
FIXPREFS="bin/fix_prefixes.py"
FIXPATHS="bin/fix_paths.py"

mkpairs() {
    OUT="${PAIRS}/${1}.gz"
    for I in $@
    do
	# if we haven't generated the pairsfile yet or if we have a sourcefile that's newer than the aggregate
	if [ ! -f $OUT ] || [ $(find $PAIRS -cnewer $OUT -type f -name "*-${I}.gz" | wc -l) != 0 ]
	then
	    for I in $@
	    do
		find $PAIRS -name "*-${I}.gz" | xargs zcat || exit 1
	    done | sort -t' ' -k1 -n -S8G | uniq | $PYTHON $FIXPAIRS | sort -t' ' -k1 -n -S8G | uniq | gzip > $OUT.tmp && mv -v $OUT.tmp $OUT
	    # break out of the outer loop, since we've processed everything
	    break
	fi
    done
}

mkprefixes() {
    OUT="${PREFIXES}/${1}.gz"
    for I in $@
    do
	if [ ! -f $OUT ] || [ $(find $PREFIXES -cnewer $OUT -type f -name "*-${I}.gz" | wc -l) != 0 ]
	then
	    for I in $@
	    do
		find $PREFIXES -name "*-${I}.gz" | xargs zcat || exit 1
	    done | sort -t':' -k1 -n -S8G | uniq | $PYTHON $FIXPREFS | sort -t':' -k1 -n -S8G | uniq | $PYTHON $FIXPREFS | gzip > $OUT.tmp && mv -v $OUT.tmp $OUT
	    break
	fi
    done
}


mkpaths() {
    OUT="${PATHS}/${1}.gz"
    for I in $@
    do
	if [ ! -f $OUT ] || [ $(find $PATHS -cnewer $OUT -type f -name "*-${I}.gz" | wc -l) != 0 ]
	then
	    for I in $@
	    do
		find $PATHS -name "*-${I}.gz" | xargs zcat || exit 1
	    done | sort -t':' -k1 -n -S8G | uniq | $PYTHON $FIXPATHS | gzip > $OUT.tmp && mv -v $OUT.tmp $OUT
	    break
	fi
    done
}




mkpairs week_2017-02-06 $(seq 20170205 20170213) &
mkprefixes week_2017-02-06 $(seq 20170205 20170213) & 
mkpaths week_2017-02-06 $(seq 20170205 20170213) &

mkpairs week_2017-02-13 $(seq 20170212 20170220) &
mkprefixes week_2017-02-13 $(seq 20170212 20170220) &
mkpaths week_2017-02-13 $(seq 20170212 20170220) &

mkpairs week_2017-02-20 $(seq 20170219 20170227) &
mkprefixes week_2017-02-20 $(seq 20170219 20170227) &
mkpaths week_2017-02-20 $(seq 20170219 20170227) &

mkpairs week_2017-02-27 $(seq 20170226 20170228) $(seq 20170301 20170306) &
mkprefixes week_2017-02-27 $(seq 20170226 20170228) $(seq 20170301 20170306) &
mkpaths week_2017-02-27 $(seq 20170226 20170228) $(seq 20170301 20170306) &

wait
