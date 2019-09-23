#### NOTE: All these are historical scripts. DO NOT USE without reading, understanding and MODIFYING to suit your needs
==================================================================================================================

This is most of the code we used to analyze data that we discussed in our paper [Detection, Classification, and Analysis of Inter-Domain Traffic with Spoofed Source IP Addresses](https://conferences.sigcomm.org/imc/2017/papers/imc17-final24.pdf)

We release this code under the [CRAPL](http://matt.might.net/articles/crapl/), which explicitly states:

   > Any appearance of design in the Program is purely coincidental and
    should not in any way be mistaken for evidence of thoughtful
    software construction.


Some hints
==========

In this README, I have collected and listed the main scripts that do the majority of the work. Their order is roughly in order of importance, the less useful scripts are further down

All scripts except build_cone.py are in the ./bin directory

There are some further usage examples in the example directory. There is also a second README there, which goes into further detail.

build_cone.py
=============
CORE tool, has a minimal CLI

loads data that has been extracted from bgp dumps via secondary scripts, builds the cone structure in RAM to be dumpend (pickled) and exported

Is loaded by our actual classification tools on the flowbox. The code is rather simple

CLI usage
---------

 - `zpairs <filename>.gz` loads a gzipped file containing AS-path-derived pairs in the form of `AS1 AS2` into a graph structure. For each pair, a directed link is added between the left and the right AS number. NOTE: works best with sorted input
 - `zprefixes <filename>.gz` loads a gzipped file containing a list of prefixes per AS in the form of `ASn: 10.0.0.0/24,10.1.0.0/24` into an existing graph structure. Calling this BEFORE calling zpairs results in UNDEFINED behaviour (i.e., probably won't work, so don't do it)
 - `cone AS1` prints a list of all ASNs in the cone of AS1
 - `cones <filename>.gz` dumps the cone for each AS in the graph into a gzipped txt file
 - `24subnets <filename>.gz` dumps a list of every possible /24 subnet along with the respective ASes in the graph that have each subnet in their cone
 - `origins <filename>.gz` dumps every entry in the prefix trie along with the associated ASNs into a gzipped file. Results in a list of ASes that is equivalent to what is expected by the `zprefixes` command, just inverted.
 - `pickle <filename>.gz` dumps the cone memory state into a gzipped file (i.e., serializes) NOTE: this can take a very long time
 - `load <filename>.gz` loads a pickled cone memory state file for further work (ie., deserializes)
 - `shell <command>` passes a command to an underlying shell


bgpdump
=======
the tool by ripencc to convert a raw binary bgp dump to human readable ASCII. Download it yourself and potentially build it from source if this binary does not work on your machine. See https://bitbucket.org/ripencc/bgpdump/wiki/Home


gzipped_prefixes_pairs_from_stdin.py
====================================
reads bgpdump output on stdin and generates `pairs`, `prefixes` and (contrary to the filename) `paths`. This script has a lot of hardcoded parameters that may need further abstraction to become generally useful.

It uses the first argument as a `<filename>` for gzipped files in the `pairs`, `paths` and `prefixes` directories if those are not already present. It then fills each of those with parsed data from the bgpdump like so

 * `pairs/<filename>.gz` contains pairwise adjacent ASNs that were seen on an AS path
 * `prefixes/<filename>.gz` contains the set of all prefixes that were seen for a given origin AS
 * `paths/<filename>.gz` contains the set of all ASes that were on the path for a given prefix

parallelized_pairs_prefixes_paths.sh
================================================
takes a date range such as `20170201 20170228` as argument and then calls a bunch of helper scripts, including (indirectly) `gzipped_prefixes_pairs_from_stdin.py` above to process all the data found on this machine in certain hardcoded folders.


gzipped_prefixes_pairs_from_stdin_filterpaths.py
================================================
same as `gzipped_prefixes_pairs_from_stdin.py`, only some ASes are dropped from consideration.

make_pairs_prefixes_paths.sh
============================
not meant to be called directly, takes a bunch of arguments to find the right files to call bgpdump on and pipe to `gzipped_prefixes_pairs_from_stdin.py`


make_pairs_prefixes_paths_filterpaths.sh
========================================
see above, only for `gzipped_prefixes_pairs_from_stdin_filterpaths.py`


breakup_sets.py
===============
once used to break up AS sets and form a full mesh. not sure if used anymore
reads lines from stdin. for lines contining curly braces, do the following:

input line:
{a,b} c

output:
a c
b c


weeks.sh
========
legacy script that would collect pairs, prefixes and paths for all weeks in a hardcoded time frame (february 2017)


fix_paths.py
============
unifies multiple lines with same prefix. used to unify prefixes announced by given AS. Input needs to be sorted by AS (0, 1 and 2 in the example) to work properly

```
echo -e "0: 1\n1: 2,3,4\n1: 4,5,6,7\n2: 8,9" | python3 bin/fix_paths.py
0: 1
1: 6,3,2,4,5,7
2: 8,9
```


fix_prefixes.py
===============
resolves AS sets ({1,2} in the example) and unifies the sets of prefixes accross AS sets. requires sorted input (like above). If called with already resolved AS sets, it further unifies like so:

```
echo -e "0: 192.168.0.0\n1: 2.0.0.0,4.0.0.0\n{1,2}: 2.0.0.0,3.0.0.0,4.0.0.0" | python3 bin/fix_prefixes.py | python3 bin/fix_prefixes.py
0: 192.168.0.0
1: 3.0.0.0,4.0.0.0,2.0.0.0
2: 3.0.0.0,4.0.0.0,2.0.0.0
```

parallelized_pairs_prefixes_paths_filterpaths.sh
====================================
same as `parallelized_pairs_prefixes_paths.sh`, only some ASes are dropped from consideration. Not really important


precalc_day.sh
==============
old legacy script that interacted with build_cone.py to create files for a single given day. only useful as reference potentially


weeks_2017-02.sh
================
script that generated all data for february 2017, some cheap parallelization, useful as reference maybe


week_2016-02-01.sh
==================
script that was used to generate data for one week in february 2017, maybe useful as reference
