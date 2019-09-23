This is a very basic example for working with the cone code, broken down into simple steps
==========================================================================================

Step 1: Extract the relevant data from a bgp dump
-------------------------------------------------

There is a sample dump file (example_dump.gz) in the ./data directory. Let's parse it but (for now) only consider the first 3 lines.
 
    # bgpdump -m data/example_dump.gz | head -n 3

should give you

    TABLE_DUMP2|1485907200|B|178.255.145.243|50304|0.0.0.0/0|50304 42708|IGP|178.255.145.243|0|0||NAG||
    TABLE_DUMP2|1485907200|B|212.25.27.44|8758|0.0.0.0/0|8758 6830|IGP|212.25.27.44|0|0|8758:110 8758:300|NAG||
    TABLE_DUMP2|1485907200|B|12.0.1.63|7018|1.0.4.0/24|7018 174 4826 38803 56203|IGP|12.0.1.63|0|0|7018:5000 7018:37232|NAG||


The first two lines are unusable for us (they are announcements of basically the entire internet). To filter such lines, we can (for now) use the following simple approach:

    # bgpdump -m example_dump.gz | grep -v "0.0.0.0/0" | head -n 3
    
This gives:

    TABLE_DUMP2|1485907200|B|12.0.1.63|7018|1.0.4.0/24|7018 174 4826 38803 56203|IGP|12.0.1.63|0|0|7018:5000 7018:37232|NAG||
    TABLE_DUMP2|1485907200|B|146.228.1.3|1836|1.0.4.0/24|1836 6939 4826 38803 56203|IGP|146.228.1.3|0|0|1836:110 1836:3000 1836:3020|NAG||
    TABLE_DUMP2|1485907200|B|79.143.241.12|29608|1.0.4.0/24|29608 6939 4826 38803 56203|IGP|79.143.241.12|0|11|29608:40090|NAG||

(Do `man grep` and look up the documentation of the `-v` parameter if you are unsure how the filter works)


Step 2: Process the AS path data into AS pairs, a format readable by the cone script
------------------------------------------------------------------------------------

Let's take the first line:

    TABLE_DUMP2|1485907200|B|12.0.1.63|7018|1.0.4.0/24|7018 174 4826 38803 56203|IGP|12.0.1.63|0|0|7018:5000 7018:37232|NAG||

Look up the bgpdump text format and understand what each of the fields (delimited by "|") do. For now we only interested in the AS path. It should be obvious that in this case this equals to

    7018 174 4826 38803 56203

.

As we have mentioned in the general README, the cone script derives the AS graph from a list of directed AS pairs. So we need to split the AS path into such pairs. We have to turn

    7018 174 4826 38803 56203

into

    7018 174
    174 4826
    4826 38803
    38803 56203

to satisfy that requirement. This output would already be usable by the cone script, if it was sorted according to the lefthand AS and written to a file and that file was conpressed using gzip. (More on that in Step 4 below.)


Step 3: Process prefix and origin into a format readable by the cone script
---------------------------------------------------------------------------

Let's again take the first line:

    TABLE_DUMP2|1485907200|B|12.0.1.63|7018|1.0.4.0/24|7018 174 4826 38803 56203|IGP|12.0.1.63|0|0|7018:5000 7018:37232|NAG||

From this, we extract the origin AS and the announced prefix,

    56203

and

    1.0.4.0/24

respectively.

We have to create a list where in each line, all prefixes for a given origin AS are listed. Based on the single line above, this is trivial:

    56203: 1.0.4.0/24

However, in reality, the AS is announcing more than that single prefix. Based on the full example dump file, that entry would look more like this (within context of some of the other processed origin ASes:

    7720: 203.29.88.0/24,203.33.252.0/24,203.33.253.0/24,203.18.240.0/24
    56303: 103.2.176.0/24,103.2.177.0/24,1.0.4.0/24,1.0.5.0/24,1.0.6.0/24
    49920: 185.149.60.0/22

As should be obvious, the entire bgpdump needs to be parsed into a suitable data structure before this list is generated. Again, a gzip compressed text file like this is already usable by the cone script.


Step 4: Actually efficiently generating all of the above
--------------------------------------------------------

Having understood the general outline about how data is to be processed for the purposes of the cone script, we can now do this practically.

In the general README, look up the script "gzipped_prefixes_pairs_from_stdin.py", which (among other things) does this when fed with bgpdump output. Feel free to copy that script and adjust it to your workflow or write your own. A slightly modified copy of the script is already present in this directory.

The script reads a parsed bgpdump from stdin and generates gzipped versions of the lists we discussed above. The general usage is:

    python3 gzipped_prefixes_pairs_from_stdin.py <filename>

To test this example, call it like this:

    # bgpdump -m data/example_dump.gz | python3 ./gzipped_prefixes_pairs_from_stdin.py just_testing

The run will finish after about 2 minutes. It will do all the filtering for you and handle even corner cases such as AS sets. Afterwards, you will find the gzipped lists based on the example dump file under the name "just_testing.gz" in the subdirectories "./pairs" and "./prefixes" respectively. 

    # zcat pairs/just_testing.gz | head -n 3

will show you

    6700 56816
    15566 15566
    44608 44608
    
and

    # zcat pairs/just_testing.gz | head -n 3

will give

    395578: 209.12.72.0/24
    55194: 129.1.158.0/24,129.1.159.0/24,129.1.0.0/16
    25845: 192.152.45.0/24,204.147.208.0/20,204.147.220.0/22

.

NOTE that the AS pairs file should be further processed before feeding it to the cone script. See Step 5 below!


Step 5: Feeding the cone script with the generated data
-------------------------------------------------------

The cone script is employing various optimizations that make interacting with it a bit tricky, especially since it does very little checking of (the correct order of) input. It is strongly advisable to read the build_cone.py section from the general README. Some points to keep in mind:

  * it can fail ungracefully given faulty input
  * the ordering of command issue is important, first you have to load a pairs file and second the origins file. doing it the other way around will result in undefined behavior even if it might not actually crash
  * some commands can take a very long time to complete
  * most commands can only meaningfully be executed _once_
  * entering empty commands can result in a crash, especially during execution
  * some data has to be preprocessed (i.e., sorted) in order for the optimizations to work

For all these reasons it is advisable to interact with the cone script via piping a carefully prepared commands from a text file (or script) into it.

An important point to note is that the pairs file needs to be sorted in order to leverage the various optimizations for building the AS graph. This can easily be done like so:

    # zcat pairs/just_testing.gz | sort -n | gzip > pairs/just_testing_sorted.gz

Now we can finally start generating a cone. In order to do this, we write our commands for the cone script into a file. (For documentation about the available commands, see the "CLI usage" section in the general README.) The file contents will probably look something like this:

    zpairs pairs/just_testing_sorted.gz
    zprefixes prefixes/just_testing.gz
    cones just_testing_cones.gz

Using this, we call the cone script like so

    # cat commands.txt | python3 ../build_cone.py

On a full dump, you will now have to wait a really long time. Up to multiple hours. What you could do as an example is only use part of a bgpdump. For testing I did the following:

    # bgpdump -m data/example_dump.gz | head -n 100000 | python3 gzipped_prefixes_pairs_from_stdin.py example

This basically prunes the bgpdump to the first 100k entries and generates pairs and prefixes based on this. Note however, that the gzipped_prefixes_pairs_from_stdin.py script won't overwrite existing files, so make sure to either delete the old ones or use a new filename pattern. Pay attention to what you are doing.

Once your run finished, you now have a finished cone under "just_testing_cones.gz" in this directory. The file format is as follows:

    ASNa ASNx ASNy ASNz

Here, the first ASN (ASNa) is the AS in question and all subsequent entries (ASNx ASNy ASNz) on that line are all the ASes in the "cone" of the AS.

See the following files for examples of what we discussed here:

  * "pairs/example_sorted.gz" for a sorted pairs list based on a pruned bgpdump as mentioned above
  * "prefixes/example.gz" for an origin-prefix list over that same pruned data
  * "example_cone_commands.txt" for the commands I used to generate this example
  * "example_cones.gz" for the resulting cone file based on that example


Final remarks
-------------

If you want to process bgp data from multiple files (e.g., in order to process data from multible route collectors or an entire week), take a look at the general README. The merging of bgpdump output has to be done _before_ feeding data to the cone script, because the latter can ONLY meaningfully read one pairs or prefix file at a time due to various optimizations. I can particularly recommend reading the documentation (and code) of "parallelized_pairs_prefixes_paths.sh". But it is fine to write your own scripts in order to do this. Just make sure that you unify (and sort!) data from multiple sources before feeding it to the cone script.


