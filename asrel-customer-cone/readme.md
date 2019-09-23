###  How do I get set up?

1. Project dependencies 

* RIPENCC BGPdump

Download, compile and install from source code:

```
wget https://bitbucket.org/ripencc/bgpdump/get/99da8741c8c8.zip
unzip 99da8741c8c8.zip
mv ripencc-bgpdump-99da8741c8c8 ripencc-bgpdump
cd ripencc-bgpdump
sh ./bootstrap.sh
make
cd ..
rm -rf 99da8741c8c8.zip
```

* Install Perl libs dependencies:

```
perl -MCPAN -e shell
install Net::Patricia
```

To use `--forks=` install Perl `Parallel::ForkManager`
```
# perl -MCPAN -e shell
# install Parallel::ForkManager
```

2. Update or create a symlink to bgpdump in the `bin` directory:

Assuming that you have installed `ripencc-bgpdump` at `/root` will be:

```
# ln -sf /root/ripencc-bgpdump/bgpdump bgpdump
```

3. *General reminder*: the scripts calls several utilities: `bzip2`, `gzcat`, `bzcat` and `bgpdump` via **symbolic links**.

    * `gzcat` is called `zcat` on some systems (so symlink as `gzcat` if necessary).  
    * `bzip2` is hardcoded as `pbzip2`. If this does not exist, create a symlink `pbzip2` pointing to `bzip2`. 

**The script does not check for the presence of these utilities, so make sure they are available ahead of time.**


##  How to run it?

#### To run the serial-1 you would need:

1. `asrank-download.pl`: it can download the raw RIBS and run the AS relationship inference.

`--get-ribs` downloads the RIB files; 
by default grabs 5 days of files (if user don't inform --days param), but this can be changed with the --days keyword. 
To give a sense of storage requirements: ~65GB is required to download 1-week of raw 
RIBS from a good number of BGP monitors from RIPE RIS and Routeviews.

`--bgp-infer` does the AS relationship inference. The first step `asrank.pl` produces the
`as-rel.txt` file; if that is all you need you can skip the customer cone inference.

> Command line examples:

Instructs to download and run AS relationship inference from 20170420 (inclusive) to 20170427 (7 days).
```
# perl asrank-download.pl --days=7 20170420
```

If you need to download only:
```
# perl asrank-download.pl --download-only --days=7 20170420
```

If you have the files and want to only run the AS relationship inference:
```
# perl asrank-download.pl --rib-paths-only --days=7 20170420
```

2. `build-paths-all.pl`: generates the `*.all-paths.bz2` from all the sub `*paths` files generated from each raw RIB.

```
# perl build-paths-all.pl /root/asrank-tools/as-relationships/toolshed/bin/20170420 | bzip2 - > /root/asrank-tools/as-relationships/toolshed/bin/20170420/20170420.all-paths.bz2
```

### Building Prefix-Level Customer Cone datasets:

1. Steps:
    1. revise local dependencies of CAIDA Customer Cone code.
    2. organize and download BGP data from RIPE RIS and Routeviews (we provide a scraper, as well as, a native wget alternative).
    3. prepare the BGP data to CAIDA Customer Cone expected organization format.
    4. execute CAIDA Customer Cone and wait for its results.
    5. using the output from CAIDA Customer Cone, execute and prepare the Prefix-Level Customer Cone
    
    It is also possible to create a Bash Helper Script and automate the process of preparing automatically a set of Prefix-Level Customer Cones.

Dependencies Prefix-Level Customer Cone:

* `dump-customercone-prefixlevelCC.pl` (requires Perl Module - `reserved.pm` located in the same folder.) 

It generates the **CAIDA Customer Cone Prefix-Level** using data computed in the original dataset of CAIDA Customer Cone. 
It builds a Prefix-level Customer Cone that takes the CAIDA Customer Cone `ppdc-ases` and a `prefix2as` files as input.
    
```
perl dump-customercone-prefixlevelCC.pl data/input/customer-cone-data/ipv4/20170501.ppdc-ases.txt.bz2 data/input/customer-cone-data/ipv4/20170501.prefix2as.bz2 > 20170501.ppdc-prefix-level-cone.txt
```
