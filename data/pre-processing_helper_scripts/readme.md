##  Pre-processing Helper Scripts

This folder presents a diverse set of helper scripts.
They range from preparing the datasets (e.g. remove information that is irrelevant in a given moment in order to be 
enable improved time/memory consumption to execute heavy processing) to data extraction from the IXP switching fabric.

### General scripts:

* `switches-data-extract-automation`: project to automate data extraction of devices from IXP switching fabrics (go inside for more details).

* `create-prefix-aggregated-levelcone-datafiles.py`
    
    Given an prefix-level cone dataset as input computes the aggregated prefix-level cone definition dataset.

    Output format: ASN prefix/size prefix/size prefix/size ...    

* `create_db_router_ips_from_midar_iff_ifaces_dataset.py`

   Generate the smallest dataset by aggregating Router IPs into prefixes.


### Extract subset datasets with only data from the IXP members:

* `create-customercone-datafiles-ixp-members.py`

    Allow to generate the `ppdc-ases` subset file for a given IXP. To generate the `ppdc-prefixes` subset file for a given IXP you just change the `-ccf` (Customer Cone file) input to be the `ppdc-prefixes`. In the case of `ppdc-prefixes` subset dataset there's the `-c` parameter to aggregate the prefixes to the small set possible. 
This is fundamental to allow post-processing over the prefixes data.

* `create-fullcone-datafiles-ixp-members.py`

    The same way as the above, it creates the IMC'17 Full Cone subset data files with only with data from the IXP Members which the traffic will be analyzed (aiming to reduce data in memory during traffic classification).
     
Order of execution to build the IXP members cones dataset files:
    
* **Complete Prefixes Full Cone files (equivalent to PPDC-prefixes from CAIDA Customer Cone)**
    ##### *Note*: to create the prefixes subset dataset it requires a large ammout of memory (more than 64 GB), so instead of doing it only in memory it will start writing the results as soon as they are available to improved the overall performance and processing power requirements.
    
1. Build the `ASes_subset=` and `prefixes_subset=` dataset files using the script (by default it will get the members defined in the constant path to mac2asn mapping). When executing the script to generate the subset of the datasets for a different IXP it's necessary to point-out the file that describes the members of the IXP. 

```
python data/pre-processing_helper_scripts/create-fullcone-datafiles-ixp-members.py \
 -odir /root/ -ccf raw_cones_day_2019-05-01.gz \
 -prefixes prefixes_2019-05-01.gz \
 -macf ixp-members-example.txt \
 -lixp "Example-IXP" -c 1
``` 

2. Multi-Organization (Siblings) Full Cone datasets.

    1. Build the `Full Cone ASes siblings dataset` and `Full Cone AS-prefixes dataset` using the `data/pre-processing_helper_scripts/create-fullcone-datafiles-ixp-members.py` command. Note: each call requires close to ~20GB.

    2. After, to be able to load in memory the `Full Cone AS-prefixes` datasets, you will need first to aggregate the prefixes in each ASN cone, otherwise you can not operate with this cone properly in memory. To achive that run over each one of the dataset the following code `data/pre-processing_helper_scripts/create-prefix-aggregated-levelcone-datafiles.py`. *Important*: you need to unzip the Full Cones before execute the script below, this is a restriction on Python to read chunk of lines and sending them to be multiprocessed (gzip or bz2 files does not offer such support in Python).


#### Steps when preparing distinct IMC'17 Full Cone datasets to evaluate stability over traffic classification

1. Follow official orientation to run Full Cone source code with distinct parameters on input BGP time range and save output files (at least *raw_cones* and *prefixes* files).
2. Use the raw_cones and prefixes output files as input to extract the slice of the ones needed, i.e., the members at the IXP in analysis.
3. Aggregate the resulting cone prefixes to better/faster in memory manipulation.
4. Lastly, execute the traffic classification with each one of the created cones.
5. Analyse the results.
