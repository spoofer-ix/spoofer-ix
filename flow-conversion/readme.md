## Traffic Flow Data Conversion Tools

The Traffic Classification Pipeline, as well as, the distinct analysis are base on Apache Avro files converted from
Sflow/NetFlow/IPFIX capture files managed with NFDUMP. The code base assumes that the traffic capture files are generated
in **5-min time intervals** (total of 288 files per day -- 24h * 12 files per hour), i.e., *if you have a different 
situation you must revise the methods and adapt them to your time-window of data collection*.

### Conversion Pipeline from NFDUMP traffic capture files to Apache Avro files

The execution of the script below must be executed from the project root directory (spoofer-ix/). 

* `flow-conversion/conversion_wrapper_nfpcap_to_avro.py`  
Wrapper to convert source NFDUMP nfcap `*.gz` files to Apache Avro for post-processing and analysis.

    * *Input*: combination of parameters to define the tasks to be executed, for more details execute with `--help`.   
    * *Output*: files converted in an output directory defined by the user.

    **Take care on the number of concurrent processors employed `-np` due to memory usage by the NFDUMP binary when exporting 
    to intermediate CSV format, unless your machine has significant free memory to use. Otherwise, files may end corrupted.**

E.g.: 
```
nohup python flow-conversion/conversion_wrapper_nfpcap_to_avro.py \
    -tw 201706010000-201706082355 \
    -tmpdir /datadrive-fast/temp/export/ \
    -flowdir /datadrive-fast/temp/IXP1-flows/ \
    -s schemas/nfcapd-shrink.avsc \
    -np 20 -w 3 -log info  > out_classif.log&
```


### Auxiliary scripts on conversion/reading files in distinct formats
* `flow-conversion/serialize_csv_toavro.py`

    Reads a CSV file containing flow records and outputs in AVRO format.  
    * Input: **.csv**
    * Output: **.avro**

```
Syntax: python serialize_csv_toavro.py <path-to-csv-input-file-to-be-transformed> <path-to-output-avro-file>

python serialize_csv_toavro.py /datadrive-fast/temp/nfexport.201711071530.csv /datadrive-fast/temp/nfexport.201711071530.avro
```
