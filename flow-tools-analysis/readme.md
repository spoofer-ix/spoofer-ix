## Flow Analysis Tools


#### General Flow Analysis Tools
* `flow-tools-analysis/flows-wrapper.py`  
    Wrapper to read compressed NFDUMP *.gz files via a similar interface.
    NFDUMP does not have support to read natively compressed files, so we develop this wrapper to
    facilitate some basic/repetitive operations via command line.
    
    * *Input*: traffic flow data files format *.gz*.
    * *Output*: traffic flow data reading to human-readable format.


```
# List possible arguments to script
python flows-wrapper.py -h

# read (-R), aggregate (-a) and filtering (-f) over a given set of files
python flows-wrapper.py -R nfcapd.20171126* -a -f /datadrive-slow/bogon-bn-agg.txt

# read one file (-r), aggregate (-a), export output to a csv file (-o csv)
python flows-wrapper.py -r nfcapd.201711260015.gz -a -o csv

# processing/analysis using pipe/bash all together
python flows-wrapper.py -r nfcapd.201711260015.gz -o csv | cut -d',' -f4,5 | less
```

#### Traffic Classification Pipeline Analysis
* `flow-tools-analysis/illegitimate_traffic_classification.py`
    
    Implements the Traffic Classification Pipeline taking as input all the datasets prepared to perform the 
    traffic classification following the input parameters defined by the user.
    
    It's important to note that the classification pipeline leverage on many different datasets which are loaded into
    memory to speedup the classification processing. That been said, it is fundamental that the user execute the scripts
    created to optimize the datasets used as input to obtain the same performance results.
    
    The code allow the user to personalize almost everything right in the script call through the specific 
    parameters defined. For more information, execute with `--help`. 

Syntax example:        
```
python flow-tools-analysis/illegitimate_traffic_classification.py -tw 201905010800-201905010800 -filter "{'ip': 4}" -tmpdir /mnt/tmp/ -flowdir /root/spoofer-ix/data/flow-data-demo/ -c 3 -fut "[0,1,1,1,0,1,1,1]" -ccid 8 -gcf 0 -coneases data/input/customer-cone-data/ipv4/may19/per-week/demo/20190501.7days.midnightRIB.ppdc-ases-DEMO.txt.bz2 -coneprefix data/input/customer-cone-data/ipv4/may19/per-week/demo/20190501.7days.midnightRIB.ppdc-prefix-DEMO.txt.bz2 > out_classif.log
```    

#### Flow Data Processing Analysis to Compute Traffic Behavior Metrics
* `flow-tools-analysis/gen_data_input_flows_behavior_metrics.py`

    Read Apache Avro traffic flow data files and generate the transformations + aggregations of unique sets of data 
    in 5-min bin. It can read and generate the output information computed taking as input all traffic data or 
    the traffic classification results, i.e, per classes (bogon, unassigned, unverifiable, incone, outofcone).
    
    * Input: traffic flow data files format *.avro*.
    * Output: export traffic flow information transformed and aggregated for post-processing.
    * It saves all the unique ingress point, IP Addresses per 5-min bin, the BGP Prefix, ORIGIN ASN of the prefix; 
    country of the /24 prefix, and count the number of occurrences for each IP Address.
  
* `flow-tools-analysis/compute_flow_data_behavior_metrics.py`

    Consumes the transformed and aggregated data exported in 5-min bins from the 
    script `gen_data_input_flows_behavior_metrics.py` and then compute
    different metrics and generate input files for plots.

    It is fundamental to remember the execution pipeline of data transformation till the execution of the current code.
    To compute the metric results the following execution order is expected:

    1. `illegitimate_traffic_classification.py`. 
    Remember to enable the param to save raw classification results for post-processing for metrics analysis.
    2. `gen_data_input_flows_behavior_metrics.py`
    3. `compute_flow_data_behavior_metrics.py`

#### Zoom-in Over Flow Data Analysis
* `flow-tools-analysis/raw_flow_read_analysis.py`
    
    Once spotted an atypical behavior on traffic flow data it will be necessary to go back to flow data and apply some
    extra operations to extract the particular data of interest allowing to perform over it some additional analysis 
    and evaluations. With this goal in mind we developed this auxiliary script to filter and extract annotated flow 
    data.
    
    The input data at this point are the Apache Avro files generated after the Classification Pipeline Processing.
    With that the user can choose which traffic class desires to investigate and extract data to further analysis.     

Syntax call examples:    
```
python flow-tools-analysis/raw_flow_read_analysis.py \
    -tw 201704220710-201704221300 \
    -filter "{'ip': 4}" \
    -tmpdir /datadrive-fast/temp/eval/ \
    -flowdir /datadrive-fast/temp/IXP-flows/ \
    -cat 3 -g5min 0 -fdir 0

python flow-tools-analysis/raw_flow_read_analysis.py \
    -tw 201704240710-201704241300 \
    -filter "{'ip': 4}" \
    -tmpdir /datadrive-fast/temp/eval/ \
    -flowdir /datadrive-fast/temp/IXP-flows/ \
    -cat 3 -g5min 0 \
    -lips /datadrive-fast/temp/raw-activitychurn-data.201704210000-201704282355.IPs-gained=src.agglevel=1.class=outofcone.txt \
    -fdir 0

python flow-tools-analysis/raw_flow_read_analysis.py \
    -tw 201704220710-201704221300 \
    -filter "{'ip': 4, 'dmac': '4CF95D990C0B'}" \
    -tmpdir /datadrive-fast/temp/eval/ \
    -flowdir /datadrive-fast/temp/IXP-flows/ \
    -cat 3 -g5min 0 -fdir 0
```    
