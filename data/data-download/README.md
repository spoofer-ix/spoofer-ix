## How the directory is organized

* `bgp_routing_collectors`

Spider crawler to scrape and download BGP files from RIPE RIS and Routeviews public project collectors. More instructions on how to run it below.

* `input`

Text files with links of BGP route collectors which are used to download BGP data, different formats due the two methods CAIDA Customer Cone and Full Cone.

* `peeringdb`

Script to export useful PeeringDB data information regarding IXP route servers, lan prefixes and colocation facilities ASes. Leverages PeeringDB official API.


### How to run the spider (bgp_routing_collectors)
Scraper to download raw BGP snapshot files from RIPE RIS and Routeviews public project collectors (more can be added, e.g., PHC, Project Isolario).
The raw files are used as input to compute the Customer Cone and Full Cone datasets. 
By default it will download the RIBs and Update files available at all BGP collectors from each of the two projects.
Also the code is already prepared to handle timeout operations when trying to download the files and respect the limits
of each project server.

##### Dependencies
* Python 3
* Python Scrapy (https://scrapy.org/)


##### Install instructions

> MacOS 

```
pip3 install scrapy --upgrade --ignore-installed six
pip3 install service_identity
```
* Scrapy installation guide, platform specifics: https://doc.scrapy.org/en/latest/intro/install.html


#### Execution
1. **IMPORTANT**: To put the spider to work go to the project’s top level 
directory (where is located the `data/data-download/bgp_routing_collectors/scrapy.cfg` file) and run it.

Syntax
```
scrapy crawl bot_getbgp_rawdata  -a url=‘$url’ -a page=‘$page' -a bgpdirdata='dir-to-save-downloaded-data'
```

Extract the links to download the data from Routeviews and RIPE RIS public BGP routing collectors.
```
scrapy crawl bot_getbgp_rawdata -a url='http://archive.routeviews.org/bgpdata/2017.05/UPDATES/' -a page='routeviews' -a bgpdirdata='/datadrive-fast/temp/mycontainer-bgp' --loglevel ERROR
scrapy crawl bot_getbgp_rawdata -a url='http://data.ris.ripe.net/rrc15/2017.05/' -a page='ripe' -a bgpdirdata='/datadrive-fast/temp/mycontainer-bgp'--loglevel ERROR
```

#### Automated execution via Bash Script
You can automate the processing by doing the following:
1. First create two files, one for each BGP Project containing the links for the periods you need data to be downloaded.
2. Execute the call to the Bash script that by levering these files will download the required data. 

```
nano links-ripe.txt
nano links-rv.txt
nohup sh down-bgp-data.sh> out_log_download.txt &
```

One can think on an alternative solution by using a Bash call using `wget`. 
Once created the input files containing the links to download the files type in the command line:

```
cat _FILE_.txt | xargs -n 1 -P 15 wget > /dev/null 2>&1
```
create N wget processes, each downloading one URL at the time. 

-n 1 will make xargs run command (wget) with only one argument at the time
-P 15 will create 15 parallel processes

#### Bash line can help to solve cases where Scrapy download failed due to timeout via the following command:
```
grep "ERROR: Error downloading" log_ripe_link_18.txt | cut -d' ' -f8 | sed 's/.$//' | xargs -n 1 -P 15 wget -q -4 -nv -P /datadrive/ripe/rrc21/2019.05/ > /dev/null 2>&1
```


#### Azure Storage file manipulation

Install AzCopy on Linux

1. Download AzCopy

`wget https://aka.ms/downloadazcopy-v10-linux`
 
2. Expand Archive

`tar -xvf downloadazcopy-v10-linux`
 
3. (Optional) Remove existing AzCopy version

`sudo rm /usr/bin/azcopy`
 
4. Move AzCopy to the destination you want to store it

`sudo cp ./azcopy_linux_amd64_*/azcopy /usr/bin/`

Once installed, use the command line with your SAS-token (can be generated via web interface) to transfer/manipulate data to/from your storage lakes.

You can get more info about large-scale data manipulation parameters in MS Azure in the following links:

https://docs.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-blobs

https://docs.microsoft.com/en-us/azure/storage/common/storage-dotnet-shared-access-signature-part-1

https://docs.microsoft.com/en-us/azure/vs-azure-tools-storage-explorer-blobs
