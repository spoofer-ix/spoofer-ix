###  Project Overview

This repo contains all the key components discussed in our paper **Challenges in Inferring Spoofed Traffic at IXPs**, CoNEXT 2019. We strive to make available the artifacts source code and documentation, respecting all NDA agreements, thus enabling reproducibility of our work within distinct IXPs.

* The scripts were written in Python 2.7, Python 3.7, Perl 5, and Bash.
* Developed on macOS Mojave (Version 10.14.5), and guaranteed execution over Linux Ubuntu 16.04/18.04 Stable distributions.
* The requirements.txt file lists the libraries required to run Python scripts.
* Large files are managed using git-lfs, thus required (instructions below).
   * tracked patterns: *.pdf; *.png; *.gz; *.bz2 (check the definitions in .gitattributes file at project root dir)
* The memory requirements to execute the project varies greatly between components. The bare minimum you need to start is 16GB RAM, however, note that you will need more to work with different components (minimum recommended 64GB RAM, 64 cores). The project setup can also easily be done in cloud providers such as Microsoft Azure, Amazon AWS, Google Cloud.

### How the project is organized
All the key directories contain an explanation of its contents to help navigate through the project.

As a principle throughout the documentation of this project, we avoid stale/duplicate information.
E.g., script parameters can change periodically, according to analysis needs, so we do not aim to explain each one of the possible parameters and all its combinations. A explanation of parameters already exists in the code (use `--help`).

Below you find the list of 1st level directories arranged alphabetically with a description of their contents.
```
.
├── asrel-customer-cone: AS-relationship, Customer Cones inferences.
|
├── data-analysis: mostly used to save data input/output from analysis, which are used to 
|                  produce new analysis and other intermediate data files. Include code to explore
|                  analysis over cone results files.
|
├── data: gather demo datasets to illustrate format, in addition to others utilized in filtering 
|         and correlation operations. Include scripts to extract data from devices and download 
|         public BGP data.
|
├── docs: content in use for documentation purposes. 
|
├── flow-conversion: contains code to convert flow capture traces files to Apache Avro.
|
├── flow-tools-analysis: contains code responsible for traffic classification, metrics computation 
|                        and raw flow analysis. 
|
├── fullcone-imc17: shared part of the source codebase from Franziska et al.; IMC 2017
|                   (https://gitlab.inet.tu-berlin.de/thorben/transitive_closure_cone)
|                   (https://conferences.sigcomm.org/imc/2017/papers/imc17-final24.pdf).
|
├── schemas: designed Apache Avro schemas required to data flow serialization.
|
├── traffic-analysis-utilities: code to perform specific analysis over the traffic flow data categories. 
|
├── utilities: helper utilities to setup project into a Ubuntu Server. 
|
└── utils: diverse set of code utilities to handle datasets manipulations, notification system, data
           conversion, data multiprocessing, etc. 
```

## How do I get set up?

There are two basic ways you can setup your project environment:

1. **Automatic setup (fresh Ubuntu 16.04/18.04 LTS).** Use our provided Bash helper script to install and configure most of the dependencies of the project, enabling to use it out-of-the-box. 

2. **Personalized setup.** Go over the detailed instructions below and set up your env with personalized configurations as you may wish.

*If you are getting started, we strongly advise using option 1 in a fresh Ubuntu 16.04/18.04 LTS*. The fresh SO requirement is essential because otherwise in already existing envs will be necessary for you to check for existing softwares conflicts to potentially avoid breaking dependencies of other existing projects. 

### Automatic setup (Ubuntu 16.04/18.04 LTS):
    > Note: by following the automatic setup you shouldn't clone the repo, but instead only copy the 
    shell script `setup-project-local-env.sh` (indicated below), which will clone the repo as part of 
    its process, as well as configure the necessary dependencies.
1) as root user do;
2) copy and paste the file/code from `utilities/localenv-helper-scripts/setup-project-local-env.sh` under a working dir of your choice. In this documentation we use: `/root` dir.
3) execute it: `sh setup-project-local-env.sh`

### Personalized setup:
In the personalized setup we suggest you to create a virtual environment using pyenv (check the install instructions at https://github.com/pyenv/pyenv) and virtualenv (https://virtualenv.pypa.io/en/latest/installation/). This adds an isolation to the libraries which will be installed in your env.

```
$ pyenv local 2.7.6
$ virtualenv .
$ source bin/activate
```

Below are the instructions to manually install the project requirements.

#### Git Large File Storage (LFS)
This project requires the open source Git extension for versioning large files 
(https://git-lfs.github.com/ and https://github.com/git-lfs/git-lfs/wiki/Installation).

**MacOS >= Mojave**
   1. Homebrew: `brew install git-lfs` or MacPorts: `port install git-lfs`
   2. At the end: `git lfs install`

**Ubuntu >= 16.04 (need to have git >= 1.8.2)**
   1. `sudo apt-get install software-properties-common` to install add-apt-repository
   2. `sudo add-apt-repository ppa:git-core/ppa`
   3. The curl script below calls `apt-get update`, if you aren't using it, don't forget to call `apt-get update` before installing git-lfs.
   4. `curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash`
   5. `sudo apt-get install git-lfs`
   6. `git lfs install`

* Repo size (*last update: Sep 22 2019*): ~180MB

* If your goal is to clone only the code base and keep large files in lfs system cache, do the following:
```
GIT_LFS_SKIP_SMUDGE=1 git clone https://github.com/spoofer-ix/spoofer-ix.git
```

* In case you change your mind and wants to download all lfs system files locally, execute:
```
git lfs fetch --all
```

#### Set of external tools and libraries

1. Install nfdump: https://github.com/phaag/nfdump

nfdump is a toolset in order to collect and process netflow and sflow data, sent from netflow/sflow 
compatible devices. The toolset supports netflow v1, v5/v7,v9, IPFIX and SFLOW. nfdump supports IPv4 as well as IPv6.

* This tool allows one to open/work with the original flow data traffic collected. 
* The script `flows-wrapper.py` require it installed to work properly.
  * Ubuntu: 
`sudo apt-get install nfdump`
  * MacOS: 
 `brew install nfdump`    

2. Download and install Apache Avro 1.8.2 (1.9.0 is also compatible): 

website: http://www.apache.org/dyn/closer.cgi/avro/

```
$ tar xvf avro-1.8.2.tar.gz
$ cd avro-1.8.2
$ sudo python setup.py install
```

3. Install Google Snappy C library: https://github.com/google/snappy
  * Ubuntu: 
`sudo apt-get install libsnappy-dev`
  * MacOS: 
`brew install snappy`

The Snappy C library is needed when the codec "snappy" is set to serialize/deserialize files using Apache Avro.

4. To run data analysis which perform IP Addresses geo location our code base supports MaxMind Geolite2 (free) and 
NetAcuity Edge (requires license). The system default is currently employing NetAcuity Edge and for that it requires to 
install the `CAIDA libipmeta` and `CAIDA pyIpmeta` projects (only authorized personel due to NetAcuity Edge licensing). However, we also provide a fallback code which uses MaxMind Geolite2 API/databases (API installed by default if you follow the instructions; the datasets you may need to look for the ones you need).
    > Note that the usage of the distinct geolocation APIs -- Netacuity vs. Maxmind -- may cause some differences in the results. Small variations may appear in Figure 11 of our results. As we used the country level geolocation, we do not expect many differences between the two databases at this level.

5. Sendgrid's (https://app.sendgrid.com, create a free account) email notification system. 
Update your development environment with your SENDGRID_API_KEY. Run the following in your shell:
```
echo "export SENDGRID_API_KEY='YOUR_API_KEY'" >> **PROFILE-FILE-PATH**
source **PROFILE-FILE-PATH**
```
*Obs.: to set environment variables permanently edit and save them in your: ~/.profile or /etc/profile*

If you decide to skip this step be aware that you will receive a warning at the end of execution of some of the codes, indicating the failed attempt to send the notification of the execution. 

6. Install Python project requirements:

```
python -m pip install --upgrade pip setuptools wheel
cd spoofer-ix/
pip install -r requirements.txt
```

7. Install Perl project requirements:

```
cpan -i install Net::Patricia
cpan -i install Parallel::ForkManager
```
 
#### Check your installation using our demo datasets

In additional to our codebase, we also provide some datasets (note, via Git-lfs) to enable you to check your installation, as well as, to have an idea of how the files are organized, layouts, etc.

To check your installation run the following commands to execute a traffic classification demo:
1) go to project root directory: `cd spoofer-ix/`;
2) then copy/past the following command line:
```
python flow-tools-analysis/illegitimate_traffic_classification.py -tw 201905010800-201905010800 -filter "{'ip': 4}" -tmpdir /mnt/tmp/ -flowdir /root/spoofer-ix/data/flow-data-demo/ -c 3 -fut "[0,1,1,1,0,1,1,1]" -ccid 8 -gcf 0 -coneases data/input/customer-cone-data/ipv4/may19/per-week/demo/20190501.7days.midnightRIB.ppdc-ases-DEMO.txt.bz2 -coneprefix data/input/customer-cone-data/ipv4/may19/per-week/demo/20190501.7days.midnightRIB.ppdc-prefix-DEMO.txt.bz2 > out_classif.log
```

*Note:* we assume you have the project sitting under `/root/spoofer-ix/` so in case this is not true you must change path parameters accordingly to make it work.


Below the illustration of Spoofer-IX key components to help guide the understanding and navigation in our repo.
![Spoofer-IX high-level overview.](/docs/images/high-level-overview-components-spooferix-stagesdelimited.png)

With this project, traffic flow data, BGP data, and the others datasets cited in this documentation, you can:
1. Prepare required datasets (flows, BGP data, dataset mappings).
2. Execute cone build methods (create Prefix-Level Customer Cones, Full Cones).
3. Classify traffic flow data.
4. Correlate, explore, and annotate results.
5. Analyze traffic flow data.

###  Getting help
You can always send an email. Please include the following information in the message:
   * What are you trying to do
   * Screen shots, output messages
   * Which datasets are you using
   * Operating system

###  Contact
Lucas F. Müller (lfmuller@inf.ufrgs.br)


###  License
CAIDA, UC San Diego & INF/UFRGS

Licensed under either of these:
 
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
