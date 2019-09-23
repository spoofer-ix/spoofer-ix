### Project overview:

**Note:** these codes require real equipments to function properly.

In order to improve the precision of results with the periodic changes in the IXP switching-fabric infrastructure
together with the IXP operators we developed an automation step to periodically pool all the network devices for its
current configurations.     

Generally the IXPs coordinators seek to work with only one manufacturer to ease the process of keeping the network working smoothly. 
However, this scenario does not hold anymore if you work with more complex infrastrucutures like IXPs. With that in mind we study ways
to work with a variety of manufactures and soft security requirements to connect to all equipments, extract and parse the
data needed to build our mappings periodically. Pre-requisites were: do not change any configuration in the devices to make it possible
and do not leverage on closed APIs provided by the vendors. 


![Extract data configuration from network devices](../../../docs/images/mac2asn-switches-query-configs.png)

###  How do I get set up?

The scripts are Python 2.7 compatible.

The key requirements are the following Python libraries (they will be installed by *requirements.txt*):

  * requests
  * netmiko
  * ntc_templates

**Netmiko** is a multi-vendor library to simplify Paramiko SSH connections to network devices.

**ntc_templates** is a repository of TextFSM Templates for Network Devices, and Python wrapper for TextFSM's CliTable.

**TextFSM** is a project built by Google that takes CLI string output and passes each line through a series of regular 
expressions until it finds a match. The regular expressions use named capture groups to build a text table out of the 
significant text. The names of the capture groups are used as column headers, and the captured values are stored as 
rows in the table.

#### Python Netmiko API documentation online:
https://ktbyers.github.io/netmiko/docs/netmiko/

#### TextFSM templates for parsing show commands of network devices
https://github.com/networktocode/ntc-templates
