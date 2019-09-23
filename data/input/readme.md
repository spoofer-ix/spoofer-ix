## Input Datasets Applied to Analysis

**Note:** the only purpose of making this set of datasets available is to demonstrate the code, its organization and allow others to see the layout of the datasets. You will note the "-DEMO" string in their names, reinforcing the warning that the *data inside is not real, i.e., the only purpose is to use in the project demonstration*.

| Data Directory | Description |
| :--- | :--- |
| **ITDK-ifaces-routers** | CAIDA ITDK data IP ranges associated with routers interfaces [4]. |
| **as-organizations** | CAIDA AS Organizations Dataset[1] mapping Autonmous Systems (AS) to the their Organizations (Org). |
| **as2types** | CAIDA AS business type classification dataset [3].|
| **asn-lookup-db** | Built offline lookup databases based on RIB archives. More info PyASN [2].|
| **asn-types-mapping** | Mapping files that describes the classification of a given set of members to its business category. |
| **bogon-prefixes-list** | Team Cymru’s Bogons list IPv4 and IPv6 validated by checking IETF RFCs definitions. |
| **customer-cone-data** | Customer Cone datasets definitions based on different executions of the inference algorithm. |
| **geolocation-db** | Maxmind Lite 2 (free) and NetAcuity (commercial) IP geo-location databases. |
| **macaddress-asn-list** | IXP switches mapped MAC addresses to ASes (Mac2ASN database). |
| **prefix-to-label-mappings** | Set of Bogon prefixes group by categories. |
| **unassigned-prefixes-list** | Historical Team Cymru’s Fullbogons feed files updated every 4 hours. |
| **vlans-remote-peering** | VLANs ids in use by members to remote peering connections. |


#### Create prefix to ASN lookup db files (asn-lookup-db)

* Download from RouteViews

IPASN data files can be created by downloading MRT/RIB BGP archives from Routeviews (or similar sources), 
and parsing them using the provided scripts through the pyasn package that tail the BGP AS-Path. 
This can be done simply as follows:

```
pyasn_util_download.py --dates-from-file data/input/asn-lookup-db/dates-to-download-routeviews-pfx2as.txt
pyasn_util_download.py --latest
pyasn_util_convert.py --single <Downloaded RIB File> <ipasn_db_file_name>
```


**References**

[1] CAIDA AS Organizations Dataset, https://www.caida.org/data/as-organizations/

[2] https://github.com/hadiasghari/pyasn

[3] AS Classification, https://www.caida.org/data/as-classification/

[4] Macroscopic Internet Topology Data Kit (ITDK), http://www.caida.org/data/internet-topology-data-kit/
