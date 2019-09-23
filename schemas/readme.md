## Conversion Schemas -- from flow capture files to Apache Avro
In order to operate with the flow traces manipulation we convert the Sflow/Netflow/IPFIX CAP raw files to Apache Avro. 
This allow us to improve manipulation of traffic flow data without losing the required data compression to store very large number of files over time.

*  `schemas/nfcapd.avsc` -- convert all fields that have value.


*  `schemas/nfcapd-shrink.avsc` -- convert a subset of all fields. Only the essential for the purpose of traffic 
classification processing.
