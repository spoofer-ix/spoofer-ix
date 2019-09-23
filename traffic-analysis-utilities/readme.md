## Traffic Analysis Tools

The scripts in this folder aim to dive in traffic behavior and properties analysis.
They explore the original flow captures, as well as, the classification categories.  

* `explore_traffic_features.py`

Process classified traffic flow data, cutting, aggregating, and annotating data to export traffic proprieties 
for the different categories analysis.

* `export_members_presence_into_categories.py`

Process traffic flow data classified to identify the IXP members which appear in each one of the different 
categories (Bogon, Unassigned, Out-of-Cone, Unverifiable, In-cone).

* `raw_flow_trafficprops_analysis.py`

Process traffic flow data collected, performing slice and dice operations. Export protocol 
(transport, application layers) traffic proprieties in bins for the different categories with annotations to further
investigation of traffic behaviors and who is involved in the exchange.

