## Analysis over resulting Cones datasets definitions 

Run analysis over the resulting Cone datasets computed by the Cones inference algorithms.
They allow to execute diff operations, compute the fraction of total address space attributed to each ASN, and
output annotated version of the results to dig in individual cases to a better understanding of the impact of 
the results.  

* `data-analysis/cones-inferences-analysis/ixpmembers_compute_cones_diff_internetwide.py`

    Given two distinct Cone datasets computes the fraction of the absolute and relative IP address space per ASN considering the different Cones datasets (ppdc-prefix).

