#!/usr/bin/env python
# -*- coding: utf-8 -*-

import utils.constants as cons
import gzip
import csv

"""
https://www.caida.org/data/as-classification/

Classifier features
We use the following features for each AS in the training and validation set.

1) Customer, provider and peer degrees: We obtain the number of customers, providers and peers (at the AS-level) 
using CAIDA's AS-rank data.

2) Size of customer cone in number of ASes: We obtain the size of an AS' customer cone using CAIDA's AS-rank data.

3) Size of the IPv4 address space advertised by that AS. We obtain this quantity using BGP routing tables collected 
from Routeviews.

4) Number of domains from the Alexa top 1 million list hosted by the AS. We obtain the list of top 1 million websites 
from Alexa, perform DNS lookups on each domain (at CAIDA) and map each returned IP address to the corresponding ASN 
using longest-prefix matching using a routing table from Routeviews. We then count the number of domains hosted by 
each AS.

5) Fraction of an AS's advertised space that is seen as active in the UCSD Network Telescope.


Source	        description
------------------------------------------------------------------------------------------------
CAIDA_class	    Classification was an inference from the machine-learning classifier
peerDB_class	AS classification was obtained directly from the PeeringDB database

Class	            description
------------------------------------------------------------------------------------------------
Transit / Access	ASes which was inferred to be either a transit and/or access provider.
Content	            ASes which provide content hosting and distribution systems.
Enterprise	        Various organizations, universities and companies at the network edge 
                    that are mostly users, rather than providers of Internet access, transit or content.
"""


def build_dicts_as2type_caida_mapping(s_dataset_epoch):
    """
    The AS classification dataset contains the business type associated with each AS.

    File format: <AS>|<Source>|<Class>

    :return:
    """
    d_as2type_data = dict()

    with gzip.open(cons.DEFAULT_AS2TYPE_CAIDA_MAPPING[s_dataset_epoch], 'rb') as as2type_data:
        reader = csv.reader(as2type_data, delimiter='|')

        for line in reader:

            if "#" not in line[0]:
                i_asn = int(line[0])
                s_source = line[1]
                s_class = line[2]

                d_as2type_data[i_asn] = [s_source, s_class]

    return d_as2type_data


def do_classtype_lookup_as2type(asn_query, d_as2type_data):
    """
    Execute lookup into CAIDA as2type and return Org type.
    """
    return d_as2type_data[asn_query][1]
