#!/usr/bin/env python
# -*- coding: utf-8 -*-

import utils.constants as cons
import gzip
import csv


def build_dicts_as2org_caida_mapping(s_dataset_epoch):
    """
    Build the dicts to map the information to extract the name of a given ASN.

    The as2org files contain two different types of entries: AS numbers and
    organizations.  The two data types are divided by lines that start with
    '# format....'. An example can be found below.

    # format: aut|changed|name|org_id|source
    1|20120224|LVLT-1|LVLT-ARIN|ARIN
    # format: org_id|changed|name|country|source
    LVLT-ARIN|20120130|Level 3 Communications, Inc.|US|ARIN

    ----------
    AS fields
    ----------
    aut     : the AS number
    changed : the changed date provided by its WHOIS entry
    name    : the name provide for the individual AS number
    org_id  : maps to an organization entry
    source  : the RIR or NIR database which was contained this entry

    --------------------
    Organization fields
    --------------------
    org_id  : unique ID for the given organization
               some will be created by the WHOIS entry and others will be
               created by our scripts
    changed : the changed date provided by its WHOIS entry
    name    : name could be selected from the AUT entry tied to the
               organization, the AUT entry with the largest customer cone,
              listed for the organization (if there existed an stand alone
               organization), or a human maintained file.
    country : some WHOIS provide as a individual field. In other cases
               we inferred it from the addresses
    source  : the RIR or NIR database which was contained this entry

    :return: d_org_data{aut} = org_id
             d_as_data{org_id} = [name, country]
    """
    # d{aut} = org_id
    d_as_data = dict()

    # d{org_id} = [name, country]
    d_org_data = dict()

    header_as_data = "# format:aut"
    enable_read_as_data = False

    header_org_data = "# format:org_id"
    enable_read_org_data = False

    with gzip.open(cons.DEFAULT_AS2ORG_CAIDA_MAPPING[s_dataset_epoch], 'rb') as as2org_data:
        reader = csv.reader(as2org_data, delimiter='|')

        for line in reader:
            if header_org_data in line:
                enable_read_org_data = True

            if header_as_data in line:
                enable_read_as_data = True
                enable_read_org_data = False

            if enable_read_org_data and "#" not in line[0]:
                org_id = line[0]
                name = line[2]
                country = line[3]

                d_org_data[org_id] = [name, country]

            if enable_read_as_data and "#" not in line[0]:
                aut = int(line[0])
                org_id = line[3]
                d_as_data[aut] = org_id

    return d_org_data, d_as_data


def do_lookup_as2org(asn_query, d_mapping_as_data, d_mapping_org_data):
    """
    Execute lookup into CAIDA as2org and return Org Name.
    :param asn_query:
    :param d_mapping_as_data:
    :param d_mapping_org_data:
    :return:
    """

    if (asn_query is not 'UNKNOWN') and (asn_query in d_mapping_as_data):
        if d_mapping_as_data[asn_query] in d_mapping_org_data:
            asn_name = d_mapping_org_data[d_mapping_as_data[asn_query]][0]
        else:
            asn_name = None
    else:
        asn_name = None

    return asn_name
