#!/usr/bin/env python
# -*- coding: utf-8 -*-

import jsonlines
import utils.constants as cons
import utils.as2org_dataset_utilities as as2orgutil


def build_dict_mapping_known_sibling_ases_crafted():
    """
    Build the mapping dict cache to sibling ASNs.
    :return:
    """

    fn_mapping_input_jsonl = cons.DEFAULT_BRAZIL_SIBLING_ASES_MAPPING

    d_sibling_ases = dict()
    with jsonlines.open(fn_mapping_input_jsonl) as reader:
        for obj in reader:
            asn = int(obj['asn'])
            asname = obj['asname']
            org_id = obj['org_id']

            if asn not in d_sibling_ases:
                d_sibling_ases[asn] = [asname, org_id]

    return d_sibling_ases


def build_dict_mapping_caidaas2org_with_local_siblings(s_as2org_epoch_input):
    """
    Build a unified view of CAIDA AS2ORG SIBLINGS with the additional local IXP members mapping dataset.
    :param s_as2org_epoch_input: year-id which defines the CAIDA AS2ORG dataset to be loaded.
    :return: unified dict[ASN] = [ASN_NAME, ORG_STRING_LABEL]
    """

    # load CAIDA AS2ORG dataset
    d_mapping_org_data, d_mapping_as_data = as2orgutil.build_dicts_as2org_caida_mapping(s_as2org_epoch_input)

    # load local siblings mapping dataset, format: d[asn] = [asname, org_id]
    d_sibling_ases_combined = build_dict_mapping_known_sibling_ases_crafted()

    # create unified output
    for i_asn, v_org_label in d_mapping_as_data.iteritems():

        if i_asn not in d_sibling_ases_combined:

            if v_org_label in d_mapping_org_data:
                asn_name = d_mapping_org_data[v_org_label][0]
            else:
                print "CAIDA AS2ORG inconsistency: ASN {} - does not have a org label entry " \
                      "in the Organization fields: {}".format(i_asn, v_org_label)

            d_sibling_ases_combined[i_asn] = [asn_name, v_org_label]

    print ("Number of entries in d_sibling_ases_combined: {}".format(len(d_sibling_ases_combined)))

    return d_sibling_ases_combined
