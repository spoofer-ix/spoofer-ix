#!/bin/bash
################################################################################################
# Instructions to use the script
# script must be executed from the data/data-download/bgp_routing_collectors/ dir level.
#
# nohup sh data/data-download/bgp_routing_collectors/down-bgp-data.sh FULLPATH_TO_DIR_TO_SAVE_FILES RUN_MODE > /datadrive-fast/temp/log_BGPdata_download.txt &
################################################################################################

DIR_TO_SAVE_FILES=$1
RUN_MODE=$2

########
# Download a batch of files per link one at a time
########

if [[ $RUN_MODE = 1 ]]
then
    # download RIPE RIS data in background
    nohup sh -c 'for line in $(cat ../input/links-ripe.txt); do scrapy crawl bot_getbgp_rawdata -a url=$line -a page='ripe' -a bgpdirdata=$DIR_TO_SAVE_FILES --loglevel ERROR; done' &

    # download Routeviews data in background
    nohup sh -c 'for line in $(cat ../input/links-rv.txt); do scrapy crawl bot_getbgp_rawdata -a url=$line -a page='routeviews' -a bgpdirdata=$DIR_TO_SAVE_FILES --loglevel ERROR; done' &
fi

########
# Enables the request for all links concurrently
########

if [[ $RUN_MODE = 2 ]]
then
    # RIPE RIS
    i=0
    for line in $(cat ../input/links-ripe.txt); do i=$((i+ 1)); nohup scrapy crawl bot_getbgp_rawdata -a url=$line -a page='ripe' -a bgpdirdata=$DIR_TO_SAVE_FILES -a datelimit='20190604' --loglevel ERROR > log_ripe_link_$i.txt & done

    # Routeviews
    i=0
    for line in $(cat ../input/links-rv.txt); do i=$((i+ 1)); nohup scrapy crawl bot_getbgp_rawdata -a url=$line -a page='routeviews' -a bgpdirdata=$DIR_TO_SAVE_FILES -a datelimit='20190604' --loglevel ERROR> log_routeviews_link_$i.txt & done
fi