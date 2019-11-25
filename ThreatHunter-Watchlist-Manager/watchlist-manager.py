#!/usr/bin/env python3

# Threat Hunter Watchlist Creator
# Copyright VMware 2019
# November 2019
# Version 0.1
# gfoss [at] carbonblack . com
#
#    usage: watchlist-manager.py [-h] [-o ORGKEY] [-p ORGPROFILE] [-w WATCHLIST_NAME] [-c CBR_QUERY] [-d DELETE_QUERY]
#
#    Parse Threat Hunter YAMLs and Create / Update Watchlists
#
#    optional arguments:
#    -h, --help            show this help message and exit
#    -p ORGPROFILE, --profile ORGPROFILE
#                            Select your cbapi credential profile
#    -w WATCHLIST_NAME, --watchlist WATCHLIST_NAME
#                            Watchlist to create. Options: [customizable]
#    -c CBR_QUERY, --convert CBR_QUERY
#                            Convert CB Response query to Threat Hunter format. Eg: (-c <query>)
#    -d DELETE_QUERY, --delete DELETE_QUERY
#                            Delete a watchlist via query. Eg: (-d <query>)


import os, sys, argparse, requests, json, yaml, time, pprint
from cbapi.psc.threathunter import *

# Import logging module to see the requests to the REST API
# import logging
# logging.basicConfig()
# logging.getLogger("cbapi").setLevel(logging.DEBUG)


# All Watchlists correspond to their local directory and must be specified below to be included in updates
def manage_watchlists(parser,args,watchlist_name):

    global yml_path
    global feed_name
    global provider_url
    global feed_summary
    global feed_category
    global feed_id_name

    # ====================================================================================================
    # Custom Watchlist
    # ====================================================================================================
    if watchlist_name == "custom":
        yml_path = './watchlists/example/'
        feed_name = "Custom Watchlist"
        provider_url = "https://carbonblack.com"
        feed_summary = "Custom Threat Detections"
        feed_category = "Custom"
        feed_id_name = "custom_report"
    
    # ====================================================================================================
    # Add other watchlists below via elif...
    # ====================================================================================================
    else:
        print(' [ ! ] Error: Watchlist (-w) must be defined...')
        print('     Available option is [custom]')


def threaty_threats(parser,args,orgprofile,watchlist_name):

    # This is the 'name' of your credential in the credential file. Set with -o at runtime.
    th = CbThreatHunterAPI(profile="{}".format(orgprofile))
    orgkey = th.credentials.org_key
    
    # Create JSON Framework
    json_data = {}
    i = 0
    json_data['feedinfo'] = {"name": feed_name, "provider_url": provider_url, "summary": feed_summary, "category": feed_category}
    json_data['reports'] = []
    yml_extensions = (".yml", ".yaml")
    print('')
    print(' [ * ] Parsing YAMLS and creating ({}) Watchlist'.format(feed_name))

    # Parse the YAMLs and populate JSON
    for root, dirs, yam in os.walk(os.path.abspath(yml_path)):
        for yamyam in yam:
            if yamyam.endswith(yml_extensions):
                i+=1
                filename = os.path.join(root, yamyam)
                #print(filename)
                #yamyams = open(yml_path+'/AMSI-WMI-Event-Consumer.yml', 'r')
                yamyams = open(filename, 'r')
                try:
                    much_wow = yaml.load(yamyams)
                except:
                    print("Oh no - something is wrong... Check ({})!".format(yamyams))

                # Define the Threaty Threats
                author = much_wow['author']
                detection = much_wow['detection']
                industry = much_wow['industry']
                link = much_wow['link']
                notes = much_wow['notes']
                tags = much_wow['tags']
                rule_type = much_wow['type']
                description = much_wow['description']
                false_positives = much_wow['false positives']
                fqp_queries = much_wow['queries']
                attack_tests = much_wow['queries']['attack test(s)']
                comments = much_wow['queries']['comment']
                th_guid = much_wow['queries']['guid']
                query = much_wow['queries']['query']
                rule_title = much_wow['queries']['title']
                supported_platforms = much_wow['supported platform(s)']
                threat_score = much_wow['threat']
                query_id = much_wow['query id']

                # Create JSON
                json_data['reports'] += [{"timestamp": int(time.time()),
                    "id": feed_id_name + str(i),
                    "link": link,
                        "title": rule_title,
                        "description": description,
                        "severity": int(threat_score),
                        "tags": tags,
                        "iocs_v2": [
                            {
                                "id": query_id,
                                "match_type": "query",
                                "values": [query],
                                "link": provider_url
                            }
                        ]
                    }]

    # Push new feeds as JSON object                
    print(" [ * ] Updating Threat Feed: {}".format(feed_id_name))
    #fh = open('data.json', 'w')
    #fh.write(json.dumps(json_data))
    ret = th.post_object("/threathunter/feedmgr/v1/feed", json_data)
    #pprint.pprint(ret.json())
    feed_access = ret.json()["access"]
    feed_id = ret.json()["id"]

    # We have to wait a few seconds for the feed to fully update
    time.sleep( 5 )
    
    # Yay - user feedback
    print('     - Feed Name: {}'.format(feed_name))
    print('     - Access: {}'.format(feed_access))
    print('     - Category: {}'.format(feed_category))
    print('     - Summary: {}'.format(feed_summary))
    print('     - Feed Count: {}'.format(i))
    print('')

    # Create a new watchlist and populate this with our new feeds
    ret = th.post_object("/threathunter/watchlistmgr/v3/orgs/{}/watchlists".format(orgkey), {
        "name": "{}".format(feed_name),
        "description": "{}".format(feed_summary),
        "id": "{}".format(feed_id),
        "tags_enabled": True,
        "alerts_enabled": True,
        "classifier": {'key': 'feed_id', 'value': feed_id}}
    )
    #pprint.pprint(ret.json())
    watchlist_id = ret.json()["id"]
    alerts_enabled = ret.json()["alerts_enabled"]
    create_timestamp = ret.json()["create_timestamp"]
    print(" [ * ] Successfully Created a new Watchlist - Now Adding Queries...")
    print('     - Alerts Enabled: {}'.format(alerts_enabled))
    print('     - Timestamp: {}'.format(create_timestamp))
    print('     - Watchlist ID: {}'.format(watchlist_id))
    print('')

    # Uncomment to validate that the feed was posted
    ret = th.get_object("/threathunter/watchlistmgr/v3/orgs/{}/watchlists/{}".format(orgkey,watchlist_id))
    #pprint.pprint(ret)


def convert_query(args,parser,cbr_query):
    th = CbThreatHunterAPI(profile="{}".format(args.orgprofile))
    
    # Convert the query
    ret = th.post_object('/threathunter/feedmgr/v2/query/translate', 
        {
            'query':'{}'.format(cbr_query)
        })
    results = ret.json()
    print('')
    print(results['query'])
    print('')


def nuke(args,parser,feed_name):
    th = CbThreatHunterAPI(profile="{}".format(args.orgprofile))
    orgkey = th.credentials.org_key

     # Deleting Feed Data
    print('')
    print('Removing WATCHLISTS based on watchlist name: {}'.format(feed_name))
    ret = th.get_object("/threathunter/watchlistmgr/v3/orgs/{}/watchlists".format(orgkey))
    for f in ret["results"]:
        #print(f["name"])
        if feed_name in f["name"]:
            print('Found Watchlist. Will Remove: {}'.format(feed_name))
            watchlist_id = f["id"]
            feed_id = f["classifier"]["value"]
            th.delete_object("/threathunter/watchlistmgr/v3/orgs/{}/watchlists/{}".format(orgkey,watchlist_id))
            print('Cleaning up the corresponding feed associated with the above watchlist: {}'.format(feed_id))
            th.delete_object("/threathunter/feedmgr/v2/orgs/{}/feeds/{}".format(orgkey,feed_id))
        else:
            print('Watchlists did not match cleanup: {}'.format(f["name"]))


def main():
    parser = argparse.ArgumentParser(description = 'Parse Threat Hunter YAMLs and Create / Update Watchlists')
    parser.add_argument('-p', '--profile', help = 'Select your cbapi credential profile', dest = 'orgprofile')
    parser.add_argument('-w', '--watchlist', help = 'Watchlist to create. Options: [AMSI, AdvancedThreats]', dest = 'watchlist_name', default = 'AMSI')
    parser.add_argument('-c', '--convert', help = 'Convert CB Response query to Threat Hunter format. Eg: (-c <query>)', dest = 'cbr_query')
    parser.add_argument('-d', '--delete', help = 'Delete a watchlist via query. Eg: (-d <query>)', dest = 'delete_query')
    args = parser.parse_args()

    if args.cbr_query:
        convert_query(args,parser,args.cbr_query)
    elif args.delete_query:
        manage_watchlists(args,parser,args.delete_query)
        nuke(args,parser,feed_name)
    elif args.orgprofile:
        if args.watchlist_name:
            manage_watchlists(args,parser,args.watchlist_name)
            threaty_threats(args,parser,args.orgprofile,args.watchlist_name)
        else:
            print(' [ ! ] Watchlist name is required: -w. Available options: [AMSI, AdvancedThreats]')
    else:
        print((parser.format_help()))
        quit()

if __name__ == "__main__":
    main()
    