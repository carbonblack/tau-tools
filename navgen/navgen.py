import requests
import json
import re
import time
from pick import pick

def get_label(option):
    return option.get('label')

def get_product():
    select = '[!] Select the product: '
    options = [{'label': 'VMWare Carbon Black EDR (formerly CB Response)'}, {'label': 'VMWare Carbon Black Enterprise EDR (formerly CB ThreatHunter)'}]
    product = pick(options, select, indicator='*', options_map_func=get_label)
    if product[1] == 0:
        product = "edr"
    elif product[1] == 1:
        product = "eedr"
    else:
        return None

    return product

def get_auth():
    """this will ask for auth info and return it"""

    full_url = input("[!] Here, enter the full url of your instance. Examples: \n\thttps://bugcrowd.my.carbonblack.io\n\thttps://defense-prod05.conferdeploy.net\n\n[*] > ")
    if "https://" not in full_url:
        full_url = "https://" + full_url

    api_key = input("[*] Enter your API key/token: > ")

    return full_url, api_key


def download_edr_reports(url, api_key):
    """
    This will download threat reports for following feeds:
        attackframework
        sans
        Bit9AdvancedThreats
        Bit9SuspiciousIndicators
        Bit9EndpointVisibility
        CbCommunity
        Bit9EarlyAccess
    and return json object
    """
    headers = {
        'Content-Type': 'application/json',
        'X-Auth-Token': api_key
    }

    # this will create a full url to get total number of reports.
    full_url = url + "/api/v1/threat_report?cb.urlver=1&cb.fq.feed_name=attackframework&cb.fq.feed_name=bit9advancedthreats&cb.fq.feed_name=cbcommunity&cb.fq.feed_name=sans&cb.fq.feed_name=bit9endpointvisibility&cb.fq.feed_name=bit9suspiciousindicators&cb.fq.feed_name=bit9earlyaccess&sort=severity_score%20desc&rows=10&facet=false&start=0&cb.fq.is_deleted=false"
    try:
        r = requests.get(full_url, headers=headers)
    except:
        r = requests.get(full_url, headers=headers, verify=False)

    # store results as json
    data = r.json()

    # gets the number of total threat reports found.
    total_results = data['total_results']
    print("There are {} total threat reports found.".format(total_results))

    # we need to determine how many requests in batches of 100 we need to make to download threat reports in
    paginate_count = total_results // 100 + 1
    data = []

    # depending on what pagiante_count is, we need to make this many requests to download threat report
    for i in range(paginate_count):
        full_url = url + "/api/v1/threat_report?cb.urlver=1&cb.fq.feed_name=attackframework&cb.fq.feed_name=bit9advancedthreats&cb.fq.feed_name=cbcommunity&cb.fq.feed_name=sans&cb.fq.feed_name=bit9endpointvisibility&cb.fq.feed_name=bit9suspiciousindicators&cb.fq.feed_name=bit9earlyaccess&sort=severity_score%20desc&rows=100&facet=false&start=" + str(i * 100) + "&cb.fq.is_deleted=false"
        try:
            r = requests.get(full_url, headers=headers)
        except:
            r = requests.get(full_url, headers=headers, verify=False)

        # append 100 batch threat report to data object
        data += r.json()['results']

    return data


def get_eedr_feed_ids(backend_url, api_key, org_key):
    headers = {
        'Content-Type': 'application/json',
        'X-Auth-Token': api_key
    }
    # this will create a full url to get total number of reports.
    full_url = backend_url + "/threathunter/feedmgr/v2/orgs/{}/feeds?include_public=true".format(org_key)

    try:
        r = requests.get(full_url, headers=headers)
    except:
        print("requests failed to get feed ids")
    data = r.json()
    feed_ids = []
    for feed in data['results']:
        if feed['access'] == 'public':
            feed_ids.append(feed['id'])

    return feed_ids


def download_eedr_feed_reports(backend_url, api_key, org_key, feed_id):
    headers = {
        'Content-Type': 'application/json',
        'X-Auth-Token': api_key
    }
    # this will create a full url to get total number of reports.
    full_url = backend_url + "/threathunter/feedmgr/v2/orgs/{}/feeds/{}".format(org_key, feed_id)

    r = requests.get(full_url, headers=headers)
    data = r.json()

    return data


def build_navigator():
   navigator  = {
      "name": "VMWare Carbon Black MITRE ATT&CK Coverage",
      "version": "3.0",
      "description": "This layer shows techniques stored in VMWare Carbon Black Threat Intelligence feeds.",
      "domain": "mitre-enterprise",
      "legendItems": [],
      "techniques": []
   }

   return navigator


def generate_tid_dict(threat_reports):
   """this will return a dictionary with TID's as keys. Values will be a list of all threat reports for that TID"""
   tid_dict = {}
   pattern = "t\d{4}"

   for threat_report in threat_reports:
      if threat_report['tags'] != None:
         for tag in threat_report['tags']:
            if re.match(pattern, tag):
               if tag in tid_dict:
                  tid_dict[tag].append(threat_report)
               else:
                  tid_dict[tag] = [threat_report]

   return tid_dict


def prepare_nav_techniques(tid, threat_report_values, product):
   """should accept one tid from build_navigator()... will contain list of mutiple queries."""

   color = get_color(threat_report_values, product)
   description = get_description(threat_report_values)
   nav_technique = {
      "techniqueID": tid.upper(),
      "color": color,
      "comment": description,
      "enabled": True
   }

   return nav_technique


def get_color(threat_report_value, product):
   color_dict = {
      'green-high': '#00ff61',
      'green-med': '#83fcb1',
      'green-low': '#d6ffe5'
   }

   # this if statement supports hardcoded tids via hardcoded_tids()
   if type(threat_report_value) == int:
      severity = threat_report_value
      threat_report_value = []
      threat_report_value.append({'severity': severity})

   for threat_report in threat_report_value:
      if product == 'edr':
         severity = threat_report['severity'] / 10
      elif product == 'eedr':
         severity = threat_report['severity']

      if severity >= 8:
         return color_dict['green-high']
      elif severity >= 5:
         return color_dict['green-med']
      elif severity >= 0:
         return color_dict['green-low']


def get_description(threat_report_values):
   number_of_reports = len(threat_report_values)
   comment = "There are %s queries matching this TID.\n\n" % (int(number_of_reports))
   for threat_report in threat_report_values:
      comment += "Feed: %s\nTitle: %s\nID: %s\nDescription: %s\n\n" % (
      threat_report['feed_name'], threat_report['title'], threat_report['id'],
      threat_report['description'].split("\n")[0])

   return comment


def main():
   product = get_product()
   if product == None:
       print("Invalid product. Qutting.")
       quit(1)

   backend_url, api_key = get_auth()
   if product == 'eedr':
       org_key =  input("[*] Enter your org key: > ")
   print("\nYour url is: {}".format(backend_url))
   print("Your API key is: {}".format(api_key))
   if product == 'eedr':
       print("Your org key is: {}".format(org_key))

   if product == 'edr':
       reports = download_edr_reports(backend_url, api_key)
       all_reports = []
       for report in reports:
          threat_report = {}
          threat_report['feed_name'] = report['feed_name']
          threat_report['id'] = report['id']
          threat_report['title'] = report['title']
          threat_report['tags'] = report['tags']
          threat_report['severity'] = report['score']
          threat_report['description'] = report['description']
          all_reports.append(threat_report)

   elif product == 'eedr':
       eedr_feed_ids = get_eedr_feed_ids(backend_url, api_key, org_key)
       all_reports = []
       for feed_id in eedr_feed_ids:
           reports = download_eedr_feed_reports(backend_url, api_key, org_key, feed_id)
           feed_name = reports['feedinfo']['name']

           for report in reports['reports']:
               threat_report = {}
               threat_report['feed_name'] = feed_name
               threat_report['id'] = report['id']
               threat_report['title'] = report['title']
               threat_report['tags'] = report['tags']
               threat_report['severity'] = report['severity']
               threat_report['description'] = report['description']
               all_reports.append(threat_report)

   # now we have a list containing all reports... we need to identify ones with a mitre attack TID.
   attack_techniques = []
   tid_dict = generate_tid_dict(all_reports)
   navigator = build_navigator()

   nav_techniques_list = []
   for tid, threat_report_values in tid_dict.items():
      nav_techniques = prepare_nav_techniques(tid, threat_report_values, product)
      navigator['techniques'].append(nav_techniques)

   # builds the navigator json
   navigator_json = json.dumps(navigator, indent=4, sort_keys=True)

   # save to disk in current working dir
   filename = "VMWareCBThreatIntel-{}-".format(product.upper()) + str(int(time.time())) + ".json"
   with open(filename, 'w') as outfile:
      outfile.write(navigator_json)
      print("\n[!] Saved MITRE Navigator json file as " + filename)
      print(
         "[!] Use this file to 'Open Existing Layer' from local file on https://mitre.github.io/attack-navigator/enterprise/")


if __name__ == '__main__':
   main()