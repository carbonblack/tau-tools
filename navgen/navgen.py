import requests
import json
import re
import time

# we need to download the json of the mitre attack matrix
resp = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
data = resp.json()

def get_auth():
    """this will ask for auth info to CbR instance and return it"""
    print("[!] To find your API key, login to your Cb Response UI and navigate to the profile section.")

    full_url = input("[!] Here, enter the full url of your Cb Response instance. Example: https://bugcrowd.my.carbonblack.io\n[*] > ")
    if "https://" not in full_url:
        full_url = "https://" + full_url

    while True:
        api_key = input("[*] Enter your API key: > ")
        if len(api_key) != 40:
            print("[!] Invalid token. Try again.")
            continue
        else:
            break

    return api_key, full_url


def download_reports(api_key, url):
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


def reports_stats(data):
    """ check to see if feeds are all enabled, and report """
    list_of_ignored = []
    for report in data:
        if report['is_ignored'] is True:
            list_of_ignored.append(report['id'])
    if list_of_ignored:
        print("\n[!] Heads up! The following report ID's are ignored within your Threat Intelligence page. Your final output may be affected.")
        for ids in list_of_ignored:
            print("\t{}".format(ids))


def hardcoded_tids(tid, comment):
    """ Some threat reports aren't tagged with a TID. """
    my_new_list =[] 
    if get_tactic(data, tid.lower()) is not None:
        for tactic in get_tactic(data, tid.lower()):
            my_new_list.append(create_dict(tid, 100, comment, tactic))

    return my_new_list


def create_dict(tid, score, comment, tactic):
    """ this will accept specific parameters and return a dictionary of a
    specific technique. It will be appended to the "techniques" key in
     Navigator JSON. """

    color = get_color(score)

    nav_techniques = {
        "techniqueID": tid.upper(),
        "tactic": tactic,
        "color": color,
        "comment": comment,
        "enabled": True
    }

    return nav_techniques


def get_tactic(data, tid):
    """ this should return a list of tactics like ['persistence'] """    
    objects = data['objects']
    for object in objects:
        # print(object)
        if object['type'] == "attack-pattern":
            tid2 = object['external_references'][0]['external_id'].lower()
            if tid == tid2:
                tactic_list = []
                for kill_chain_phase in object['kill_chain_phases']:
                    tactic = kill_chain_phase['phase_name']
                    tactic_list.append(tactic)
    try:
        return tactic_list
    except:
        pass


def generate_tid_dict(threat_reports):
    """this will return a dictionary with TID's as keys. Values will be a list of all threat reports for that TID"""
    tid_dict = {}
    pattern = "t\d{4}"

    for threat_report in threat_reports:
        # grab all the supported OS tags
        if "windows" in threat_report['tags'] or "linux" in threat_report['tags'] or "macos" in threat_report['tags']:
            for tag in threat_report['tags']:
                if re.match(pattern, tag):
                    if tag in tid_dict:
                        tid_dict[tag].append(threat_report)
                    else:
                        tid_dict[tag] = [threat_report]

    return tid_dict


def build_navigator():
    navigator = {
        "name": "Cb Response Coverage (Windows,Linux,macOS)",
        "version": "2.2",
        "domain": "mitre-enterprise",
        "description": "",
        "filters": {
            "stages": [
                "act"
            ],
            "platforms": [
                "windows",
                "mac",
                "linux"
            ]
        },
        "sorting": 0,
        "viewMode": 0,
        "hideDisabled": False,
        "gradient": {
            "colors": [
                "#ff6666",
                "#ffe766",
                "#8ec843"
            ],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True
    }

    return navigator


def prepare_nav_techniques(tid, threat_report_values):
    """should accept one tid from build_navigator()... will contain list of mutiple queries."""

    tactic = get_tactic(data, tid)
    color = get_color(threat_report_values)
    comment = get_comment(threat_report_values)
    nav_technique = {
        "techniqueID": tid.upper(),
        "tactic": tactic,
        "color": color,
        "comment": comment,
        "enabled": True
    }

    return nav_technique


def get_comment(threat_report_values):
    number_of_reports = len(threat_report_values)
    comment = "There are %s queries matching this TID.\n\n" % (int(number_of_reports))
    for threat_report in threat_report_values:
        comment += "Feed: %s\nTitle: %s\nID: %s\nDescription: %s\n\n" % (threat_report['feed_name'], threat_report['title'], threat_report['id'], threat_report['description'].split("\n")[0])

    return comment


def get_color(threat_report_value):
    color_dict = {
        'green-high': '#00ff61',
        'green-med': '#83fcb1',
        'green-low': '#d6ffe5'
    }

    # this if statement supports hardcoded tids via hardcoded_tids()
    if type(threat_report_value) == int:
        score = threat_report_value
        threat_report_value = []
        threat_report_value.append({'score': score})

    for threat_report in threat_report_value:
        if threat_report['score'] >= 80:
            return color_dict['green-high']
        elif threat_report['score'] >= 50:
            return color_dict['green-med']
        elif threat_report['score'] >= 0:
            return color_dict['green-low']


def main():
    api_key, url = get_auth()
    print("\nYour url is: {}".format(url))
    print("Your API key is: {}".format(api_key))

    # download all reports from Cb Response server as json object
    data_from_cbr = download_reports(api_key, url)

    # provide stats about threat reports found.
    reports_stats(data_from_cbr)

    tid_dict = generate_tid_dict(data_from_cbr)

    nav_techniques_list = []
    for tid, threat_report_values in tid_dict.items():
        nav_techniques = prepare_nav_techniques(tid, threat_report_values)

        # Since prepare_nav_techniques returns list with multiple tactics, we should iterate through them to create 1:1 relationships. This for loop fixes that.
        try:
            for tactic in nav_techniques['tactic']:

                nav_techniques_copy = dict(nav_techniques)
                nav_techniques_copy['tactic'] = tactic
                nav_techniques_list.append(nav_techniques_copy)
        except:
                print("\n[!] WARNING: Did not find tactic for: ")
                print(nav_techniques)

    navigator = build_navigator()
    navigator['techniques'] = nav_techniques_list

    # we'll hardcode some TID's that target a fundamental feature.
    # extending the existing list in case a hard coded tid has more than one tactic. This will unroll the list from hardcoded_tids()
    navigator['techniques'].extend(hardcoded_tids("t1129", "Native product functionality."))
    navigator['techniques'].extend(hardcoded_tids("t1116", "Native product functionality."))
    navigator['techniques'].extend(hardcoded_tids("t1065", "Native product functionality."))
    navigator['techniques'].extend(hardcoded_tids("t1043", "Native product functionality."))

    # builds the navigator json
    navigator_json = json.dumps(navigator, indent=4, sort_keys=True)

    # save to disk in current working dir
    filename = "CbResponseNavigator-" + str(int(time.time())) + ".json"
    with open(filename, 'w') as outfile:
        outfile.write(navigator_json)
        print("\n[!] Saved MITRE Navigator json file as " + filename)
        print("[!] Use this file to 'Open Existing Layer' from local file on https://mitre.github.io/attack-navigator/enterprise/")


if __name__ == "__main__":
    main()
