import requests
import json
import re
import time
import pprint


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
    my_new_list = {}
    if get_tactic(tid.lower()) is not None:
        for tactic in get_tactic(tid.lower()):
            my_new_dict = (create_dict(tid, 100, comment, tactic))
    return my_new_dict


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


def get_tactic(tid):
    # we should generate this dict by scraping https://attack.mitre.org/wiki/All_Techniques
    """ this will accept a tid, and return a list of tactics"""
    attack_dict = {
        "t1156": ["persistence"],
        "t1134": ["defense-evasion", "privilege-escalation"],
        "t1015": ["persistence", "privilege-escalation"],
        "t1087": ["discovery"],
        "t1098": ["credential-access"],
        "t1182": ["persistence", "privilege-escalation"],
        "t1103": ["persistence", "privilege-escalation"],
        "t1155": ["execution", "lateral-movement"],
        "t1017": ["lateral-movement"],
        "t1138": ["persistence", "privilege-escalation"],
        "t1010": ["discovery"],
        "t1123": ["collection"],
        "t1131": ["persistence"],
        "t1119": ["collection"],
        "t1020": ["exfiltration"],
        "t1197": ["defense-evasion", "persistence"],
        "t1139": ["credential-access"],
        "t1009": ["defense-evasion"],
        "t1067": ["persistence"],
        "t1217": ["discovery"],
        "t1176": ["persistence"],
        "t1110": ["credential-access"],
        "t1088": ["defense-evasion", "privilege-escalation"],
        "t1191": ["defense-evasion", "execution"],
        "t1042": ["persistence"],
        "t1146": ["defense-evasion"],
        "t1115": ["collection"],
        "t1116": ["defense-evasion"],
        "t1059": ["execution"],
        "t1043": ["command-and-control"],
        "t1092": ["command-and-control"],
        "t1109": ["defense-evasion", "persistence"],
        "t1122": ["defense-evasion", "persistence"],
        "t1090": ["command-and-control"],
        "t1196": ["defense-evasion", "execution"],
        "t1136": ["persistence"],
        "t1003": ["credential-access"],
        "t1081": ["credential-access"],
        "t1214": ["credential-access"],
        "t1094": ["command-and-control"],
        "t1024": ["command-and-control"],
        "t1207": ["defense-evasion"],
        "t1038": ["defense-evasion", "persistence", "privilege-escalation"],
        "t1073": ["defense-evasion"],
        "t1002": ["exfiltration"],
        "t1132": ["command-and-control"],
        "t1022": ["exfiltration"],
        "t1001": ["command-and-control"],
        "t1074": ["collection"],
        "t1030": ["exfiltration"],
        "t1213": ["collection"],
        "t1005": ["collection"],
        "t1039": ["collection"],
        "t1025": ["collection"],
        "t1140": ["defense-evasion"],
        "t1089": ["defense-evasion"],
        "t1175": ["lateral-movement"],
        "t1172": ["command-and-control"],
        "t1189": ["initial-access"],
        "t1157": ["persistence", "privilege-escalation"],
        "t1173": ["execution"],
        "t1114": ["collection"],
        "t1106": ["execution"],
        "t1129": ["execution"],
        "t1048": ["exfiltration"],
        "t1041": ["exfiltration"],
        "t1011": ["exfiltration"],
        "t1052": ["exfiltration"],
        "t1190": ["initial-access"],
        "t1203": ["execution"],
        "t1212": ["credential-access"],
        "t1211": ["defense-evasion"],
        "t1068": ["privilege-escalation"],
        "t1210": ["lateral-movement"],
        "t1133": ["persistence"],
        "t1181": ["defense-evasion", "privilege-escalation"],
        "t1008": ["command-and-control"],
        "t1107": ["defense-evasion"],
        "t1006": ["defense-evasion"],
        "t1044": ["persistence", "privilege-escalation"],
        "t1083": ["discovery"],
        "t1187": ["credential-access"],
        "t1144": ["defense-evasion"],
        "t1061": ["execution"],
        "t1148": ["defense-evasion"],
        "t1200": ["initial-access"],
        "t1158": ["defense-evasion", "persistence"],
        "t1147": ["defense-evasion"],
        "t1143": ["defense-evasion"],
        "t1179": ["credential-access", "persistence", "privilege-escalation"],
        "t1062": ["persistence"],
        "t1183": ["defense-evasion", "persistence", "privilege-escalation"],
        "t1054": ["defense-evasion"],
        "t1066": ["defense-evasion"],
        "t1070": ["defense-evasion"],
        "t1202": ["defense-evasion"],
        "t1056": ["collection", "credential-access"],
        "t1141": ["credential-access"],
        "t1130": ["defense-evasion"],
        "t1118": ["defense-evasion", "execution"],
        "t1208": ["credential-access"],
        "t1215": ["persistence"],
        "t1142": ["credential-access"],
        "t1161": ["persistence"],
        "t1149": ["defense-evasion"],
        "t1171": ["credential-access"],
        "t1177": ["execution", "persistence"],
        "t1159": ["persistence"],
        "t1160": ["persistence", "privilege-escalation"],
        "t1152": ["defense-evasion", "execution", "persistence"],
        "t1168": ["persistence", "execution"],
        "t1162": ["persistence"],
        "t1037": ["lateral-movement", "persistence"],
        "t1185": ["collection"],
        "t1036": ["defense-evasion"],
        "t1031": ["persistence"],
        "t1112": ["defense-evasion"],
        "t1170": ["defense-evasion", "execution"],
        "t1104": ["command-and-control"],
        "t1188": ["command-and-control"],
        "t1026": ["command-and-control"],
        "t1079": ["command-and-control"],
        "t1096": ["defense-evasion"],
        "t1128": ["persistence"],
        "t1046": ["discovery"],
        "t1126": ["defense-evasion"],
        "t1135": ["discovery"],
        "t1040": ["credential-access", "discovery"],
        "t1050": ["persistence", "privilege-escalation"],
        "t1027": ["defense-evasion"],
        "t1137": ["persistence"],
        "t1075": ["lateral-movement"],
        "t1097": ["lateral-movement"],
        "t1174": ["credential-access"],
        "t1201": ["discovery"],
        "t1034": ["persistence", "privilege-escalation"],
        "t1120": ["discovery"],
        "t1069": ["discovery"],
        "t1150": ["defense-evasion", "persistence", "privilege-escalation"],
        "t1205": ["command-and-control", "defense-evasion", "persistence"],
        "t1013": ["persistence", "privilege-escalation"],
        "t1086": ["execution"],
        "t1145": ["credential-access"],
        "t1057": ["discovery"],
        "t1186": ["defense-evasion"],
        "t1093": ["defense-evasion"],
        "t1055": ["defense-evasion", "privilege-escalation"],
        "t1012": ["discovery"],
        "t1163": ["persistence"],
        "t1164": ["persistence"],
        "t1108": ["defense-evasion", "persistence"],
        "t1060": ["persistence"],
        "t1121": ["defense-evasion", "execution"],
        "t1117": ["defense-evasion", "execution"],
        "t1219": ["command-and-control"],
        "t1076": ["lateral-movement"],
        "t1105": ["command-and-control", "lateral-movement"],
        "t1021": ["lateral-movement"],
        "t1018": ["discovery"],
        "t1091": ["lateral-movement", "initial-access"],
        "t1014": ["defense-evasion"],
        "t1085": ["defense-evasion", "execution"],
        "t1178": ["privilege-escalation"],
        "t1198": ["defense-evasion", "persistence"],
        "t1184": ["lateral-movement"],
        "t1053": ["execution", "persistence", "privilege-escalation"],
        "t1029": ["exfiltration"],
        "t1113": ["collection"],
        "t1180": ["persistence"],
        "t1064": ["defense-evasion", "execution"],
        "t1063": ["discovery"],
        "t1101": ["persistence"],
        "t1167": ["credential-access"],
        "t1035": ["execution"],
        "t1058": ["persistence", "privilege-escalation"],
        "t1166": ["privilege-escalation"],
        "t1051": ["lateral-movement"],
        "t1023": ["persistence"],
        "t1218": ["defense-evasion", "execution"],
        "t1216": ["defense-evasion", "execution"],
        "t1045": ["defense-evasion"],
        "t1153": ["execution"],
        "t1151": ["defense-evasion", "execution"],
        "t1193": ["initial-access"],
        "t1192": ["initial-access"],
        "t1194": ["initial-access"],
        "t1071": ["command-and-control"],
        "t1032": ["command-and-control"],
        "t1095": ["command-and-control"],
        "t1165": ["persistence", "privilege-escalation"],
        "t1169": ["privilege-escalation"],
        "t1206": ["privilege-escalation"],
        "t1195": ["initial-access"],
        "t1019": ["persistence"],
        "t1082": ["discovery"],
        "t1016": ["discovery"],
        "t1049": ["discovery"],
        "t1033": ["discovery"],
        "t1007": ["discovery"],
        "t1124": ["discovery"],
        "t1080": ["lateral-movement"],
        "t1072": ["execution", "lateral-movement"],
        "t1209": ["persistence"],
        "t1099": ["defense-evasion"],
        "t1154": ["execution", "persistence"],
        "t1127": ["defense-evasion", "execution"],
        "t1199": ["initial-access"],
        "t1111": ["credential-access"],
        "t1065": ["command-and-control"],
        "t1204": ["execution"],
        "t1078": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
        "t1125": ["collection"],
        "t1102": ["command-and-control", "defense-evasion"],
        "t1100": ["persistence", "privilege-escalation"],
        "t1077": ["lateral-movement"],
        "t1047": ["execution"],
        "t1084": ["persistence"],
        "t1028": ["execution", "lateral-movement"],
        "t1004": ["persistence"],
        "t1222": ["defense-evasion"]
    }

    tactics = attack_dict.get(tid, None)
    return tactics


def generate_tid_dict(threat_reports):
    """this will return a dictionary with TID's as keys. Values will be a list of all threat reports for that TID"""
    tid_dict = {}
    pattern = "t\d{4}"

    for threat_report in threat_reports:
        # print(threat_report['tags'])
        if "windows" in threat_report['tags']:
            for tag in threat_report['tags']:
                if re.match(pattern, tag):
                    # print("match")
                    # if tid, this means it's attack query. Check to see if there's tid key already in dict...
                    if tag in tid_dict:
                        # if it exists, add as list.
                        # print("exists... adding")
                        tid_dict[tag].append(threat_report)
                    else:
                        # if key doesn't exist, create it
                        # print("doesn't exist")
                        tid_dict[tag] = [threat_report]
                        # tid_dict[tag].append(threat_report)
    return tid_dict

def build_navigator():
    navigator = {
        "name": "Cb Response - Windows",
        "version": "2.0",
        "domain": "mitre-enterprise",
        "description": "",
        "filters": {
            "stages": [
                "act"
            ],
            "platforms": [
                "windows"
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

    tactic = get_tactic(tid)
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

    if type(threat_report_value) == int:
        if threat_report_value >= 80:
            return color_dict['green-high']
        elif threat_report_value >= 50:
            return color_dict['green-med']
        elif threat_report_value >= 0:
            return color_dict['green-low']
    else:
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
        for tactic in nav_techniques['tactic']:
            nav_techniques_copy = dict(nav_techniques)
            nav_techniques_copy['tactic'] = tactic
            nav_techniques_list.append(nav_techniques_copy)

    navigator = build_navigator()
    navigator['techniques'] = nav_techniques_list

    # we'll hardcode some TID's that target a fundamental feature.
    navigator['techniques'].append(hardcoded_tids("t1129", "Native product functionality."))
    navigator['techniques'].append(hardcoded_tids("t1116", "Native product functionality."))
    navigator['techniques'].append(hardcoded_tids("t1065", "Native product functionality."))
    navigator['techniques'].append(hardcoded_tids("t1043", "Native product functionality."))

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
