## Threatunter Watchlist Manager

        Manage custom watchlists across multiple environments

        Convert ThreatHunter Queries

        Delete Watchlists and Feeds


### Watchlist Management

Watchlists are in YAML format and can be managed by the associated folder structure. Lines 43 - 52 of watchlist-manager.py can be modified as necessary to create a watchlist. Additional lines can be added as needed.

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

Create new watchlist entries and store them under the associated 'yml_path' folder. Feel free to rename any of these variables / folders. Create a separate yaml file (.yml / .yaml) format. Use a separate folder for each watchlist grouping.


### Script Usage

Requires CBAPI configured to work with ThreatHunter: https://cbapi.readthedocs.io/en/latest/threathunter-api.html

Install python3 requirements:

        pip3 install -r requirements.txt

Parse ThreatHunter YAMLs and Create / Update Watchlists:

        watchlist-manager.py [-h] [-o ORGKEY] [-p ORGPROFILE] [-w WATCHLIST_NAME] [-c CBR_QUERY] [-d DELETE_QUERY]

        optional arguments:
        -h, --help            show this help message and exit
        -p ORGPROFILE, --profile ORGPROFILE
                                Select your cbapi credential profile
        -w WATCHLIST_NAME, --watchlist WATCHLIST_NAME
                                Watchlist to create. Options: [customizable...]
        -c CBR_QUERY, --convert CBR_QUERY
                                Convert CB Response query to ThreatHunter format. Eg: (-c <query>)
        -d DELETE_QUERY, --delete DELETE_QUERY
                                Delete a watchlist via query. Eg: (-d <query>)


### Examples

Create Watchlist:

        python3 watchlist-manager.py -p <cbapi PSC profile> -w <watchlist_name>

Delete Watchlist:

        python3 watchlist-manager.py -p <cbapi PSC profile> -d <watchlist_name>

Convert Query:

        python3 watchlist-manager.py -p <cbapi PSC profile> -c '<response query>'

To Update a watchlist, you must first delete it and then re-create it.


### YAML Format

Each watchlist entry is a separate YAML file in somewhat-sigma format with a yaml/yml file extension. Refer to the example.yml and below.

        ---
        author: You
        detection: 'Rule Name'
        industry: 'Is this industry-specific? Default: all'
        link: 'Supporting links'
        notes: 'Notes that are noy visible in the CB Cloud Interface'
        tags:
        - exploitation
        - T(MITRE technique)
        - windows
        - advancedthreats
        - attack
        - attackframework
        type: Custom
        description: "Description of the rule...
                        can be multiple lines"
        false positives: 'Describe the false-positive ratio observed in testing'
        queries:
          attack test(s): Link to any tests that simulate and validate the rule
          comment: Comments that are not displayed within CB Cloud Interface
          guid: Generate via uuidgen on MacOS / Linux
          query: ThreatHunter query
          title: Rule Title
        supported platform(s): windows
        threat: 'Choose a rating between 1-10'
        query id: custom_unique_identification
        ...
