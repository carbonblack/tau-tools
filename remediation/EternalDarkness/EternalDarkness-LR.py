#!/usr/bin/env python3

# Carbon Black Cloud - EternalDarkness LiveResponse
# Copyright VMware 2020
# March 2020
# Version 0.1
# gfoss [at] vmware . com
#
# usage: EternalDarkness-LR.py [-h] [-m MACHINENAME] [-c] [-p] [-o ORGPROFILE]
# 
# optional arguments:
#   -h, --help            show this help message and exit
#   -m MACHINENAME, --machinename MACHINENAME
#                         machinename to run host forensics recon on
#   -c, --check           Check the system for the vulnerable SMBv3
#                         Configuration
#   -p, --patch           Mitigate the vulnerable system's SMBv3 configuration
#                         by disabling compression
#   -o ORGPROFILE, --orgprofile ORGPROFILE
#                         Select your cbapi credential profile

import os, sys, argparse, requests, json, yaml, time, pprint
from cbapi.defense import *

def live_response(cb, host=None, response=None):
    
    print ("")

    #Select the device you want to gather recon data from
    query_hostname = "hostNameExact:%s" % host
    print ("[ * ] Establishing LiveResponse Session with Remote Host:")

    #Create a new device object to launch LR on
    device = cb.select(Device).where(query_hostname).first()
    print("     - Hostname: {}".format(device.name))
    print("     - OS Version: {}".format(device.osVersion))
    print("     - Sensor Version: {}".format(device.sensorVersion))
    print("     - AntiVirus Status: {}".format(device.avStatus))
    print("     - Internal IP Address: {}".format(device.lastInternalIpAddress))
    print("     - External IP Address: {}".format(device.lastExternalIpAddress))
    print ("")

    #Execute our LR session
    with device.lr_session() as lr_session:
        print ("[ * ] Uploading EternalDarkness.ps1 to the remote host")
        lr_session.put_file(open("EternalDarkness.ps1", "rb"), "C:\\Program Files\\Confer\\temp\\EternalDarkness.ps1")

        if response == "patch":
            print ("[ * ] Patching the vulnerable SMBv3 configuration by disabling compression:")
            result = lr_session.create_process("powershell.exe -ExecutionPolicy Bypass -File .\\EternalDarkness.ps1 -mitigate", wait_for_output=True, remote_output_file_name=None, working_directory="C:\\Program Files\\Confer\\temp\\", wait_timeout=30, wait_for_completion=True)
            print ("")
            print("{}".format(result))
            print ("")
        else:
            print ("[ * ] Checking the system for vulnerable SMBv3 configuration:")
            result = lr_session.create_process("powershell.exe -ExecutionPolicy Bypass -File .\\EternalDarkness.ps1", wait_for_output=True, remote_output_file_name=None, working_directory="C:\\Program Files\\Confer\\temp\\", wait_timeout=30, wait_for_completion=True)
            print ("")
            print("{}".format(result))
            print ("")

        print ("[ * ] Removing EternalDarkness.ps1")
        lr_session.create_process("powershell.exe del .\\EternalDarkness.ps1", wait_for_output=False, remote_output_file_name=None, working_directory="C:\\Program Files\\Confer\\temp\\", wait_timeout=30, wait_for_completion=False)
        print ("")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--machinename", help="machinename to run host forensics recon on")
    parser.add_argument("-c", "--check", help="Check the system for the vulnerable SMBv3 Configuration", action = "store_true")
    parser.add_argument("-p", "--patch", help="Mitigate the vulnerable system's SMBv3 configuration by disabling compression", action = "store_true")
    parser.add_argument('-o', '--orgprofile', help = "Select your cbapi credential profile", dest = "orgprofile", default = "default")
    args = parser.parse_args()

    #Create the CbD LR API object
    profile = CbDefenseAPI(profile="{}".format(args.orgprofile))
    cb_url = profile.credentials.url
    cb_token = profile.credentials.token
    cb_org_key = profile.credentials.org_key
    cb_ssl = "True"
    cb = CbDefenseAPI(url=cb_url, token=cb_token, orgId=cb_org_key, ssl_verify=cb_ssl)

    if args.machinename:
        if args.patch:
            live_response(cb, host=args.machinename, response="patch")
        else:
            live_response(cb, host=args.machinename, response="check")
    else:
        print ("[ ! ] You must specify a machinename with a --machinename parameter. IE ./EternalDarkness-LR.py --machinename cheese")

if __name__ == "__main__":
  main()
