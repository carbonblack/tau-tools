#!/usr/bin/env python3

# Carbon Black Cloud - HiveNightmare LiveResponse
# Copyright VMware 2021
# Ed Myers & Casey Parman
# usage: HiveNightmare-LR.py [-h] [-m MACHINENAME] [-c] [-p] [-o ORGPROFILE]
# 
# optional arguments:
#   -h, --help            show this help message and exit
#   -m MACHINENAME, --hostname MACHINENAME
#                         hostname to run host forensics recon on
#   -c, --check           Check the system for the vulnerable SMBv3
#                         Configuration
#   -p, --patch           Mitigate the vulnerable system's SMBv3 configuration
#                         by disabling compression
#   -o ORGPROFILE, --orgprofile ORGPROFILE
#                         Select your cbapi credential profile

import os, sys, time, argparse
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
        print ("[ * ] Uploading HiveNightmare.ps1 to the remote host")
        lr_session.put_file(open("HiveNightmare.ps1", "rb"), "C:\\Program Files\\Confer\\temp\\HiveNightmare.ps1")

        if response == "patch":
            print ("[ * ] Mitigating the vulnerable system32\config files:")
            result = lr_session.create_process("powershell.exe -ExecutionPolicy Bypass -File .\\HiveNightmare.ps1 -mitigate", wait_for_output=True, remote_output_file_name=None, working_directory="C:\\Program Files\\Confer\\temp\\", wait_timeout=30, wait_for_completion=True).decode("utf-8")
            print ("")
            print("{}".format(result))
        else:
            print ("[ * ] Checking the system for vulnerable system32\config files:")
            result = lr_session.create_process("powershell.exe -ExecutionPolicy Bypass -File .\\HiveNightmare.ps1", wait_for_output=True, remote_output_file_name=None, working_directory="C:\\Program Files\\Confer\\temp\\", wait_timeout=30, wait_for_completion=True).decode("utf-8")
            print ("")
            print("{}".format(result))

        print ("[ * ] Removing HiveNightmare.ps1")
        lr_session.create_process("powershell.exe del .\\HiveNightmare.ps1", wait_for_output=False, remote_output_file_name=None, working_directory="C:\\Program Files\\Confer\\temp\\", wait_timeout=30, wait_for_completion=False)
        print ("")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hostname", help = "hostname to run host forensics recon on")
    parser.add_argument("--check", help = "Check the system for the vulnerable system32\config files", action = "store_true")
    parser.add_argument("--mitigate", help = "Mitigate the vulnerable system's vulnerable system32\config files", action = "store_true")
    parser.add_argument('--orgprofile', help = "Select your cbapi credential profile", dest = "orgprofile", default = "default")
    args = parser.parse_args()

    #Create the CbD LR API object
    profile = CbDefenseAPI(profile="{}".format(args.orgprofile))
    cb_url = profile.credentials.url
    cb_token = profile.credentials.token
    cb_org_key = profile.credentials.org_key
    cb_ssl = "True"
    cb = CbDefenseAPI(url=cb_url, token=cb_token, orgId=cb_org_key, ssl_verify=cb_ssl)

    if args.hostname:
        if args.mitigate:
            live_response(cb, host=args.hostname, response="patch")
        else:
            live_response(cb, host=args.hostname, response="check")
    else:
        print ("[ ! ] You must specify a hostname with a --hostname parameter. IE ./HiveNightmare-LR.py --hostname cheese")

if __name__ == "__main__":
  main()
