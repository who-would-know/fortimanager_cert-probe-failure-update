import os
import os.path
import sys
import time
import requests
import urllib3
# Ignore Self Signed Certs from Devices
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()
import json
import getpass
# Module file for logging outputs
import transcript
# Converting IP Subnet mask
import ipaddress
# Regex find IP
import re

### Define additional global variables
taskID = ''
# Default User Input values
default_hostIP = '172.30.250.33'
default_hostADMIN = 'apiadmin'
default_hostPASSWD = ''
default_fgtDEVname = 'fwcluster-fw03'
default_userOPTION = '1'
adomNAME = ''

### Start Logging
# Remove previous log files and create a new files
if os.path.isfile('mainLOG.txt'):
    os.remove('mainLOG.txt')
if os.path.isfile('ERRORlog.txt'):
        os.remove('ERRORlog.txt')
transcript.start('mainLOG.txt')
ERRORlog = open("ERRORlog.txt", "a")
print ('>> Start logging script output to mainLOG.txt <<')
# Start stopwatch for script timing
stopwatchSTART = time.time()

### FUNCTIONS
def continue_script():
    print ('-=-' * 20)
    while True:
        try:
            print('--> Continue script with current variables? (y or n): ')
            goNOgo = input()
        except ValueError:
            print ('    Input not understood, please input y or n.')
            continue
        if goNOgo == 'y':
            print ('    Variables accepted, continuing script.')
            print
            print ('-=-' * 20)
            print
            goNOgo = ''
            break
        elif goNOgo == 'n':
            print ('    Variables NOT accepted, exiting script!')
            print
            exit()
        else:
            print ('    Input not understood, please input y or n!')
            print
            continue

def fmg_login(hostAPIUSER, hostPASSWD, hostIP):
    '''FortiManager Login & Create Session
    Arguments:
    hostAPIUSER - API User Account Name
    hostPASSWD - API User Passwd
    hostIP - IP addres of FortiManager. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    # Global Save Session ID
    global session
    # Create HTTPS URL
    global url
    url = 'https://' + hostIP + '/jsonrpc'
    # JSON Body to sent to API request
    body = {
    "id": 1,
            "method": "exec",
            "params": [{
                    "url": "sys/login/user",
                    "data": [{
                            "user": hostAPIUSER,
                            "passwd": hostPASSWD
                    }]
            }],
            "session": 1
    }
    # Test HTTPS connection to host then Capture and output any errors
    try:
        r = requests.post(url, json=body, verify=False)
    except requests.exceptions.RequestException as e: 
        print (SystemError(e))
        # Exit Program, Connection was not Successful
        sys.exit(1)
    # Save JSON response from FortiManager
    json_resp = json.loads(r.text)
    # Check if User & Passwd was valid, no code -11 means invalid
    if json_resp['result'][0]['status']['code'] != -11:
        session = json_resp['session']
        print ('--> Logging into FortiManager: %s' % hostIP)
        # HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    else:
        print ('<--Username or password is not valid, please try again, exiting...')
        # HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        # Exit Program, Username or Password is not valided or internal FortiManager error review Hcode & Jmesg
        sys.exit(1)

def fmg_logout(hostIP):
    '''FortiManager logout
    Arguments:
    hostIP - IP addres of FortiManager. Note, if not on default HTTPS(443) port can input: 1.1.1.1:8080
    '''
    body = {
       "id": 1,
        "method": "exec",
        "params": [{
                "url": "sys/logout"
        }],
        "session": session
    }
    # Test HTTPS connection to host then Capture and output any errors
    try:
        r = requests.post(url, json=body, verify=False)
    except requests.exceptions.RequestException as e:
        print (SystemError(e))
        # Exit Program, Connection was not Successful
        sys.exit(1)
    # Save JSON response from FortiManager    
    json_resp = json.loads(r.text)
    # Check if any API Errors returned
    if json_resp['result'][0]['status']['code'] != -11:    
        print ('--> Logging out of FMG: %s' % hostIP)
        # HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
    else:
        print ('<--Error Occured, check Hcode & Jmesg')
        # Exit Program, internal FortiManager error review Hcode & Jmesg
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
        sys.exit(1)

### Get Adoms based off FortiGate Device
def get_adom(fgtDEVname):
        global adomLIST
        adomLIST = []
        json_url = "dvmdb/adom"
        body = {
                "id": 1,
                "method": "get",
                "params": [{
                        "expand member": [
                            {
                                "fields": [
                                    "name",
                                ],
                                "filter": [
                                    "name", "==", fgtDEVname
                                ],
                                "url": "/device"
                            }
                        ],
                       "fields": [
                            "name",
                       ],
                       "url": json_url
                }],
                "session": session,
                #"verbose": 1
        }
        r = requests.post(url, json=body, verify=False)
        json_resp = json.loads(r.text)
        #print(json.dumps(json_resp, indent=2))
        for entry in json_resp['result'][0]['data']:
            #print(entry);
            if "expand member" in entry:
                adomLIST.append(entry['name'])
                # print(entry)

def workspace_lock(lADOM):
    json_url = "pm/config/adom/" + lADOM + "/_workspace/lock"
    body = {
        "id": 1,
        "method": "exec",
        "params": [{
            "url": json_url
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print ('--> Locking ADOM: %s' % lADOM)
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    if 'No permission for the resource' in json_resp['result'][0]['status']['message']:
        print(f"<--!!!ERROR!!! Unable to lock for r/w to ADOM: {lADOM}. Check to make sure it's unlocked")
        print ("\n")
        ERRORlog.write(f"<-- !!!ERROR!!! Unable to lock for r/w to ADOM: {lADOM}. Check to make sure it's unlocked")
        return False
    return True

def workspace_commit(cADOM):
    json_url = "pm/config/adom/" + cADOM + "/_workspace/commit"
    body = {
        "id": 1,
        "method": "exec",
        "params": [{
            "url": json_url
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print("\n")
    print ('--> Saving changes for ADOM %s' % cADOM)
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    # print ("\n")

def workspace_unlock(uADOM):
    json_url = "pm/config/adom/" + uADOM + "/_workspace/unlock"
    body = {
        "id": 1,
        "method": "exec",
        "params": [{
            "url": json_url
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print ("\n")
    print ('--> Unlocking ADOM %s' % uADOM)
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    print ("\n")

def status_taskid():
    global state
    json_url = "/task/task/" + str(taskID)
    body = {
        "id": 1,
        "method": "get",
        "params": [{
            "url": json_url
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    print
    #print json_resp['result']['data']['state']
    state = json_resp['result'][0]['data']['state']
    totalPercent = json_resp['result'][0]['data']['tot_percent']
    if state == 0:
        print ('    Current task state (%d): pending' % state)
    if state == 1:
        print ('    Current task state (%d): running' % state)
    if state == 2:
        print ('    Current task state (%d): cancelling' % state)
    if state == 3:
        print ('    Current task state (%d): cancelled' % state)
    if state == 4:
        print ('    Current task state (%d): done' % state)
    if state == 5:
        print ('    Current task state (%d): error' % state)
    if state == 6:
        print ('    Current task state (%d): aborting' % state)
    if state == 7:
        print ('    Current task state (%d): aborted' % state)
    if state == 8:
        print ('    Current task state (%d): warning' % state)
    if state == 9:
        print ('    Current task state (%d): to_continue' % state)
    if state == 10:
        print ('    Current task state (%d): unknown' % state)
    if json_resp['result'][0]['status']['message'] == 'OK':
        print ('    Current task percentage: (%d)' % totalPercent)
        print

def poll_taskid (csADOM):
    global state
    state = 0
    while state not in [3,4,5,7]:
        print ('--> Polling task: %s' % taskID)
        time.sleep( 3 )
        status_taskid()
    if state == 4:
        print ('--> Task %s is done!' % taskID)
        print
    else:
        print ('--> Task %s is DIRTY, check FMG task manager for details!' % taskID)
        print ('    Adding this ADOM to the error log %s !' % ERRORlog.name)
        ERRORlog.write("%s %s %s\n" % (csADOM, taskID, state))
        print

def create_adomrev(fmgADOM, hostADMIN):
    json_url = "dvmdb/adom/" + fmgADOM + "/revision"
    body = {
        "id": 1,
        "method": "add",
        "params": [{
            "url": json_url,
            "data": {
                "locked": 0,
                "desc": "Created via JSON API",
                "name": "Post ADOM DB upgrade",
                "created_by": hostADMIN
            }
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    print ('--> Creating ADOM revision')
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
    print
    time.sleep( 2 )

# Check ADOM exists
def check_adom(adom):
    json_url = "dvmdb/adom/" + adom
    body = {
    "id": 1,
        "method": "get",
        "params":[  {
               "url": json_url,
        }],
        "session": session
    }
    print("\n")
    print(f'<-- Checking ADOM {adom}')    
    # Test HTTPS connection to host then Capture and output any errors
    try:
        r = requests.post(url, json=body, verify=False)
    except requests.exceptions.RequestException as e:
        print('<--!!!ERROR!!! Connection to FMG failed, please check FMG connection and try again, existing...') 
        print (SystemError(e))
        time.sleep(5)
        # Exit Program, Connection was not Successful
        sys.exit(1)
    # Save JSON response from FortiManager
    json_resp = json.loads(r.text)
    # Check if User & Passwd was valid, no code -11 means invalid
    if json_resp['result'][0]['status']['code'] == 0:
        print(f'<-- Verified ADOM {adom} exists\n')
    else:
        print (f'<--!!!ERROR!!! ADOM not found! {adom}, please try again, exiting...')
        # HTTP & JSON code & message
        print ('<-- HTTPcode: %d JSONmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))
        print
        time.sleep(5)
        # Exit Program
        sys.exit(1)

##Install Policy Package
def installPOLICY(pADOM):
    global taskID
    policyPACK = []
    ##Get Policy Packages
    json_url = "/pm/pkg/adom/" + pADOM
    body = {
    "id": 1,
            "method": "get",
            "params": [{
                    #"fields": [
                    #    [
                    #        "name"
                    #    ]
                    #],                        
                    "url": json_url,
            }],
            "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    #print(r.content)
    #print(json_resp['result'][0]['data']['name'])

    ##Get all Policy Package Names
    for entry in json_resp['result'][0]['data']:
        policyPACK.append(entry['name'])
        #print(entry['name'])
        #print(r.content)
    
    ##Install loop ALL Policy Package Names
    for pp in policyPACK:    
        if pp != "default":        
        ##Install Policy Package
            json_url2 = "securityconsole/install/package"
            body = {
            "id": 1,
                    "method": "exec",
                    "params": [{
                        "data": {
                            "adom": pADOM,
                            "flags": [
                                "install_cfg"
                            ],
                            "pkg": pp
                        },
                        "url": json_url2
                    }],
                    "session": session
            }
            r2 = requests.post(url, json=body, verify=False)
            json_resp2 = json.loads(r2.text)    
            taskID = json_resp2['result'][0]['data']['task']
            print
            print ('>>>>')
            print ('>>>>')
            print ('--> Perform Install of Policy Package %s on ADOM %s' % (pp, pADOM))
            print ('<-- Hcode: %d Jmesg: %s' % (r2.status_code, json_resp2['result'][0]['status']['message']))
            print
            time.sleep( 0.3 )
            poll_taskid(pADOM)
            print ('--> Policy Install Completed for Policy Package %s on ADOM %s. Check logs & Task Monitor for Errors' % (pp, pADOM))
    ###END LOOP
    
    ###Save
    workspace_commit(pADOM)

##Change SSL Inspection from Full to Cert on all Policies
def check_clone_profile(csADOM):
    global taskID
    #VARS
    sslPROFILE = []
    
    #####Get SSL-SSH-Profile Names
    json_url = "/pm/config/adom/" + csADOM + "/obj/firewall/ssl-ssh-profile"
    body = {
    "id": 1,
            "method": "get",
            "params": [{
                    "url": json_url,
            }],
            "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    ###print(json_resp['result'][0]['data']['name'])
    #
    for entry in json_resp['result'][0]['data']:
        sslPROFILE.append(entry['name'])
        #print(entry['name'])
    ####print(r.content)
    #DUMP IT ALL    print(json.dumps(json_resp, indent=4, sort_keys=True))

    for profile in sslPROFILE:    
        if profile == "ENC_Options01":
            return True
    return False

#Update all profiles that are not default - certificate-inspection, deep-inspection, no-inspection
def update_all_profiles(csADOM):
    #VARS
    sslPROFILE = []
    read_only_profile = ['certificate-inspection', 'deep-inspection', 'no-inspection']

    #####Get SSL-SSH-Profile Names
    json_url = "/pm/config/adom/" + csADOM + "/obj/firewall/ssl-ssh-profile"
    body = {
    "id": 1,
            "method": "get",
            "params": [{
                    "url": json_url,
            }],
            "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    ###print(json_resp['result'][0]['data']['name'])
    # Get profile name and create a list
    for entry in json_resp['result'][0]['data']:
        #Check if status = cert_inspection, do updates
        if entry['https']['status'] == 1:
            sslPROFILE.append(entry['name'])

    # Go through the profiles and if not default read-only update cert-probe-failure allow, cert-validation-failure allow
    for i, profile in enumerate(sslPROFILE):
        if profile not in read_only_profile:
            json_url2 = "/pm/config/adom/" + csADOM + "/obj/firewall/ssl-ssh-profile/" + profile
            body = {
            "id": 1,
                    "method": "update",
                    "params": [{
                        "data": {
                            "https": {
                                "cert-probe-failure": 1,
                                "cert-validation-failure": 0,
                            }
                        },
                            "url": json_url2,
                    }],
                    "session": session
            }
            r2 = requests.post(url, json=body, verify=False)
            json_resp2 = json.loads(r2.text)
            print("\n")
            print ('--> Updating SSL-SSH Profile %s to cert-probe-failure allow & set cert-validation-failure allow for ADOM %s' % (profile, csADOM))
            print ('<-- Hcode: %d Jmesg: %s' % (r2.status_code, json_resp2['result'][0]['status']['message']))    

    ###Save SSL-SSH Inspection Changes
    workspace_commit(csADOM)

def update_cert_probe_failure(csADOM):
    profile = "ENC_Options01"

    #Update cert-probe-failure to allow (not default)
    json_url = "/pm/config/adom/" + csADOM + "/obj/firewall/ssl-ssh-profile/" + profile # + "/https"
    body = {
            "id": 1,
            "method": "update",
            "params": [{
                "data": {
                    "https": {
                        "cert-probe-failure": 1,
                        "cert-validation-failure": 0,
                        # "unsupported-ssl-version": 1,
                        "status": 1,
                        "ports": 443,
                    },
                    "ftps": {
                        "status": 0,
                    },
                    "imaps": {
                        "status": 0,
                    },
                    "pop3s": {
                         "status": 0,
                    },
                    "smtps": {
                         "status": 0,
                    },
                    "ssh": {
                         "status": 0,
                    },
                    "dot": {
                         "status": 0,
                    }
                },
                "url": json_url
            }],
            "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)

    print("\n")
    print ('--> Updating SSL-SSH Profile %s to cert-probe-failure allow for ADOM %s' % (profile, csADOM))
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))    

    ###Save SSL-SSH Inspection Changes
    workspace_commit(csADOM)

def update_profile_comments(csADOM):
    profile_deep_name = "deep-inspection"
    profile_deep_comment = "Read-only SSL deep inspection profile. DO NOT USE"
    profile_cert_name = "certificate-inspection"
    profile_cert_comment = "Read-only SSL handshake inspection profile. DO NOT USE"

    #Update deep inspect profile
    json_url = "/pm/config/adom/" + csADOM + "/obj/firewall/ssl-ssh-profile/" + profile_deep_name
    body = {
            "id": 1,
            "method": "update",
            "params": [{
                "data": {
                    "comment": profile_deep_comment
                },
                "url": json_url
            }],
            "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)

    print("\n")
    print ('--> Updating SSL-SSH Profile %s comments for ADOM %s' % (profile_deep_name, csADOM))
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))

    #Update cert inspect profile
    json_url = "/pm/config/adom/" + csADOM + "/obj/firewall/ssl-ssh-profile/" + profile_cert_name
    body = {
            "id": 1,
            "method": "update",
            "params": [{
                "data": {
                    "comment": profile_cert_comment
                },
                "url": json_url
            }],
            "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)

    print("\n")
    print ('--> Updating SSL-SSH Profile %s comments for ADOM %s' % (profile_cert_name, csADOM))
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))      

    ###Save SSL-SSH Inspection Comment Changes
    workspace_commit(csADOM)


def get_ssl_profile_config(csADOM, profileNAME):
    #Get SSL Profile configs
    json_url = "/pm/config/adom/" + csADOM + "/obj/firewall/ssl-ssh-profile/" + profileNAME #+ "/https"
    body = {
            "id": 1,
            "method": "get",
            "params": [{
                "url": json_url
            }],
            "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    # print(f'profile output GET {json_resp}')    

def clone_ssl_profile(csADOM):
    profile_name = "certificate-inspection"
    clone_profile_name = "ENC_Options01"
    comment_update = "General Use Certificate Inspection"
    revision_note = "Creating clone of certificate-inspection with cert-probe-failure updated"

    # clone profile
    json_url = "/pm/config/adom/" + csADOM + "/obj/firewall/ssl-ssh-profile/" + profile_name
    body = {
            "id": 1,
            "method": "clone",
            "params": [{
                "data": {
                    "name": clone_profile_name,
                    "comment": comment_update
                },
                "url": json_url
            }],
            "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    # print(f'Clone profile for cloning... {json_resp}')    

    print("\n")
    print ('--> Cloning SSL-SSH Profile certificate-inspection to ENC_Options01 with cert-probe-failure allow for ADOM %s' % (csADOM))
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))    

    ###Save SSL-SSH Inspection Changes
    workspace_commit(csADOM)

    ### Update
    update_cert_probe_failure(csADOM)

def remove_oid(data):
    if isinstance(data, dict):
        data.pop("oid", None)  # Remove 'oid' if it exists
        for key in data:
            remove_oid(data[key])  # Recursively check nested dictionaries
    elif isinstance(data, list):
        for item in data:
            remove_oid(item)  # Recursively check list elements

def get_policy_packages(csADOM):
    policy_pkg_list = []

    json_url = 'pm/pkg/adom/' + csADOM
    body = {
        "id": 1,
        "method": "get",
        "params": [{
            "url": json_url
        }],
        "session": session
    }
    r = requests.post(url, json=body, verify=False)
    json_resp = json.loads(r.text)
    # print(f'GET policy package {json.dumps(json_resp, indent=2)}')
    print ('--> Getting Policy Packages for ADOM: %s' % (csADOM))
    print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))    
    
    for entry in json_resp['result'][0]['data']:
        # print(f'policy packages {entry["name"]}')
        policy_pkg_list.append(entry['name'])
    
    if policy_pkg_list:
        print("\n")
        print ('--> Policy packages for ADOM: %s found: %s' % (csADOM, policy_pkg_list))
        print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))        
    else:
        print("\n")
        print ('--> No Policy Packages found for ADOM: %s' % (csADOM))
        print ('<-- Hcode: %d Jmesg: %s' % (r.status_code, json_resp['result'][0]['status']['message']))    
    
    return policy_pkg_list

def update_fw_policy_ssl(csADOM, policyPKG):
    cert_inspect_profile = "certificate-inspection"
    profile = "ENC_Options01"
    pkg_updated = False

    print("\n")
    print("--> Processing ADOM: %s Policy Packages..." % (csADOM))

    for pkg_name in policyPKG:
        json_url = 'pm/config/adom/' + csADOM + '/pkg/' + pkg_name + '/firewall/policy'
        body = {
            "id": 1,
            "method": "get",
            "params": [{
                "fields": [
                    "policyid",
                    "ssl-ssh-profile",
                ],
                "filter": [
                    "ssl-ssh-profile", "==", cert_inspect_profile
                ],
                "url": json_url
            }],
            "session": session
        }
        r = requests.post(url, json=body, verify=False)
        json_resp = json.loads(r.text)
        # print(f'GET policy package {json.dumps(json_resp, indent=2)}')

        # Updating the individual policies for pkg
        if json_resp['result'][0]['data']:
            print("\n")
            print ('--> Policy packages for ADOM: %s found policies in PKG: %s to update...' % (csADOM,pkg_name))

            for entry in json_resp['result'][0]['data']:
                # Update policy
                json_url2 = 'pm/config/adom/' + csADOM + '/pkg/' + pkg_name + '/firewall/policy'
                body2 = {
                    "id": 1,
                    "method": "update",
                    "params": [{
                        "data": {
                            "policyid": entry['policyid'],
                            "ssl-ssh-profile": profile
                        },
                        "url": json_url2
                    }],
                    "session": session
                }
                r2 = requests.post(url, json=body2, verify=False)
                json_resp2 = json.loads(r2.text)
                # print(f'Policy Package results... {json.dumps(json_resp2, indent=2)}')

                # Verify success or not
                if json_resp2['result'][0]['status']['code'] != -11:
                    print("\n")
                    print ("--> Updated Policy id: %s in PKG: %s for ADOM: %s" % (entry['policyid'], pkg_name, csADOM))
                    pkg_updated = True
                else:
                    print("\n")
                    print ("--> ERROR Updating Policy id: %s in PKG: %s for ADOM: %s ", (entry['policyid'], pkg_name, csADOM))
                    ERRORlog.write("--> ERROR Updating Policy id: %s in PKG: %s for ADOM: %s ", (entry['policyid'], pkg_name, csADOM))
            # Save/Commit if changes done
            if pkg_updated:
                workspace_commit(csADOM)
                pkg_updated = False
        else:
            print("\n")
            print ('--> No policies found needing update in Policy PKG: %s for ADOM: %s' % (pkg_name, csADOM))


##########
#### MAIN
##########

# Main section
def main():
    ### Warning message
    print ('\n==DISCLAIMER==\nThis script will be doing the following: \n Look at each ADOM ssl certificate profiles, clone new profile if needed, then update cert-probe-failure to allow. Update all Firewall Rules that are using the default ssl certificate profile to clone profile. \nThis script will ask for the FortiGate Cluster then find all ADOM associated to update. \n\nIt is the responsibility of the user to verify via FortiManager => System Settings => Event Log and/or FortiManager => System Settings => Task Monitor changes done.\nLog files will be created for viewing when completed "mainLOG.txt", ERRORlog.txt".\n====')
    print ('!!! Please make sure a FortiManager Backup and/or Snapshot(vm) before running script.Thanks!!!!\n==\n')

    ### Get variables from user input
    print ('--> Prompting for variables to use \n--> Please provide values or except defaults\n')

    ### Get FortiManager Info
    print ('================FMG=============')
    print(f'FortiManager IP address? (default: {default_hostIP}): ')
    hostIP = input()
    if hostIP == '':
        hostIP = default_hostIP
    print ('    Using: %s' % hostIP)

    print(f'FortiManager API admin (Read/Write required)? (default: {default_hostADMIN}): ')
    hostADMIN = input()
    if hostADMIN == '':
        hostADMIN = default_hostADMIN
    print ('    Using: %s' % hostADMIN)

    hostPASSWD = getpass.getpass('FortiManager API password? (default: ---): ')
    if hostPASSWD == '':
        hostPASSWD = default_hostPASSWD
    hostPASSWDlength = (len(hostPASSWD))
    secret = '*' * hostPASSWDlength
    print ('    Using: %s' % secret)

    # Option for user
    while (default_userOPTION := input("\nPlease select from the following options: (type 1 or 2) \n 1) Update SSL Certificate Profile & Firewall Policies in one ADOM \n 2) Update SSL Certificate Profile & Firewall Policies for multiple ADOMs based on the FortiGate Cluster Device Name\n ")).strip() not in ["1", "2"]:
        print("\nInvalid option. Please try again.")
    print(f"You selected option {default_userOPTION}\n")

    # Selected option from user
    match default_userOPTION:
        case "1":
                while (adomNAME := input("Please enter ADOM name as need in FMG:\n")).strip() == "":  
                    print("ADOM name cannot be empty. Please try again.\n")
                continue_script()
        case "2":
                print(f'FortiGate device name as seen in FMG device mgr tab? (default: {default_fgtDEVname}): ')
                fgtDEVname = input()
                if fgtDEVname == '':
                    fgtDEVname = default_fgtDEVname
                print ('    Using: %s' % fgtDEVname)
                # Check with user on above input before starting
                continue_script()
        
    ### Log into FMG
    print
    print ('-=-' * 20)
    print ('Logging into FMG %s' % hostIP)
    print ('-=-' * 20)
    print
    ### FMG Login
    fmg_login(hostADMIN, hostPASSWD, hostIP)

    match default_userOPTION:
        case "1":
            # Check ADOM exists
            check_adom(adomNAME)

            #Lock ADOM
            workspace_lock(adomNAME)

            # if it doesn't exist, clone profile
            if check_clone_profile(adomNAME): 
                update_cert_probe_failure(adomNAME)
                update_profile_comments(adomNAME)
                update_all_profiles(adomNAME)
            else:
                clone_ssl_profile(adomNAME)
                update_profile_comments(adomNAME)
                update_all_profiles(adomNAME)

            #Get Policy Packages
            policy_packages = get_policy_packages(adomNAME)

            #Get SSL Profiles in Policy
            if policy_packages:
                update_fw_policy_ssl(adomNAME, policy_packages)
                #Install Policy
                installPOLICY(adomNAME)
            else:
                print("\n")
                print ('--> No Policy Packages found for ADOM: %s, skipping ADOM ssl profile updates' % (adomNAME))

            #UnLock ADOM
            workspace_unlock(adomNAME)

            # #check
            # profileNAME="ENC_Options01"
            # get_ssl_profile_config(adomNAME, profileNAME)

        case "2":
            # Get ADOM list based on FortiGate Device
            get_adom(fgtDEVname)
            print ("\n")
            print(f"<-- Found following ADOM(s) for FortiGate Device {fgtDEVname}:") 
            for myadom in adomLIST:
                print(myadom)
            continue_script()

            # Process ADOMs
            # addressNAMELIST = []
            for myadom in adomLIST:
                #Lock ADOM
                workspace_lock(myadom)

                # Check if Clone Profile exists, if not created it. 
                if check_clone_profile(myadom): 
                    update_cert_probe_failure(myadom)
                    update_profile_comments(myadom)
                    update_all_profiles(myadom)
                else:
                    clone_ssl_profile(myadom)
                    update_profile_comments(myadom)
                    update_all_profiles(myadom)

                # Get Policy Packages
                policy_packages = get_policy_packages(myadom)

                # Get SSL Profiles in Policy
                if policy_packages:
                    update_fw_policy_ssl(myadom, policy_packages)
                    #Install Policy
                    installPOLICY(myadom)
                else:
                    print("\n")
                    print ('--> No Policy Packages found for ADOM: %s, skipping ADOM ssl profile updates' % (myadom))

                #UnLock ADOM
                workspace_unlock(myadom)

                #check
                # profileNAME="ENC_Options01"
                # get_ssl_profile_config(myadom, profileNAME)
            
    ## Logout
    fmg_logout(hostIP)

    ## Exit Program, save Log file, keep Terminal Window Open for Customer experience with EXE
    print ('-=-' * 20)
    stopwatchTOTAL = time.time()-stopwatchSTART
    print ('>>>>>> %s ran for %d seconds <<<<<<' % (sys.argv[0], stopwatchTOTAL))
    print ('-=-' * 20)

    print ('>> Stop logging script output to mainLOG.txt <<')
    ERRORlog.close()
    transcript.stop()
    print ('-=-' * 20)
    print ('Completed Script, for Log files please view "mainLOG.txt" and "ERRORlog.txt" .\n')
    print ('Closing console in 5..4..3..2..1.')
    time.sleep( 5 )

####Run MAIN FUNCTION
if __name__ == "__main__":
    main()

######
### EOF
######