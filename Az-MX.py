import requests, json, time
import meraki
import pycurl
import numpy as np
from io import BytesIO
from operator import itemgetter
from passwordgenerator import pwgenerator
import json
import logging
import msal
import re
import urllib.request
from datetime import datetime, timedelta


'''
Below is a list of all the necessary Meraki and Azure credentials
'''

# Meraki credentials are placed below

api_key = ''
header = {"X-Cisco-Meraki-API-Key": "", "Content-Type": "application/json"}

# Optional logging
# logging.basicConfig(level=logging.DEBUG)  # Enable DEBUG log for entire script
# logging.getLogger("msal").setLevel(logging.INFO)  # Optionally disable MSAL DEBUG logs

# Variables for Azure, enter your own credentials between "" below

config = {

        "authority": "",
        "client_id": "",
        "client_secret": "",
        "scope": ["https://management.azure.com/.default"],
        "subscription_id": "",
        "vwan_name": ""
}

storage_account_name = ""
storage_account_container = ""
storage_blob_name = ""
resource_group = ""
vpngw = ""
subscription = ""
vwan_name = ""

# Create a preferably long-lived app instance which maintains a token cache.

app = msal.ConfidentialClientApplication(
    config["client_id"], authority=config["authority"],
    client_credential=config["client_secret"],

    # token_cache=...  # Default cache is in memory only.
                       # You can learn how to use SerializableTokenCache from
                       # https://msal-python.rtfd.io/en/latest/#msal.SerializableTokenCache
    )

# The pattern to acquire a token looks like this.

result = None

# Firstly, looks up a token from cache
# Since we are looking for token for the current app, NOT for an end user,
# notice we give account parameter as None.

result = app.acquire_token_silent(config["scope"], account=None)

if not result:
    logging.info("No suitable token exists in cache. Let's get a new one from AAD.")
    result = app.acquire_token_for_client(scopes=config["scope"])

if "access_token" not in result:
    print(result.get("error"))
    print(result.get("error_description"))
    print(result.get("correlation_id"))  # You may need this when reporting a bug
    exit()

# Get list of VWANs

virtualWANs = requests.get(
            "https://management.azure.com/subscriptions/" + config["subscription_id"] + "/providers/Microsoft.Network/virtualWans?api-version=2019-12-01",
            headers={'Authorization': 'Bearer ' + result['access_token']},).json()

print(virtualWANs)

#print("Rest API call result: \n%s" % json.dumps(virtualWANs, indent=2))

# Find virtual wan instance

virtualWAN = None
for vwan in virtualWANs["value"]:
    if vwan['name'] == config["vwan_name"]:
        virtualWAN = vwan
        break

if virtualWAN is None:
    print("Could not find vWAN instance...")
    exit()

# Build root URL for VWAN Calls

vwan_endpoint = "https://management.azure.com" + virtualWAN["id"]

# Get the resource group -- this may be useful later

virtualWAN["resourceGroup"] = re.search('resourceGroups/(.*)/providers', virtualWAN["id"]).group(1)
resource_group = virtualWAN["resourceGroup"]


# generating random password below for site to site VPN config

psk = pwgenerator.generate()
print(psk)

# start of Meraki loop to update vWAN and VPN site information

branchsubnets = []
merakivpns = []

# below is a org wide Meraki call to obtain all Meraki networks tagged with vWAN-x, with x being variable

networkstags = 'https://api.meraki.com/api/v0/organizations/<orgid>/networks'
tagsnetwork = json.loads(requests.get(networkstags, headers=header).content)
for i in tagsnetwork:
        if i['tags'] is None:
                pass
        elif "vWAN-" in i['tags']:
                network_info = i['id']
                netname = i['name']
                nettag = i['tags'] # need to find all tags
                ma = meraki.DashboardAPI(api_key)
                va = ma.networks.getNetworkSiteToSiteVpn(network_info)
                testextract = ([x['localSubnet'] for x in va['subnets'] if x['useVpn'] == True])  # for placeholder
                (testextract)
                privsub = str(testextract)[1:-1]
                devices = ma.devices.getNetworkDevices(network_info)
                x = devices[0]
                up = x['serial']
                modelnumber = x['model']
                uplinks = json.loads(requests.get('https://api.meraki.com/api/v0/networks/' + network_info + '/devices/' + up + '/uplink', headers=header).content)

                # getting uplinks now

                uplinks_info = dict.fromkeys(['WAN1', 'WAN2', 'Cellular'])
                uplinks_info['WAN1'] = dict.fromkeys(['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])
                uplinks_info['WAN2'] = dict.fromkeys(['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])
                uplinks_info['Cellular'] = dict.fromkeys(['interface', 'status', 'ip', 'provider', 'publicIp', 'model', 'connectionType'])

                for uplink in uplinks:
                    if uplink['interface'] == 'WAN 1':
                        for key in uplink.keys():
                            uplinks_info['WAN1'][key] = uplink[key]
                    elif uplink['interface'] == 'WAN 2':
                        for key in uplink.keys():
                            uplinks_info['WAN2'][key] = uplink[key]
                    elif uplink['interface'] == 'Cellular':
                        for key in uplink.keys():
                            uplinks_info['Cellular'][key] = uplink[key]


                for g in uplinks_info:
                    # also need Failed status and Ready
                    if uplinks_info['WAN2']['status'] == "Active" and uplinks_info['WAN1']['status'] == "Active": # this will grab both uplinks
                        print("both uplinks active")

                        pubs = uplinks_info['WAN2']['publicIp']
                        pubssec = uplinks_info['WAN1']['publicIp']
                        secondaryuplinkindicator = 'True'

                        uplinksetting = json.loads(requests.get('https://api.meraki.com/api/v0/networks/' + network_info + '/uplinkSettings', headers=header).content)
                        port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])
                        wan2port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])

                    elif uplinks_info['WAN2']['status'] == "Active" and uplinks_info['WAN1']['status'] == "Ready":
                        print("WAN 2 primary")

                        pubs = uplinks_info['WAN2']['publicIp']
                        pubssec = uplinks_info['WAN1']['publicIp']
                        secondaryuplinkindicator = 'True'

                        uplinksetting = json.loads(requests.get('https://api.meraki.com/api/v0/networks/' + network_info + '/uplinkSettings', headers=header).content)
                        port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])
                        wan2port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])

                    elif uplinks_info['WAN2']['status'] == "Ready" and uplinks_info['WAN1']['status'] == "Active":
                        print("WAN 1 primary")

                        pubs = uplinks_info['WAN1']['publicIp']
                        pubssec = uplinks_info['WAN2']['publicIp']
                        secondaryuplinkindicator = 'True'

                        uplinksetting = json.loads(requests.get('https://api.meraki.com/api/v0/networks/' + network_info + '/uplinkSettings', headers=header).content)
                        port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])
                        wan2port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])

                    elif uplinks_info['WAN2']['status'] == "Active":
                        pubs = uplinks_info['WAN2']['publicIp']

                        uplinksetting = json.loads(requests.get('https://api.meraki.com/api/v0/networks/' + network_info + '/uplinkSettings', headers=header).content)
                        port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])

                    elif uplinks_info['WAN1']['status'] == "Active":
                        pubs = uplinks_info['WAN1']['publicIp']


                        uplinksetting = json.loads(requests.get('https://api.meraki.com/api/v0/networks/' + network_info + '/uplinkSettings', headers=header).content)
                        port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])

                    else:
                        print("else")

                # writing function to get ISP

                splist = []

                def sp(primispvar, secispvar):
                    b_obj = BytesIO()
                    crl = pycurl.Curl()
                    # Set URL value
                    crl.setopt(crl.URL, 'https://ipapi.co/' + primispvar + '/json/')
                    # Write bytes that are utf-8 encoded
                    crl.setopt(crl.WRITEDATA, b_obj)
                    # Perform a file transfer
                    crl.perform()
                    # End curl session
                    crl.close()
                    # Get the content stored in the BytesIO object (in byte characters)
                    get_body = b_obj.getvalue()
                    # Decode the bytes stored in get_body to HTML and print the result
                    resdict = json.loads(get_body.decode('utf-8'))
                    isp = resdict['org']
                    #print(isp)
                    splist.append(isp)
                    if secondaryuplinkindicator == 'True':
                        b_objsec = BytesIO()
                        crl = pycurl.Curl()
                        # Set URL value
                        crl.setopt(crl.URL, 'https://ipapi.co/' + '76.102.224.16' + '/json/')
                        # Write bytes that are utf-8 encoded
                        crl.setopt(crl.WRITEDATA, b_objsec)
                        # Perform a file transfer
                        crl.perform()
                        # End curl session
                        crl.close()
                        # Get the content stored in the BytesIO object (in byte characters)
                        get_bodysec = b_objsec.getvalue()
                        # Decode the bytes stored in get_body to HTML and print the result
                        resdictsec = json.loads(get_bodysec.decode('utf-8'))
                        ispsec = resdictsec['org']
                        #print(isp)
                        splist.append(ispsec)
                sp(pubs, pubssec)
                localsp = splist[0]
                secisp = splist[1]

                # need to get ISP out of function update this below

                final = (["Model " + str(modelnumber) + str(" Meraki Network Name ") + str(netname) + " Public " + str(pubs) + " Private " +  str(privsub) + " port " + str(port) + " ISP " + localsp]) # added brackets
                branchsubnets.append(final)

                netname2 = netname.replace(' ', '')
                if netname2 in str(virtualWAN):
                    print("found")
                    # need to make VPN site data for second uplink


                    print(secondaryuplinkindicator)

                    if secondaryuplinkindicator == 'True':

                        # need to set psk as each uplink will have different key which we dont support

                        # creating VPN connection


                        vwan_site_endpoint = "https://management.azure.com/subscriptions/" + config["subscription_id"] + "/resourceGroups/" + virtualWAN["resourceGroup"] + "/providers/Microsoft.Network/vpnSites/"

                        site_config = { "tags": {
                    "key1": "value1"
                },
                "location": "westeurope",
                "properties": {
                    "virtualWan": {
                        "id": virtualWAN["id"]
                    },
                    "addressSpace": {
                        "addressPrefixes": [
                            "10.34.0.0/16"
                        ]
                    },
                    "isSecuritySite": False,
                    "vpnSiteLinks": [
                        {
                            "name": "Meraki-Rest-Site",
                            "properties": {
                                "ipAddress": pubs,
                                "linkProperties": {
                                    "linkProviderName": "Meraki",
                                    "linkSpeedInMbps": 1000
                                }
                            }
                        }, {
                            "name": "Meraki-Rest-Site-2",
                            "properties": {
                                "ipAddress": "56.56.56.56",
                                "linkProperties": {
                                    "linkProviderName": "Meraki",
                                    "linkSpeedInMbps": 1000
                                }
                            }
                        }
                    ]
                            }

                        }

                        vwan_site_status = requests.put(
                        vwan_site_endpoint + "/" + netname2 + "?api-version=2019-12-01",
                        headers={'Authorization': 'Bearer ' + result['access_token']},json=site_config)

 
                        if (vwan_site_status.status_code != 200 and vwan_site_status.status_code != 202):

                            print("Failed adding/updating vWAN site")
                            exit()
                        print(vwan_site_status.json())
# need to add data for single uplink

                    else:
                        createvpnsite = requests.put('https://management.azure.com/subscriptions/'+subscription+'/resourceGroups/'+resource_group+'/providers/Microsoft.Network/vpnSites/'+netname2+'?api-version=2019-11-01', data=vpnsitedata, headers=headers)
                        print(createvpnsite)

                else:

                     vwan_site_endpoint = "https://management.azure.com/subscriptions/" + config["subscription_id"] + "/resourceGroups/" + virtualWAN["resourceGroup"] + "/providers/Microsoft.Network/vpnSites/"

                site_config = { "tags": {
                    "key1": "value1"
                },
                "location": "westeurope",
                "properties": {
                    "virtualWan": {
                        "id": virtualWAN["id"]
                    },
                    "addressSpace": {
                        "addressPrefixes": [
                            "10.34.0.0/16"
                        ]
                    },
                    "isSecuritySite": False,
                    "vpnSiteLinks": [
                        {
                            "name": "Meraki-Rest-Site",
                            "properties": {
                                "ipAddress": pubs,
                                "linkProperties": {
                                    "linkProviderName": "Meraki",
                                    "linkSpeedInMbps": 1000
                                }
                            }
                        }, {
                            "name": "Meraki-Rest-Site-2",
                            "properties": {
                                "ipAddress": "56.56.56.56",
                                "linkProperties": {
                                    "linkProviderName": "Meraki",
                                    "linkSpeedInMbps": 1000
                                }
                            }
                        }
                    ]
                            }
                }

                
                vwan_site_status = requests.put(
                vwan_site_endpoint + "/" + netname2 + "?api-version=2019-12-01",
                headers={'Authorization': 'Bearer ' + result['access_token']},json=site_config)


                if (vwan_site_status.status_code != 200 and vwan_site_status.status_code != 202):

                    exit()
                print(vwan_site_status.json())
                # creating vpn connection between vpn site and vpn gateway


# Get list of site configurations

sites = []
for site in virtualWAN["properties"]["vpnSites"]:
    sites.append(site["id"])

# Get storage account keys
storage_endpoint = "https://management.azure.com/subscriptions/" + config["subscription_id"] + "/resourceGroups/" + virtualWAN["resourceGroup"] + "/providers/MIcrosoft.Storage/storageAccounts/" + storage_account_name + "/"
keys = requests.post(
            storage_endpoint + "listKeys?api-version=2019-06-01",
            headers={'Authorization': 'Bearer ' + result['access_token']},).json()

storage_account_key = keys["keys"][0]['value']

# Generate SAS URL

from azure.storage.blob import BlobSasPermissions, generate_blob_sas
token = BlobSasPermissions(read=True,add=False,create=False,write=True)
sas_url = 'https://' + storage_account_name + '.blob.core.windows.net/' + storage_account_container + '/' + storage_blob_name + '?' + generate_blob_sas(storage_account_name, storage_account_container, storage_blob_name, snapshot=None, account_key=storage_account_key, user_delegation_key=None, permission=token, expiry=datetime.utcnow() + timedelta(hours=1), start=datetime.utcnow(), policy_id=None, ip=None)

# Download site configuration file

vwan_config_status = requests.post(
            vwan_endpoint + "/vpnConfiguration?api-version=2019-12-01",
            headers={'Authorization': 'Bearer ' + result['access_token']},json={'vpnSites': sites, 'outputBlobSasUrl': sas_url}).status_code

if vwan_config_status != 202:
    print("Could not get blob configuration")
    exit()

try:
    with urllib.request.urlopen(sas_url) as url:
        vwan_config_file = json.loads(url.read().decode())

except Exception as e:# -*- coding: utf-8 -*-
    print(e)
    print("Could not download config")
    exit()

# Show site configuration file
print(vwan_config_file)

# parsing the VPN config file for public IP of Instance 0

