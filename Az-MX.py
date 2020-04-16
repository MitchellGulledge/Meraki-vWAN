from azure.storage.blob import BlobSasPermissions, generate_blob_sas
import requests
import json
import time
import meraki
import pycurl
import numpy as np
from io import BytesIO
from operator import itemgetter
from passwordgenerator import pwgenerator
import logging
import msal
import re
import urllib.request
from datetime import datetime, timedelta

'''
Below is a list of all the necessary Meraki and Azure credentials
'''

'''
Authors: Mitchell Gulledge
'''

# Meraki credentials are placed below
meraki_config = {
	'api_key': "",
	'org_id': ""
}

# Variables for Azure, enter your own credentials between "" below
azure_config = {
	'azure_ad_tenant_id': "https://login.microsoftonline.com/",
	'client_id': "",
	'client_secret': "",
	'subscription_id': "",
	'vwan_name': "",
	'vwan_hub_name': "",
	'storage_account_name': "",
	'storage_account_container': "",
	'scope': ["https://management.azure.com/.default"]
}

'''
End user configurations
'''

# Setup header used by Meraki API calls
header = {
	'X-Cisco-Meraki-API-Key': meraki_config['api_key'], 'Content-Type': "application/json"}

# Authenticate to azure via Service Principal
app = msal.ConfidentialClientApplication(
	azure_config['client_id'], authority=azure_config['azure_ad_tenant_id'],
	client_credential=azure_config['client_secret']
)

result = None

# Look up token from cache
result = app.acquire_token_silent(azure_config['scope'], account=None)

if not result:
	logging.info(
		"No suitable token exists in cache. Let's get a new one from AAD.")
	result = app.acquire_token_for_client(scopes=azure_config['scope'])

if "access_token" not in result:
	print(result.get("error"))
	print(result.get("error_description"))
	print(result.get("correlation_id"))
	exit()

# Get list of VWANs
virtualWANs = requests.get("https://management.azure.com/subscriptions/" + azure_config[
	'subscription_id'] + "/providers/Microsoft.Network/virtualWans?api-version=2019-12-01",
						   headers={'Authorization': 'Bearer ' + result['access_token']}, ).json()

# Find virtual wan instance
virtualWAN = None
for vwan in virtualWANs['value']:
	if vwan['name'] == azure_config['vwan_name']:
		virtualWAN = vwan
		virtualWAN['resourceGroup'] = re.search(
			'resourceGroups/(.*)/providers', virtualWAN['id']).group(1)
		break

if virtualWAN is None:
	print("Could not find vWAN instance...")
	exit()

# Get VWAN Hub Info
vwan_hub_endpoint = "https://management.azure.com/subscriptions/" + \
					azure_config['subscription_id'] + "/resourceGroups/" + virtualWAN['resourceGroup'] + \
					"/providers/Microsoft.Network/virtualHubs/" + azure_config['vwan_hub_name']
vwan_hub_info = requests.get(
	vwan_hub_endpoint + "/" + "?api-version=2020-03-01",
	headers={'Authorization': 'Bearer ' + result['access_token']})

if (vwan_hub_info.status_code != 200):
	print("Cannot find vWAN Hub")
	print(vwan_hub_info.text)
	exit()

vwan_hub_info = vwan_hub_info.json()
vwan_hub_info['vpnGatewayName'] = vwan_hub_info['properties']['vpnGateway']['id'].rpartition('/')[2]

# Build root URL for VWAN Calls
vwan_endpoint = "https://management.azure.com" + virtualWAN['id']

# start of Meraki loop to update vWAN and VPN site information
branchsubnets = []
merakivpns = []

# below is a org wide Meraki call to obtain all Meraki networks tagged with vWAN-x, with x being variable
networkstags = "https://api.meraki.com/api/v0/organizations/" + \
			   meraki_config['org_id'] + "/networks"
meraki_network_api_endpoint = "https://api.meraki.com/api/v0/networks/"

tagsnetwork = json.loads(requests.get(networkstags, headers=header).content)

for i in tagsnetwork:
	if i['tags'] is None:
		pass
	elif "vWAN-" in i['tags']:
		network_info = i['id']
		netname = i['name']
		nettag = i['tags']  # need to find all tags
		ma = meraki.DashboardAPI(meraki_config['api_key'])
		va = ma.networks.getNetworkSiteToSiteVpn(network_info)
		testextract = ([x['localSubnet'] for x in va['subnets']
						if x['useVpn'] == True])  # for placeholder
		(testextract)
		privsub = str(testextract)[1:-1]
		devices = ma.devices.getNetworkDevices(network_info)
		x = devices[0]
		up = x['serial']
		modelnumber = x['model']
		uplinks = json.loads(requests.get(meraki_network_api_endpoint +
										  network_info + '/devices/' + up + '/uplink', headers=header).content)

		# getting uplinks now

		uplinks_info = dict.fromkeys(['WAN1', 'WAN2', 'Cellular'])
		uplinks_info['WAN1'] = dict.fromkeys(
			['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])
		uplinks_info['WAN2'] = dict.fromkeys(
			['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])
		uplinks_info['Cellular'] = dict.fromkeys(
			['interface', 'status', 'ip', 'provider', 'publicIp', 'model', 'connectionType'])

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
			# this will grab both uplinks
			if uplinks_info['WAN2']['status'] == "Active" and uplinks_info['WAN1']['status'] == "Active":
				print("both uplinks active")

				pubs = uplinks_info['WAN2']['publicIp']
				pubssec = uplinks_info['WAN1']['publicIp']
				secondaryuplinkindicator = 'True'

				uplinksetting = json.loads(requests.get(
					meraki_network_api_endpoint + network_info + "/uplinkSettings", headers=header).content)
				port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])
				wan2port = (
					uplinksetting['bandwidthLimits']['wan2']['limitDown'])

			elif uplinks_info['WAN2']['status'] == "Active" and uplinks_info['WAN1']['status'] == "Ready":
				print("WAN 2 primary")

				pubs = uplinks_info['WAN2']['publicIp']
				pubssec = uplinks_info['WAN1']['publicIp']
				secondaryuplinkindicator = 'True'

				uplinksetting = json.loads(requests.get(
					meraki_network_api_endpoint + network_info + "/uplinkSettings", headers=header).content)
				port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])
				wan2port = (
					uplinksetting['bandwidthLimits']['wan2']['limitDown'])

			elif uplinks_info['WAN2']['status'] == "Ready" and uplinks_info['WAN1']['status'] == "Active":
				print("WAN 1 primary")

				pubs = uplinks_info['WAN1']['publicIp']
				pubssec = uplinks_info['WAN2']['publicIp']
				secondaryuplinkindicator = 'True'

				uplinksetting = json.loads(requests.get(
					meraki_network_api_endpoint + network_info + "/uplinkSettings", headers=header).content)
				port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])
				wan2port = (
					uplinksetting['bandwidthLimits']['wan2']['limitDown'])

			elif uplinks_info['WAN2']['status'] == "Active":
				pubs = uplinks_info['WAN2']['publicIp']

				uplinksetting = json.loads(requests.get(
					meraki_network_api_endpoint + network_info + "/uplinkSettings", headers=header).content)
				port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])

			elif uplinks_info['WAN1']['status'] == "Active":
				pubs = uplinks_info['WAN1']['publicIp']

				uplinksetting = json.loads(requests.get(
					meraki_network_api_endpoint + network_info + "/uplinkSettings", headers=header).content)
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
			# print(isp)
			splist.append(isp)
			if secondaryuplinkindicator == 'True':
				b_objsec = BytesIO()
				crl = pycurl.Curl()
				# Set URL value
				crl.setopt(crl.URL, 'https://ipapi.co/' +
						   '76.102.224.16' + '/json/')
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
				# print(isp)
				splist.append(ispsec)


		sp(pubs, pubssec)
		localsp = splist[0]
		secisp = splist[1]

		# need to get ISP out of function update this below

		final = (["Model " + str(modelnumber) + str(" Meraki Network Name ") + str(netname) + " Public " +
				  str(pubs) + " Private " + str(privsub) + " port " + str(port) + " ISP " + localsp])  # added brackets
		branchsubnets.append(final)

		netname2 = netname.replace(' ', '')
		if netname2 in str(virtualWAN):
			print("found")
			# need to make VPN site data for second uplink

			print(secondaryuplinkindicator)

			if secondaryuplinkindicator == 'True':

				# need to set psk as each uplink will have different key which we dont support

				# creating VPN connection

				vwan_site_endpoint = "https://management.azure.com/subscriptions/" + \
									 azure_config['subscription_id'] + "/resourceGroups/" + \
									 virtualWAN['resourceGroup'] + \
									 "/providers/Microsoft.Network/vpnSites/"

				site_config = {"tags": {
				},
					"location": vwan_hub_info['location'],
					"properties": {
						"virtualWan": {
							"id": virtualWAN['id']
						},
						"addressSpace": {
							"addressPrefixes": [
								str(privsub)[1:-1]
							]
						},
						"isSecuritySite": False,
						"vpnSiteLinks": [
							{
								"name": netname2 + "-wan1",
								"properties": {
									"ipAddress": pubs,
									"linkProperties": {
										"linkProviderName": localsp,
										"linkSpeedInMbps": 1000
									}
								}
							}, {
								"name": netname2 + "-wan2",
								"properties": {
									"ipAddress": "173.36.212.119",
									"linkProperties": {
										"linkProviderName": secisp,
										"linkSpeedInMbps": 1000
									}
								}
							}
						]
					}
				}

				vwan_site_status = requests.put(
					vwan_site_endpoint + "/" + netname2 + "?api-version=2019-12-01",
					headers={'Authorization': 'Bearer ' + result['access_token']}, json=site_config)

				if (vwan_site_status.status_code != 200 and vwan_site_status.status_code != 202):
					print("Failed adding/updating vWAN site")
					print(vwan_site_status.text)
					exit()

				print(json.dumps(vwan_site_status.json(), indent=2))

				#######################################
				# Connect Site Link to VWAN Hub
				#######################################
				# Generate random password for site to site VPN config
				psk = pwgenerator.generate()
				print(psk)

				# Connection configuration
				vwan_vpn_site_id = "/subscriptions/" + \
								   azure_config["subscription_id"] + "/resourceGroups/" + \
								   virtualWAN["resourceGroup"] + "/providers/Microsoft.Network/vpnSites/" + netname2
				connection_config = {
					"properties": {
						"remoteVpnSite": {
							"id": vwan_vpn_site_id
						},
						"vpnLinkConnections": [
							{
								"name": netname2 + "-connection",
								"properties": {
									"vpnSiteLink": {
										"id": vwan_vpn_site_id + "/vpnSiteLinks/"+netname2+"-wan1",
										"id": vwan_vpn_site_id + "/vpnSiteLinks/"+netname2+"-wan2"
									},
									"connectionBandwidth": 200,
									"ipsecPolicies": [
										{
											"saLifeTimeSeconds": 3600,
											"ipsecEncryption": "AES256",
											"ipsecIntegrity": "SHA1",
											"ikeEncryption": "AES256",
											"ikeIntegrity": "SHA1",
											"dhGroup": "DHGroup2",
											"pfsGroup": "None"
										}
									],
									"vpnConnectionProtocolType": "IKEv1",
									"sharedKey": psk,
									"enableBgp": False,
									"enableRateLimiting": False,
									"useLocalAzureIpAddress": False,
									"usePolicyBasedTrafficSelectors": False,
									"routingWeight": 0
								}
							}
						]
					}
				}

				vwan_vpnGateway_connection_endpoint = "https://management.azure.com/subscriptions/" + \
													  azure_config['subscription_id'] + "/resourceGroups/" + virtualWAN[
														  'resourceGroup'] + \
													  "/providers/Microsoft.Network/vpnGateways/" + vwan_hub_info[
														  'vpnGatewayName'] + \
													  "/vpnConnections/" + netname2 + "-connection"
				vwan_hub_info = requests.put(
					vwan_vpnGateway_connection_endpoint + "/" + "?api-version=2020-03-01",
					headers={'Authorization': 'Bearer ' + result['access_token']}, json=connection_config)

				if (vwan_hub_info.status_code != 200 and vwan_hub_info.status_code != 202):
					print("Failed creating Virtual WAN connection")
					print(vwan_hub_info.text)
					exit()

				print(json.dumps(vwan_vpnGateway_connection_endpoint.json(), indent=2))

			# need to add data for single uplink

			else:
				createvpnsite = requests.put('https://management.azure.com/subscriptions/' + azure_config[
					'subscription_id'] + '/resourceGroups/' + virtualWAN[
												 'resourceGroup'] + '/providers/Microsoft.Network/vpnSites/' + netname2 + '?api-version=2019-11-01',
											 data=vpnsitedata, headers=headers)

				print(json.dumps(createvpnsite.json(), indent=2))

		else:
			# Create / Update vWAN Site Links
			vwan_site_endpoint = "https://management.azure.com/subscriptions/" + \
								 azure_config['subscription_id'] + "/resourceGroups/" + \
								 virtualWAN['resourceGroup'] + \
								 "/providers/Microsoft.Network/vpnSites/"

                        site_config = {"tags": {
                                },
                                        "location": vwan_hub_info['location'],
                                        "properties": {
                                                "virtualWan": {
                                                        "id": virtualWAN['id']
                                                },
                                                "addressSpace": {
                                                        "addressPrefixes": [
                                                                str(privsub)[1:-1]
                                                        ]
                                                },
                                                "isSecuritySite": False,
                                                "vpnSiteLinks": [
                                                        {
                                                                "name": netname2 + "-wan1",
                                                                "properties": {
                                                                        "ipAddress": pubs,
                                                                        "linkProperties": {
                                                                                "linkProviderName": localsp,
                                                                                "linkSpeedInMbps": 1000
                                                                        }
                                                                }
                                                        }, {
                                                                "name": netname2 + "-wan2",
                                                                "properties": {
                                                                        "ipAddress": "173.36.212.119",
                                                                        "linkProperties": {
                                                                                "linkProviderName": secisp,
                                                                                "linkSpeedInMbps": 1000
                                                                        }
                                                                }
                                                        }
                                                ]
                                        }
                                }


		vwan_site_status = requests.put(
			vwan_site_endpoint + "/" + netname2 + "?api-version=2019-12-01",
			headers={'Authorization': 'Bearer ' + result['access_token']}, json=site_config)

		if (vwan_site_status.status_code != 200 and vwan_site_status.status_code != 202):
			print("Failed adding/updating vWAN site")
			print(vwan_site_status.text)
			exit()

		print(json.dumps(vwan_site_status.json(), indent=2))

		#######################################
		# Connect Site Link to VWAN Hub
		#######################################
		# Generate random password for site to site VPN config
		psk = pwgenerator.generate()
		print(psk)

		# Connection configuration
		vwan_vpn_site_id = "/subscriptions/" + \
						   azure_config["subscription_id"] + "/resourceGroups/" + \
						   virtualWAN["resourceGroup"] + "/providers/Microsoft.Network/vpnSites/" + netname2
		connection_config = {
			"properties": {
				"remoteVpnSite": {
					"id": vwan_vpn_site_id
				},
				"vpnLinkConnections": [
					{
						"name": netname2 + "-connection",
						"properties": {
							"vpnSiteLink": {
								"id": vwan_vpn_site_id + "/vpnSiteLinks/"+netname2+"-wan1",
								"id": vwan_vpn_site_id + "/vpnSiteLinks/"+netname2+"-wan2"
							},
							"connectionBandwidth": 200,
							"ipsecPolicies": [
								{
									"saLifeTimeSeconds": 3600,
									"ipsecEncryption": "AES256",
									"ipsecIntegrity": "SHA1",
									"ikeEncryption": "AES256",
									"ikeIntegrity": "SHA1",
									"dhGroup": "DHGroup2",
									"pfsGroup": "None"
								}
							],
							"vpnConnectionProtocolType": "IKEv1",
							"sharedKey": psk,
							"enableBgp": False,
							"enableRateLimiting": False,
							"useLocalAzureIpAddress": False,
							"usePolicyBasedTrafficSelectors": False,
							"routingWeight": 0
						}
					}
				]
			}
		}

		vwan_vpnGateway_connection_endpoint = "https://management.azure.com/subscriptions/" + \
											  azure_config['subscription_id'] + "/resourceGroups/" + virtualWAN[
												  'resourceGroup'] + \
											  "/providers/Microsoft.Network/vpnGateways/" + vwan_hub_info[
												  'vpnGatewayName'] + \
											  "/vpnConnections/" + netname2 + "-connection"
		vwan_hub_info = requests.put(
			vwan_vpnGateway_connection_endpoint + "/" + "?api-version=2020-03-01",
			headers={'Authorization': 'Bearer ' + result['access_token']}, json=connection_config)

		if (vwan_hub_info.status_code != 200 and vwan_hub_info.status_code != 202):
			print("Failed creating Virtual WAN connection")
			print(vwan_hub_info.text)
			exit()

		print(json.dumps(vwan_vpnGateway_connection_endpoint.json(), indent=2))

# Get list of site configurations
sites = []
for site in virtualWAN['properties']['vpnSites']:
	sites.append(site['id'])

# Get storage account keys
storage_endpoint = "https://management.azure.com/subscriptions/" + azure_config[
	'subscription_id'] + "/resourceGroups/" + \
				   virtualWAN['resourceGroup'] + "/providers/Microsoft.Storage/storageAccounts/" + \
				   azure_config['storage_account_name'] + "/"
keys = requests.post(
	storage_endpoint + "listKeys?api-version=2019-06-01",
	headers={'Authorization': 'Bearer ' + result['access_token']}, ).json()

storage_account_key = keys['keys'][0]['value']

# Generate SAS URL
token = BlobSasPermissions(read=True, add=False, create=False, write=True)
sas_url = 'https://' + azure_config['storage_account_name'] + '.blob.core.windows.net/' + azure_config[
	'storage_account_container'] + '/' + azure_config['storage_blob_name'] + '?' + generate_blob_sas(
	azure_config['storage_account_name'], azure_config['storage_account_container'], azure_config['storage_blob_name'],
	snapshot=None, account_key=storage_account_key, user_delegation_key=None, permission=token,
	expiry=datetime.utcnow() + timedelta(hours=1), start=datetime.utcnow(), policy_id=None, ip=None)

# Write site configuration file to blob storage
vwan_site_config = requests.post(
	vwan_endpoint + "/vpnConfiguration?api-version=2019-12-01",
	headers={'Authorization': 'Bearer ' + result['access_token']},
	json={'vpnSites': sites, 'outputBlobSasUrl': sas_url})

if vwan_site_config.status_code != 202:
	print("Could not get blob configuration")
	print(vwan_site_config.text)
	exit()

try:
	with urllib.request.urlopen(sas_url) as url:
		vwan_config_file = json.loads(url.read().decode())

except Exception as e:  # -*- coding: utf-8 -*-
	print(e)
	print("Could not download config")
	exit()

# Show site configuration file
print(json.dumps(vwan_config_file, indent=2))

# parsing the VPN config file for public IP of Instance 0
print("made it")
