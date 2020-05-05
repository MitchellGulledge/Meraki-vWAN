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
Below is a list of all the necessary Meraki credentials
'''

# Meraki credentials are placed below
meraki_config = {
	'api_key': "",
	'orgName': ""
}

'''
Below is a list of all the necessary Azure credentials
'''
azure_config = {
	'azure_ad_tenant_id': "",
	'client_id': "",
	'client_secret': "",
	'subscription_id': "",
	'vwan_name': "",
	'vwan_hub_name': "",
	'storage_account_name': "",
	'storage_account_container': "",
	'scope': ["https://management.azure.com/.default"],
    'storage_account_blob': ""
}

'''
End user configurations for Azure
'''

def siteConfig(location, vwanID, addressPrefixes, site_name, wans):
	site_config = {"tags": {
				},
					"location": location,
					"properties": {
						"virtualWan": {
							"id": vwanID
						},
						"addressSpace": {
							"addressPrefixes": [
								addressPrefixes
							]
						},
						"isSecuritySite": False,
						"vpnSiteLinks": [
							{
								"name": site_name + "-wan1",
								"properties": {
									"ipAddress": wans['wan1']['ipaddress'],
									"linkProperties": {
										"linkProviderName": wans['wan1']['isp'],
										"linkSpeedInMbps": 1000 # This will be updated with the port variable calculated below
									}
								}
							}, {
								"name": site_name + "-wan2",
								"properties": {
									"ipAddress": wans['wan2']['ipaddress'],
									"linkProperties": {
										"linkProviderName": wans['wan2']['isp'],
										"linkSpeedInMbps": 1000 # This will be updated with the port variable calculated below
									}
								}
							}
						]
					}
				}
	return site_config

# Authenticate to azure via Service Principal
app = msal.ConfidentialClientApplication(
	azure_config['client_id'], authority="https://login.microsoftonline.com/" + azure_config['azure_ad_tenant_id'],
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

# writing function to obtain org ID via linking ORG name
mdashboard = meraki.DashboardAPI(meraki_config['api_key'])
result_org_id = mdashboard.organizations.getOrganizations()
for x in result_org_id:
    if x['name'] == meraki_config['orgName']:
        meraki_config['org_id'] = x['id']

# Generate random password for site to site VPN config
psk = pwgenerator.generate()
print(psk)

# branch subnets is a variable to display local branch site info
branchsubnets = []
# variable with new and existing s2s VPN config
merakivpns = []

# performing initial get to obtain all Meraki existing VPN info to add to merakivpns list above
originalvpn = mdashboard.organizations.getOrganizationThirdPartyVPNPeers(
    meraki_config['org_id']
)
merakivpns.append(originalvpn)

# Meraki call to obtain Network information
tagsnetwork = mdashboard.networks.getOrganizationNetworks(meraki_config['org_id'])

# loop that iterates through the variable tagsnetwork and matches networks with vWAN in the tag
for i in tagsnetwork:
    if i['tags'] is None:
        pass
    elif "vWAN-" in i['tags']:
        network_info = i['id'] # need network ID in order to obtain device/serial information
        netname = i['name'] # network name used to label Meraki VPN and Azure config
        nettag = i['tags']  # obtaining all tags for network as this will be placed in VPN config
        va = mdashboard.networks.getNetworkSiteToSiteVpn(network_info) # gets branch local vpn subnets
        testextract = ([x['localSubnet'] for x in va['subnets']
						if x['useVpn'] == True])  # list comprehension to filter for subnets in vpn
        (testextract)
        privsub = str(testextract)[1:-1] # needed to parse brackets
        devices = mdashboard.devices.getNetworkDevices(network_info) # call to get device info
        xdevices = devices[0]
        up = xdevices['serial'] # serial number to later obtain the uplink information for the appliance
        firmwareversion = xdevices['firmware'] # now we obtained the firmware version, need to still add the validation portion
        firmwarecompliance = str(firmwareversion).startswith("wired-15") # validation to say True False if appliance is on 15 firmware
        if firmwarecompliance == True:
            print("firmware is compliant, continuing")
        else:
            break # if box isnt firmware compliant we break from the loop
        modelnumber = xdevices['model']

        uplinks = mdashboard.devices.getNetworkDeviceUplink(network_info, up) # obtains uplink information for branch

		# creating keys for dictionaries inside dictionaries
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

        uplinksetting = mdashboard.uplink_settings.getNetworkUplinkSettings(network_info) # obtains meraki sd wan traffic shaping uplink settings
        for g in uplinks_info:
			# loops through the variable uplinks_info which reveals the value for each uplink key
            if uplinks_info['WAN2']['status'] == "Active" or uplinks_info['WAN2']['status'] == "Ready" and uplinks_info['WAN1']['status'] == "Active" or uplinks_info['WAN1']['status'] == "Ready":
                print("both uplinks active")

                pubs = uplinks_info['WAN2']['publicIp']
                pubssec = uplinks_info['WAN1']['publicIp']
                secondaryuplinkindicator = 'True'

                port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])/1000
                wan2port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])/1000

            elif uplinks_info['WAN2']['status'] == "Active":
                pubs = uplinks_info['WAN2']['publicIp']
                port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])/1000

            elif uplinks_info['WAN1']['status'] == "Active":
                pubs = uplinks_info['WAN1']['publicIp']
                port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])/1000

            else:
                print("uplink info error")


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


        sp(pubs, pubssec) # defining SP function and placing both primary and secondary IPs to get provider
        localsp = splist[0]
        secisp = splist[1]

		# Don't use the same public IP for both links; use a place holder
        if(pubs == pubssec):
                pubssec = "1.2.3.4"

        # listing site below in output with branch information
        if secondaryuplinkindicator == 'True':
            branches = str(netname) + "  " + str(pubs) + "  " + str(localsp) + "  " + str(port) + "  " + str(pubssec) + "  " + str(secisp) + "  " + str(wan2port) + "  " + str(privsub)
        else:
            branches = str(netname) + "  " +  str(pubs) + "  " +  str(localsp) + "  " +  str(port) + "  " +  str(privsub)

        print(branches)

        netname2 = netname.replace(' ', '')


		# If the site has two uplinks; create and update vwan site with data in API call to contain two links
        if secondaryuplinkindicator == 'True':
            wans = {'wan1': {'ipaddress': pubs, 'isp': localsp},
                    'wan2': {'ipaddress': pubssec, 'isp': secisp}}
        else:			
            wans = {'wan1': {'ipaddress': pubs, 'isp': localsp}}

        privsubnoquptes = privsub.replace("'", "")
        print(privsubnoquptes)

        site_config = siteConfig(vwan_hub_info['location'], virtualWAN['id'], privsubnoquptes, netname2, wans) # here we are parsing private subnets wrong

		# Create/Update the vWAN Site + Site Links
        vwan_site_endpoint = "https://management.azure.com/subscriptions/" + \
								azure_config['subscription_id'] + "/resourceGroups/" + \
								virtualWAN['resourceGroup'] + \
								"/providers/Microsoft.Network/vpnSites/"

        vwan_site_status = requests.put(
                vwan_site_endpoint + "/" + netname2 + "?api-version=2019-12-01",
                headers={'Authorization': 'Bearer ' + result['access_token']}, json=site_config)

        if (vwan_site_status.status_code < 200 and vwan_site_status.status_code > 202):
            print("Failed adding/updating vWAN site")
            print(vwan_site_status.text)
            exit()

        print(json.dumps(vwan_site_status.json(), indent=2))

		#######################################
		# Connect Site Link to VWAN Hub
		#######################################

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
									"ipsecIntegrity": "SHA256",
									"ikeEncryption": "AES256",
									"ikeIntegrity": "SHA256",
									"dhGroup": "DHGroup14",
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

        if (vwan_hub_info.status_code < 200 and vwan_hub_info.status_code > 202):
            print("Failed creating Virtual WAN connection")
            print(vwan_hub_info.text)
            exit()

        print(json.dumps(vwan_hub_info.json(), indent=2))

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
        print(keys)
        storage_account_key = keys['keys'][0]['value']

        # Generate SAS URL
        token = BlobSasPermissions(read=True, add=False, create=False, write=True)
        sas_url = 'https://' + azure_config['storage_account_name'] + '.blob.core.windows.net/' + azure_config[
            'storage_account_container'] + '/' + azure_config['storage_account_blob'] + '?' + generate_blob_sas(
            azure_config['storage_account_name'], azure_config['storage_account_container'], azure_config['storage_account_blob'],
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

        # here we are going to try and correctly parse the vwan config file
       
        azureinstance0 = "192.0.2.1" # placeholder value
        azureinstance1 = "192.0.2.2" # placeholder value
        azureconnectedsubnets = ['1.1.1.1'] # placeholder value
    
        for element in vwan_config_file:
            if element['vpnSiteConfiguration']['Name'] == 'DorothyHomeMX-DONOTTOUCH': # replace with netname2 variable for site name
                print('Found your match')
                ins0 = element['vpnSiteConnections'][0]['gatewayConfiguration']['IpAddresses']['Instance0'] # parses primary Azure IP
                ins1 = element['vpnSiteConnections'][0]['gatewayConfiguration']['IpAddresses']['Instance1'] # parses backup Azure IP
                consubnets = element['vpnSiteConnections'][0]['hubConfiguration']['ConnectedSubnets'] # Connected subnets in Azure
                azureinstance0 = str(ins0)
                azureinstance1 = str(ins1)
                azureconnectedsubnets = consubnets

        print(azureinstance0)
        print(azureinstance1)
        print(azureconnectedsubnets)
        print("look above")

        specifictag = re.findall(r'[v]+[W]+[A]+[N]+[-]+[0-999]', str(nettag))
         
        azconsubnets = json.dumps(azureconnectedsubnets)

        # sample IPsec template config that is later replaced with corresponding Azure variables (PSK pub IP, lan IP etc)
        putdata1 = '{"name":"placeholder","publicIp":"192.0.0.0","privateSubnets":["0.0.0.0/0"],"secret":"meraki123", "ipsecPolicies":{"ikeCipherAlgo":["aes256"],"ikeAuthAlgo":["sha1"],"ikeDiffieHellmanGroup":["group2"],"ikeLifetime":28800,"childCipherAlgo":["aes256"],"childAuthAlgo":["sha1"],"childPfsGroup":["group2"],"childLifetime":3600},"networkTags":["west"]}'
        database = putdata1.replace("west", specifictag[0]) # applies specific tag from org overview page to ipsec config
        updatedata = database.replace('192.0.0.0', azureinstance0)   # change variable to intance 0 IP
        updatedata1 = updatedata.replace('placeholder' , netname) # replaces placeholder value with dashboard network name
        addprivsub = updatedata1.replace('["0.0.0.0/0"]', str(azconsubnets)) # replace with azure private networks
        addpsk = addprivsub.replace('meraki123', psk) # replace with pre shared key variable generated above
        newmerakivpns = merakivpns[0]
        
        # creating second data input to append instance 1 to the merakivpn list
        
        putdata2 = '{"name":"theplaceholder","publicIp":"192.1.0.0","privateSubnets":["0.0.0.0/1"],"secret":"meraki223", "ipsecPolicies":{"ikeCipherAlgo":["aes256"],"ikeAuthAlgo":["sha1"],"ikeDiffieHellmanGroup":["group2"],"ikeLifetime":28800,"childCipherAlgo":["aes256"],"childAuthAlgo":["sha1"],"childPfsGroup":["group2"],"childLifetime":3600},"networkTags":["east"]}'
        
        secondaryvpnname = str(netname2) + "-sec"
        database2 = putdata2.replace("east", specifictag[0]) # applies specific tag from org overview page to ipsec config need to make this secondary
        updatedata2 = database2.replace('192.1.0.0', azureinstance1)
        updatedata3 = updatedata2.replace('theplaceholder' , secondaryvpnname) # replaces placeholder value with dashboard network name
        addprivsub3 = updatedata3.replace('["0.0.0.0/1"]', str(azconsubnets)) # replace with azure private networks
        addpsk2 = addprivsub3.replace('meraki223', psk) # replace with pre shared key variable generated above


        found = 0
        for site in merakivpns: # should be new meraki vpns variable
            print(type(site))
            for namesite in site:
                if netname == namesite['name']:
                    found = 1
        if found == 0:
            print(type(addpsk))
            #newmerakivpns.append(addpsk)    
            newmerakivpns.append(json.loads(addpsk)) # appending new vpn config with original vpn config
            newmerakivpns.append(json.loads(addpsk2))
        print(found)

# Final Call to Update Meraki VPN config with Parsed Blob from Azure 
updatemvpn = mdashboard.organizations.updateOrganizationThirdPartyVPNPeers(
    meraki_config['org_id'], merakivpns[0]
)
print(updatemvpn)
