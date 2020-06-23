from azure.storage.blob import BlobSasPermissions, generate_blob_sas
import requests
import json
import time
import meraki
from io import BytesIO
from operator import itemgetter
from passwordgenerator import pwgenerator
import logging
import re
import urllib.request
import os
import sys
import datetime as dt
from ipwhois import IPWhois
from datetime import datetime, timedelta
from IPy import IP
import azure.functions as func

def main(MerakiTimer: func.TimerRequest) -> None:    
    startTime = dt.datetime.utcnow()    
    utc_timestamp = startTime.replace(tzinfo=dt.timezone.utc).isoformat()

    logging.info('Python timer trigger function ran at %s', utc_timestamp)
    logging.info('Python version: %s', sys.version)

    '''
    Below is a list of all the necessary Meraki credentials
    '''

    # Meraki credentials are placed below
    meraki_config = {
        'api_key': os.environ["meraki_api_key"],
        'orgName': os.environ["meraki_orgName"],
        'use_maintenance_window': os.environ["use_maintenance_window"],
        'maintenance_time_in_utc': os.environ["maintenance_time_in_utc"]
    }

    '''
    Below is a list of all the necessary Azure credentials
    '''
    azure_config = {
        'subscription_id': os.environ["subscription_id"],
        'vwan_name': os.environ["vwan_name"],
        'vwan_hub_name': os.environ["vwan_hub_name"],
        'storage_account_name': os.environ["storage_account_name"],
        'storage_account_container': os.environ["storage_account_container"],
        'storage_account_blob': os.environ["storage_account_blob"]
    }

    '''
    End user configurations
    '''

    identity_endpoint = os.environ["IDENTITY_ENDPOINT"]
    identity_header = os.environ["IDENTITY_HEADER"]

    def get_bearer_token(resource_uri):
        token_auth_uri = f"{identity_endpoint}?resource={resource_uri}&api-version=2017-09-01"
        head_msi = {'secret':identity_header}
        try:
            resp = requests.get(token_auth_uri, headers=head_msi)
            access_token = resp.json()['access_token']
        except Exception as e:
            logging.error("Could not obtain access token to manage other Azure resources.")
            logging.debug(e)

        return access_token

    def siteConfig(location, vwanID, addressPrefixes, site_name, wans):
        vpnSiteLinks = [{
                                    "name": site_name + "-wan1",
                                    "properties": {
                                        "ipAddress": wans['wan1']['ipaddress'],
                                        "linkProperties": {
                                            "linkProviderName": wans['wan1']['isp'],
                                            "linkSpeedInMbps": int(float(wans['wan1']['linkspeed']))
                                        }
                                    }
                                }]

        if 'wan2' in wans:
            vpnSiteLinks.append( {
                                    "name": site_name + "-wan2",
                                    "properties": {
                                        "ipAddress": wans['wan2']['ipaddress'],
                                        "linkProperties": {
                                            "linkProviderName": wans['wan2']['isp'],
                                            "linkSpeedInMbps": int(float(wans['wan2']['linkspeed']))
                                        }
                                    }
                                }
            )

        site_config = {"tags": { },
                        "location": location,
                        "properties": {
                            "virtualWan": {
                                "id": vwanID
                            },
                            "addressSpace": {
                                "addressPrefixes": addressPrefixes                                
                            },
                            "isSecuritySite": False,
                            "vpnSiteLinks": vpnSiteLinks                
                        }
                    }
        return site_config

    # obtain org ID via linking ORG name
    mdashboard = meraki.DashboardAPI(meraki_config['api_key'])
    result_org_id = mdashboard.organizations.getOrganizations()
    for x in result_org_id:
        if x['name'] == meraki_config['orgName']:
            meraki_config['org_id'] = x['id']

    if not 'org_id' in meraki_config:
        logging.error("Could not find Meraki Organization Name.")
        return

    # Check if any changes have been made to the Meraki configuration
    change_log = mdashboard.change_log.getOrganizationConfigurationChanges(meraki_config['org_id'],total_pages=1, timespan=300)  
    dashboard_config_change_ts = False
    for tag_events in change_log:
        if tag_events['label'] == 'Network tags':
            dashboard_config_change_ts = True

    if(dashboard_config_change_ts == False and MerakiTimer.past_due == False):
        logging.info("No changes in the past 5 minutes have been detected. No updates needed.")
        return

    # Get access token to authenticate to Azure
    access_token = get_bearer_token("https://management.azure.com/")
    
    # Get list of VWANs
    virtualWANs_request = requests.get("https://management.azure.com/subscriptions/" + azure_config[
        'subscription_id'] + "/providers/Microsoft.Network/virtualWans?api-version=2019-12-01",
                            headers={'Authorization': 'Bearer ' + access_token}, )

    if (virtualWANs_request.status_code != 200):
        logging.error("Cannot find vWAN resource.  Please make sure you have delegated access in the Azure portal for this script to have access to your Azure subscription.")
        logging.debug(virtualWANs_request.text)
        return

    virtualWANs = virtualWANs_request.json()

    # Find virtual wan instance
    virtualWAN = None
    for vwan in virtualWANs['value']:
        if vwan['name'] == azure_config['vwan_name']:
            virtualWAN = vwan
            virtualWAN['resourceGroup'] = re.search(
                'resourceGroups/(.*)/providers', virtualWAN['id']).group(1)
            break

    if virtualWAN is None:
        logging.error("Could not find vWAN instance...")
        return

    # Get VWAN Hub Info
    vwan_hub_endpoint = "https://management.azure.com/subscriptions/" + \
                        azure_config['subscription_id'] + "/resourceGroups/" + virtualWAN['resourceGroup'] + \
                        "/providers/Microsoft.Network/virtualHubs/" + azure_config['vwan_hub_name']
    vwan_hub_info = requests.get(
        vwan_hub_endpoint + "/" + "?api-version=2020-03-01",
        headers={'Authorization': 'Bearer ' + access_token})

    if (vwan_hub_info.status_code != 200):
        logging.error("Cannot find vWAN Hub")
        logging.debug(vwan_hub_info.text)
        return

    vwan_hub_info = vwan_hub_info.json()
    vwan_hub_info['vpnGatewayName'] = vwan_hub_info['properties']['vpnGateway']['id'].rpartition('/')[2]

    # Build root URL for VWAN Calls
    vwan_endpoint = "https://management.azure.com" + virtualWAN['id']

    # Generate random password for site to site VPN config
    psk = pwgenerator.generate()

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

    # Check if we should force changes even if during maintenance window
    # creating list of network IDs that can later be referenced to remove the apply now tag once the script has executed  
    remove_network_id_list = []  
    for apply_now_tag in tagsnetwork:  
        if "vwan-apply-now" in str(apply_now_tag['tags']):  
            remove_network_id = apply_now_tag['id'] # variable that contains network ID of matched tag  
            remove_network_id_list.append(remove_network_id) # appending network id variable to list of network ids

    # if we are in maintenance mode or if update now tag is seen execute loop  
    if (meraki_config['use_maintenance_window'] == 'Yes' and int(meraki_config['maintenance_time_in_utc']) == startTime.hour) or meraki_config['use_maintenance_window'] == 'No' or (len(remove_network_id_list) > 0):
        # loop that iterates through the variable tagsnetwork and matches networks with vWAN in the tag
        for i in tagsnetwork:
            if i['tags'] is None or i['name'] == 'Tag-Placeholder':
                pass
            elif "vWAN-" in i['tags']:
                network_info = i['id'] # need network ID in order to obtain device/serial information
                netname = i['name'] # network name used to label Meraki VPN and Azure config
                nettag = i['tags']  # obtaining all tags for network as this will be placed in VPN config
                va = mdashboard.networks.getNetworkSiteToSiteVpn(network_info) # gets branch local vpn subnets
                privsub = ([x['localSubnet'] for x in va['subnets']
                                if x['useVpn'] == True])  # list comprehension to filter for subnets in vpn
                devices = mdashboard.devices.getNetworkDevices(network_info) # call to get device info
                xdevices = devices[0]
                up = xdevices['serial'] # serial number to later obtain the uplink information for the appliance
                firmwareversion = xdevices['firmware'] # now we obtained the firmware version, need to still add the validation portion
                firmwarecompliance = str(firmwareversion).startswith("wired-15") # validation to say True False if appliance is on 15 firmware
                if not firmwarecompliance:
                    break # if box isnt firmware compliant we break from the loop
                modelnumber = xdevices['model']

                # Check for NAT-T (Not supported by VWAN)
                meraki_local_uplink_ip = IP(xdevices['lanIp'])
                if meraki_local_uplink_ip.iptype() == 'PRIVATE':
                    logging.error('NAT-T Detected for %s', netname)
                    break
                
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
                secondaryuplinkindicator = 'False'
                for g in uplinks_info:
                    # loops through the variable uplinks_info which reveals the value for each uplink key
                    if (uplinks_info['WAN2']['status'] == "Active" or uplinks_info['WAN2']['status'] == "Ready") and (uplinks_info['WAN1']['status'] == "Active" or uplinks_info['WAN1']['status'] == "Ready"):
                        logging.info("both uplinks active")

                        pubs = uplinks_info['WAN1']['publicIp']
                        obj = IPWhois(pubs)
                        res=obj.lookup_whois()
                        localsp = res['nets'][0]['name']

                        pubssec = uplinks_info['WAN2']['publicIp']
                        secondaryuplinkindicator = 'True'
                        if(pubs == pubssec):
                            # NAT-T detected, using a placeholder value
                            pubssec = "1.2.3.4"
                            secisp = localsp
                        else:
                            isp2obj = IPWhois(pubssec)
                            isp2res=obj.lookup_whois()
                            secisp = res['nets'][0]['name']

                        port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])/1000
                        wan2port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])/1000

                    elif uplinks_info['WAN2']['status'] == "Active":
                        pubs = uplinks_info['WAN2']['publicIp']
                        port = (uplinksetting['bandwidthLimits']['wan2']['limitDown'])/1000
                        isp2obj = IPWhois(pubssec)
                        isp2res=obj.lookup_whois()
                        localsp = res['nets'][0]['name']

                    elif uplinks_info['WAN1']['status'] == "Active":
                        pubs = uplinks_info['WAN1']['publicIp']
                        port = (uplinksetting['bandwidthLimits']['wan1']['limitDown'])/1000
                        obj = IPWhois(pubs)
                        res=obj.lookup_whois()
                        localsp = res['nets'][0]['name']

                    else:
                        logging.error("uplink info error")


                # writing function to get ISP
                splist = []

                #################################
                # this logic needs to be fixed to account for WAN 2 being primary instead of always secondary
                #################################
                # listing site below in output with branch information
                if secondaryuplinkindicator == 'True':
                    branches = str(netname) + "  " + str(pubs) + "  " + str(localsp) + "  " + str(port) + "  " + str(pubssec) + "  " + str(secisp) + "  " + str(wan2port) + "  " + str(privsub)
                else:
                    branches = str(netname) + "  " +  str(pubs) + "  " +  str(localsp) + "  " +  str(port) + "  " +  str(privsub)

                netname2 = netname.replace(' ', '')

                # If the site has two uplinks; create and update vwan site with data in API call to contain two links
                if secondaryuplinkindicator == 'True':
                    wans = {'wan1': {'ipaddress': pubs, 'isp': localsp, 'linkspeed': port},
                            'wan2': {'ipaddress': pubssec, 'isp': secisp, 'linkspeed': wan2port}}
                else:			
                    wans = {'wan1': {'ipaddress': pubs, 'isp': localsp, 'linkspeed': port}}

                site_config = siteConfig(vwan_hub_info['location'], virtualWAN['id'], privsub, netname2, wans) # here we are parsing private subnets wrong

                #################################

                # Create/Update the vWAN Site + Site Links
                vwan_site_endpoint = "https://management.azure.com/subscriptions/" + \
                                        azure_config['subscription_id'] + "/resourceGroups/" + \
                                        virtualWAN['resourceGroup'] + \
                                        "/providers/Microsoft.Network/vpnSites/"

                vwan_site_status = requests.put(
                        vwan_site_endpoint + "/" + netname2 + "?api-version=2019-12-01",
                        headers={'Authorization': 'Bearer ' + access_token}, json=site_config)

                if (vwan_site_status.status_code < 200 or vwan_site_status.status_code > 202):
                    logging.error("Failed adding/updating vWAN site")
                    logging.debug(vwan_site_status.text)
                    return

                logging.info(json.dumps(vwan_site_status.json(), indent=2))

                #######################################
                # Connect Site Links to VWAN Hub
                #######################################

                # Connection configuration
                vwan_vpn_site_id = "/subscriptions/" + \
                                    azure_config['subscription_id'] + "/resourceGroups/" + \
                                    virtualWAN['resourceGroup'] + "/providers/Microsoft.Network/vpnSites/" + netname2
                vpnSiteLinks = []
                for (wan, properties) in wans.items():
                    vpnSiteLinks.append({
                                    "name": netname2 + "-"+wan,
                                    "properties": {
                                        "vpnSiteLink": {"id": vwan_vpn_site_id + "/vpnSiteLinks/"+netname2+"-"+wan},
                                        "connectionBandwidth": int(float(properties['linkspeed'])),
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
                                        "vpnConnectionProtocolType": "IKEv2",
                                        "sharedKey": psk,
                                        "enableBgp": False,
                                        "enableRateLimiting": False,
                                        "useLocalAzureIpAddress": False,
                                        "usePolicyBasedTrafficSelectors": False,
                                        "routingWeight": 0
                                    }
                                })

                connection_config = {
                    "properties": {
                        "remoteVpnSite": {
                            "id": vwan_vpn_site_id
                        },
                        "vpnLinkConnections": vpnSiteLinks
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
                    headers={'Authorization': 'Bearer ' + access_token}, json=connection_config)

                if (vwan_hub_info.status_code < 200 or vwan_hub_info.status_code > 202):
                    logging.error("Failed creating Virtual WAN connection")
                    logging.debug(vwan_hub_info.text)
                    return

                logging.info(json.dumps(vwan_hub_info.json(), indent=2))

                # Get list of site configurations
                sites = []
                if('vpnSites' in virtualWAN['properties']):
                    for site in virtualWAN['properties']['vpnSites']:
                        sites.append(site['id'])

                # Get storage account keys
                storage_endpoint = "https://management.azure.com/subscriptions/" + azure_config[
                    'subscription_id'] + "/resourceGroups/" + \
                                virtualWAN['resourceGroup'] + "/providers/Microsoft.Storage/storageAccounts/" + \
                                azure_config['storage_account_name'] + "/"
                keys_request = requests.post(
                    storage_endpoint + "listKeys?api-version=2019-06-01",
                    headers={'Authorization': 'Bearer ' + access_token}, )
                
                if (keys_request.status_code != 200):
                    logging.error("Failed getting storage account keys to write VWAN configuration")
                    logging.debug(keys_request.text)
                    return
                
                keys = keys_request.json()

                storage_account_key = keys['keys'][0]['value']

                # Ensure container exists
                storage_container_endpoint = "https://management.azure.com/subscriptions/" + azure_config[
                    'subscription_id'] + "/resourceGroups/" + \
                                virtualWAN['resourceGroup'] + "/providers/Microsoft.Storage/storageAccounts/" + \
                                azure_config['storage_account_name'] + "/blobServices/default/containers/" + \
                                azure_config['storage_account_container']
                storage_container = requests.put(
                    storage_container_endpoint + "?api-version=2019-06-01",
                    headers={'Authorization': 'Bearer ' + access_token}, json={"properties": {"publicAccess": "None"}})

                if (storage_container.status_code < 200 or storage_container.status_code > 201 ):
                    logging.error("Could not ensure storage account container exists to write Virtual WAN configuration to blob storage.")
                    logging.debug(storage_container.text)
                    return

                # Generate SAS URL
                token = BlobSasPermissions(read=True, add=False, create=False, write=True)
                sas_url = 'https://' + azure_config['storage_account_name'] + '.blob.core.windows.net/' + azure_config[
                    'storage_account_container'] + '/' + azure_config['storage_account_blob'] + '?' + generate_blob_sas(
                    azure_config['storage_account_name'], azure_config['storage_account_container'], azure_config['storage_account_blob'],
                    snapshot=None, account_key=storage_account_key, user_delegation_key=None, permission=token,
                    expiry=datetime.utcnow() + timedelta(hours=1), start=datetime.utcnow(), policy_id=None, ip=None)

                # Write site configuration file to blob storage
                vwan_site_config = requests.post(
                    vwan_endpoint + "/vpnConfiguration?api-version=2020-04-01",
                        headers={'Authorization': 'Bearer ' + access_token},
                    json={'vpnSites': sites, 'outputBlobSasUrl': sas_url})

                if vwan_site_config.status_code != 202:
                    logging.error("Could not get blob configuration")
                    logging.debug(vwan_site_config.text)
                    return

                try:
                    with urllib.request.urlopen(sas_url) as url:
                        vwan_config_file = json.loads(url.read().decode())

                except Exception as e:  # -*- coding: utf-8 -*-
                    logging.error("Could not download config")
                    logging.debug(e)
                    return

                # Show site configuration file
                logging.info(json.dumps(vwan_config_file, indent=2))

                # here we are going to try and correctly parse the vwan config file
            
                azureinstance0 = "192.0.2.1" # placeholder value
                azureinstance1 = "192.0.2.2" # placeholder value
                azureconnectedsubnets = ['1.1.1.1'] # placeholder value
            
                for element in vwan_config_file:
                    if element['vpnSiteConfiguration']['Name'] == netname2: # replace with netname2 variable for site name
                        ins0 = element['vpnSiteConnections'][0]['gatewayConfiguration']['IpAddresses']['Instance0'] # parses primary Azure IP
                        ins1 = element['vpnSiteConnections'][0]['gatewayConfiguration']['IpAddresses']['Instance1'] # parses backup Azure IP
                        consubnets = element['vpnSiteConnections'][0]['hubConfiguration']['ConnectedSubnets'] # Connected subnets in Azure
                        azureinstance0 = str(ins0)
                        azureinstance1 = str(ins1)
                        azureconnectedsubnets = consubnets

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
                database2 = putdata2.replace("east", specifictag[0] + "-sec") # applies specific tag from org overview page to ipsec config need to make this secondary
                updatedata2 = database2.replace('192.1.0.0', azureinstance1)
                updatedata3 = updatedata2.replace('theplaceholder' , secondaryvpnname) # replaces placeholder value with dashboard network name
                addprivsub3 = updatedata3.replace('["0.0.0.0/1"]', str(azconsubnets)) # replace with azure private networks
                addpsk2 = addprivsub3.replace('meraki223', psk) # replace with pre shared key variable generated above

                if not any(site['name'] == netname for site in newmerakivpns):
                    newmerakivpns.append(json.loads(addpsk)) # appending new vpn config with original vpn config
                    newmerakivpns.append(json.loads(addpsk2))

                # updating preshared key for primary VPN tunnel
                for vpnpeers in merakivpns[0]: # iterates through the list of VPNs from the original call
                    if vpnpeers['name'] == netname: # matches against network name that is meraki network name variable
                        if vpnpeers['secret'] != psk: # if statement for if password in VPN doesnt match psk variable
                            vpnpeers['secret'] = psk # updates the pre shared key for the vpn dictionary

                # updating preshared key for backup VPN tunnel
                for vpnpeers in merakivpns[0]: # iterates through the list of VPNs from the original call
                    if vpnpeers['name'] == str(netname2) + '-sec': # matches against network name that is netname variable
                        if vpnpeers['secret'] != psk: # if statement for if password in VPN doesnt match psk variable
                            vpnpeers['secret'] = psk # updates the pre shared key for the vpn dictionary
            else:
                # VWAN tag not found, skip to next tag
                pass

        # Final Call to Update Meraki VPN config with Parsed Blob from Azure 
        updatemvpn = mdashboard.organizations.updateOrganizationThirdPartyVPNPeers(
            meraki_config['org_id'], newmerakivpns
        )
        logging.info(updatemvpn)

        # Cleanup any found vwan-apply-now tags
        if len(remove_network_id_list) > 0:
            for remove_tag in tagsnetwork:
                if "vwan-apply-now" in str(remove_tag['tags']):
                    new_tag_list = remove_tag['tags'].replace('vwan-apply-now','')
                    remove_apply_now_tag = mdashboard.networks.updateNetwork(remove_tag['id'],tags=new_tag_list)

    else:
        logging.info("Maintenance mode detected, but it is not during scheduled hours, nor has the vwan-apply-now tag been detected.  Skipping updates")

