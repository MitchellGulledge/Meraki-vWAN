import datetime as dt
import json
import logging
import os
import re
import sys
import time
import urllib.request
from datetime import datetime, timedelta
from io import BytesIO
from operator import itemgetter
import time
import azure.functions as func
import meraki
import requests
from IPy import IP
from ipwhois import IPWhois
from passwordgenerator import pwgenerator

_AZURE_MGMT_URL = "https://management.azure.com"
_BLOB_HOST_URL = "blob.core.windows.net"
_YES = "Yes"
_NO = "No"
_VWAN_APPLY_NOW_TAG = 'vwan-apply-now'

def _get_microsoft_network_base_url(mgmt_url, sub_id, rg_name=None, provider="Microsoft.Network"):
    if rg_name:
        return "{0}/subscriptions/{1}/resourceGroups/{2}/providers/{3}".format(mgmt_url, sub_id, rg_name, provider)
    return "{0}/subscriptions/{1}/providers/{2}".format(mgmt_url, sub_id, provider)


def get_bearer_token(resource_uri):
    access_token = None
    try:
        identity_endpoint = os.environ['IDENTITY_ENDPOINT']
        identity_header = os.environ['IDENTITY_HEADER']
    except:
        logging.error("Could not obtain authentication token for Azure. Please ensure "
                      "System Assigned identities have been enabled on the Azure Function.")

    token_auth_uri = f"{identity_endpoint}?resource={resource_uri}&api-version=2017-09-01"
    head_msi = {'secret': identity_header}
    try:
        resp = requests.get(token_auth_uri, headers=head_msi)
        access_token = resp.json()['access_token']
    except Exception as e:
        logging.error("Could not obtain access token to manage other Azure resources.")
        logging.error(e)

    return access_token


def get_site_config(location, vwan_id, address_prefixes, site_name, wans):
    vpn_site_links = [{
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
        vpn_site_links.append({
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

    site_config = {
        "tags": {},
        "location": location,
        "properties": {
            "virtualWan": {
                "id": vwan_id
            },
            "addressSpace": {
                "addressPrefixes": address_prefixes
            },
            "isSecuritySite": False,
            "vpnSiteLinks": vpn_site_links
        }
    }
    return site_config


def get_site_link_config(name, wan, vwan_vpn_site_id, linkspeed, psk):
    site_link_config = {
        "name": f"{name}-{wan}",
        "properties": {
            "vpnSiteLink": {
                "id": f"{vwan_vpn_site_id}/vpnSiteLinks/{name}-{wan}"
            },
            "connectionBandwidth": int(float(linkspeed)),
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
    }
    return site_link_config


def get_meraki_ipsec_config(name, public_ip, private_subnets, secret, network_tags) -> dict:
    ipsec_config = {
        "name": name,
        "ikeVersion": "2",
        "publicIp": public_ip,
        "privateSubnets": private_subnets,
        "secret": secret,
        "ipsecPolicies": {
            "ikeCipherAlgo": ["aes256"],
            "ikeAuthAlgo": ["sha256"],
            "ikeDiffieHellmanGroup": ["group14"],
            "ikeLifetime": 28800,
            "childCipherAlgo": ["aes256"],
            "childAuthAlgo": ["sha256"],
            "childPfsGroup": ["group14"],
            "childLifetime": 3600
        },
        "networkTags": network_tags
    }
    return ipsec_config


def get_meraki_networks_by_tag(tag_name, networks):
    remove_network_id_list = []
    for network in networks:
        if tag_name in str(network['tags']):
            # appending network id variable to list of network ids
            remove_network_id_list.append(network['id'])
    return remove_network_id_list


def clean_meraki_vwan_tags(mdashboard, remove_tag, tagged_networks):
    for network in tagged_networks:
        if remove_tag in str(network['tags']):
            new_tag_list = network['tags'].replace(remove_tag, '')
            mdashboard.networks.updateNetwork(network['id'], tags=new_tag_list)
    return

def meraki_parse_tags(tags):
    tags_list = []
    for tag in tags.strip().split(' '):
        tags_list.append(tag)

    return tags_list

def find_azure_virtual_wan(virtual_wan_name, virtual_wans):
    virtual_wan = None
    for vwan in virtual_wans['value']:
        if vwan['name'] == virtual_wan_name:
            virtual_wan = vwan
            virtual_wan['resourceGroup'] = re.search(r'resourceGroups/(.*)/providers', virtual_wan['id']).group(1)
            break

    return virtual_wan


def get_whois_info(public_ip):
    obj = IPWhois(public_ip)
    res = obj.lookup_whois()
    whois_info = res["nets"][0]['name']
    return whois_info


def get_azure_virtual_wans(header_with_bearer_token):
    endpoint_url = _get_microsoft_network_base_url(_AZURE_MGMT_URL,
                                                   AzureConfig.subscription_id) + "/virtualWans?api-version=2020-05-01"
    virtual_wans_request = requests.get(endpoint_url, headers=header_with_bearer_token)

    if virtual_wans_request.status_code != 200:
        logging.error(
                "Cannot find vWAN resource.  Please make sure you have delegated access in the Azure portal for this "
                "script to have access to your Azure subscription.")
        logging.error(virtual_wans_request.text)
        return None

    return virtual_wans_request.json()


def get_azure_virtual_wan_hub_info(resource_group, header_with_bearer_token):
    vwan_hub_endpoint = _get_microsoft_network_base_url(_AZURE_MGMT_URL, AzureConfig.subscription_id, resource_group)\
                        + f"/virtualHubs/{AzureConfig.vwan_hub_name}?api-version=2020-05-01"
    vwan_hub_info = requests.get(vwan_hub_endpoint, headers=header_with_bearer_token)

    if vwan_hub_info.status_code != 200:
        logging.error("Could not find Virtual WAN Hub")
        logging.error(vwan_hub_info.text)
        return None

    vwan_hub_info = vwan_hub_info.json()
 
    try:
        vwan_hub_info['vpnGatewayName'] = vwan_hub_info['properties']['vpnGateway']['id'].rsplit('/', 1)[1]
    except:
        logging.error(f"VPN Gateway was not provisioned for hub {vwan_hub_info['name']}."
                        "Please provision the VPN Gateway and try again.")
        return None

    return vwan_hub_info

def get_azure_virtual_wan_gateway_config(resource_group, virtual_wan_hub, vpn_gateway_name, header_with_bearer_token):

    vpn_gateway_endpoint = _get_microsoft_network_base_url(_AZURE_MGMT_URL, AzureConfig.subscription_id, resource_group)\
                        + f"/vpnGateways/{vpn_gateway_name}?api-version=2020-05-01"
    vpn_gateway_info = requests.get(vpn_gateway_endpoint, headers=header_with_bearer_token)

    if vpn_gateway_info.status_code != 200:
        logging.error("Could not obtain vWAN Gateway information")
        logging.error(vpn_gateway_info.text)
        return None

    gateway_info = vpn_gateway_info.json()
    gateway_info['connectedVirtualNetworks'] = []

    # Due to no Azure API existing for connected networks to the hub, pull connected VNets via effective routes
    effective_routes_endpoint = _get_microsoft_network_base_url(_AZURE_MGMT_URL, AzureConfig.subscription_id, resource_group)\
                        + f"/virtualHubs/{virtual_wan_hub}/effectiveRoutes?api-version=2020-05-01"
    payload = {
        "VirtualWanResourceType": "RouteTable",
        "ResourceId": f"/subscriptions/{AzureConfig.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/virtualHubs/{virtual_wan_hub}/hubRouteTables/defaultRouteTable"
    }
    effective_routes_endpoint_response = requests.post(effective_routes_endpoint, headers=header_with_bearer_token, data=json.dumps(payload))

    if effective_routes_endpoint_response.status_code == 202 or effective_routes_endpoint_response.status_code == 200:                
        # Get header and pull new endpoint
        if effective_routes_endpoint_response.headers['Azure-AsyncOperation']:
            effective_routes_async_response = requests.get(effective_routes_endpoint_response.headers['Azure-AsyncOperation'],
                                                            headers=header_with_bearer_token)
            for x in range(5):
                time.sleep(10)
                effective_routes_async_result = effective_routes_async_response.json()
                logging.info(f"Retrying for effective routes. Attempt: {x}")
                try:
                    for network in effective_routes_async_result['properties']['output']['value']:
                        if network['nextHopType'] == 'Remote Hub' or network['nextHopType'] == 'Virtual Network Connection':
                            for prefix in network['addressPrefixes']:
                                gateway_info['connectedVirtualNetworks'].append(prefix)
                    break
                except Exception as e:
                    logging.error("Could not obtain effective routes. Trying again...")
                    effective_routes_async_response = requests.get(effective_routes_endpoint_response.headers['Azure-AsyncOperation'],
                                                            headers=header_with_bearer_token)
                
                if x == 4:
                    logging.error("Could not obtain effective routes and 5 attempts.")
                    return None

    else:
        logging.error("Could not obtain effective routes. Assuming no networks.")
        logging.error(vpn_gateway_info.text)
        return None

    if not gateway_info['connectedVirtualNetworks']:
        logging.info(f"No connected virtual networks or hubs to {virtual_wan_hub}")

    return gateway_info


def update_azure_virtual_wan_site_links(resource_group, site_name, header_with_bearer_token, site_config):
    vwan_site_endpoint = _get_microsoft_network_base_url(_AZURE_MGMT_URL, AzureConfig.subscription_id,
                                                         resource_group) + \
                         f"/vpnSites/{site_name}?api-version=2020-05-01"

    vwan_site_status = requests.put(vwan_site_endpoint, headers=header_with_bearer_token, json=site_config)

    if vwan_site_status.status_code < 200 or vwan_site_status.status_code > 202:
        logging.error("Failed adding/updating vWAN site")
        logging.error(vwan_site_status.text)
        return None

    return vwan_site_status.json()


def create_virtual_wan_connection(resource_group, vpn_gateway_name, network_name,
                                  subscription_id, wans, psk, header_with_bearer_token):

    vwan_vpn_site_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}" + \
                                   f"/providers/Microsoft.Network/vpnSites/{network_name}"

    vpn_site_links = []
    for (wan, properties) in wans:
        vpn_site_links.append(get_site_link_config(network_name, wan, vwan_vpn_site_id, properties['linkspeed'], psk))

    connection_config = {
                    "properties": {
                        "remoteVpnSite": {
                            "id": vwan_vpn_site_id
                        },
                        "vpnLinkConnections": vpn_site_links
                    }
                }

    vwan_vpn_gateway_connection_endpoint = _get_microsoft_network_base_url(_AZURE_MGMT_URL,
                                                                           AzureConfig.subscription_id,
                                                                           resource_group) + "/vpnGateways" \
                                                                                             f"/{vpn_gateway_name}/" \
                                                                                             "vpnConnections" \
                                                                                             f"/{network_name}-" \
                                                                                             "connection?" \
                                                                                             "api-version=2020-05-01"
    vwan_connection_info = requests.put(vwan_vpn_gateway_connection_endpoint,
                                        headers=header_with_bearer_token,
                                        json=connection_config)

    if vwan_connection_info.status_code < 200 or vwan_connection_info.status_code > 202:
        logging.error("Failed creating Virtual WAN connection")
        logging.error(vwan_connection_info.text)
        return None

    return vwan_connection_info.json()


class MerakiConfig:
    api_key = os.environ['meraki_api_key'].lower()
    org_name = os.environ['meraki_org_name']
    use_maintenance_window = os.environ['use_maintenance_window']
    maintenance_time_in_utc = int(os.environ['maintenance_time_in_utc'])
    tag_prefix = 'vwan-'
    org_id = None


class AzureConfig:
    subscription_id = os.environ['subscription_id']
    vwan_name = os.environ['vwan_name']
    vwan_hub_name = os.environ['vwan_hub_name']


def main(MerakiTimer: func.TimerRequest) -> None:
    start_time = dt.datetime.utcnow()
    utc_timestamp = start_time.replace(tzinfo=dt.timezone.utc).isoformat()

    logging.info('Python timer trigger function ran at %s', utc_timestamp)
    logging.info('Python version: %s', sys.version)

    # obtain org ID via linking ORG name
    mdashboard = meraki.DashboardAPI(MerakiConfig.api_key)
    result_org_id = mdashboard.organizations.getOrganizations()
    for x in result_org_id:
        if x['name'] == MerakiConfig.org_name:
            MerakiConfig.org_id = x['id']

    if not MerakiConfig.org_id:
        logging.error("Could not find Meraki Organization Name.")
        return

    # Check if any changes have been made to the Meraki configuration
    change_log = mdashboard.change_log.getOrganizationConfigurationChanges(MerakiConfig.org_id, total_pages=1,
                                                                           timespan=300)
    dashboard_config_change_ts = False
    for tag_events in change_log:
        if tag_events['label'] == 'Network tags' or tag_events['label'] == 'VPN subnets':
            dashboard_config_change_ts = True

    # If no maintenance mode, check if changes were made in last 5 minutes or if script has not been run within 5 minutes; check for updates
    if dashboard_config_change_ts is False and MerakiTimer.past_due is False and MerakiConfig.use_maintenance_window == _NO:
        logging.info("No changes in the past 5 minutes have been detected. No updates needed.")
        return

    # Meraki call to obtain Network information
    tags_network = mdashboard.networks.getOrganizationNetworks(MerakiConfig.org_id)

    # Check if we should force changes even if during maintenance window
    # creating list of network IDs that can later be referenced to remove the
    # apply now tag once the script has executed
    remove_network_id_list = get_meraki_networks_by_tag(_VWAN_APPLY_NOW_TAG, tags_network)

    # if we are in maintenance mode or if update now tag is seen
    if (MerakiConfig.use_maintenance_window == _YES and MerakiConfig.maintenance_time_in_utc == start_time.hour) or \
            MerakiConfig.use_maintenance_window == _NO or len(remove_network_id_list) > 0:
        
        # variable with new and existing s2s VPN config
        merakivpns: list = []

        # performing initial get to obtain all Meraki existing VPN info to add to
        # merakivpns list above
        originalvpn = mdashboard.organizations.getOrganizationThirdPartyVPNPeers(MerakiConfig.org_id)
        merakivpns.append(originalvpn)

        # Get access token to authenticate to Azure
        access_token = get_bearer_token(_AZURE_MGMT_URL)
        if access_token is None:
            return
        header_with_bearer_token = {'Authorization': f'Bearer {access_token}'}

        # Get list of Azure Virtual WANs
        virtual_wans = get_azure_virtual_wans(header_with_bearer_token)

        # If no WANs, exit script
        if virtual_wans is None:
            return

        # Find virtual wan instance
        virtual_wan = find_azure_virtual_wan(AzureConfig.vwan_name, virtual_wans)

        if virtual_wan is None:
            logging.error(
                "Could not find vWAN instance.  Please ensure you have created your Virtual WAN resource prior to running "
                "this script or check that the system assigned identity has access to your Virtual WAN instance.")
            return

        # Get VWAN Hub Info
        vwan_hub_info = get_azure_virtual_wan_hub_info(virtual_wan['resourceGroup'], header_with_bearer_token)

        # If no wan hub or VPN Gateway, exit script
        if vwan_hub_info is None:
            return

        # Generate random password for site to site VPN config
        psk = pwgenerator.generate()

        # Get Virtual WAN Gateway Configuration               
        vwan_config = get_azure_virtual_wan_gateway_config(virtual_wan['resourceGroup'], vwan_hub_info['name'], vwan_hub_info['vpnGatewayName'], header_with_bearer_token)
        if vwan_config is None:
            return

        # networks with vWAN in the tag
        found_tagged_networks = False
        for network in tags_network:
            # Check for placeholder network
            if network['name'].lower() == 'tag-placeholder':
                logging.info("Tag-Placeholder network found, skipping.")
                continue

            # Check if tags exist
            if not network['tags']:
                logging.info(f"No tags found for {network['name']}, skipping to next network")
                continue

            # Check if any vwan tags exist
            tags = meraki_parse_tags(network['tags'])

            if not any(re.match(f"(?i){MerakiConfig.tag_prefix}[0-9]+", lowertag) \
                                                for lowertag in (tag.lower() for tag in tags)):
                logging.info(f"No vwan tags found for {network['name']}, skipping to next network") 
                continue

            logging.info(f"Tags found for {network['name']} | Tags: {tags}") 

            # need network ID in order to obtain device/serial information
            network_info = network['id']

            # network name used to label Meraki VPN and Azure config
            netname = str(network['name']).replace(' ', '')

            # obtaining all tags for network as this will be placed in VPN config
            nettag = str(network['tags'])

            # get device info
            devices = mdashboard.devices.getNetworkDevices(network_info)
            xdevices = devices[0]

            # check if appliance is on 15 firmware
            firmwarecompliance = str(xdevices['firmware']).startswith("wired-15")
            if not firmwarecompliance:
                continue  # if box isnt firmware skip to next network

            # gets branch local vpn subnets
            va = mdashboard.networks.getNetworkSiteToSiteVpn(network_info)

            # filter for subnets in vpn
            privsub = ([x['localSubnet'] for x in va['subnets'] if x['useVpn'] is True])

            # serial number to later obtain the uplink information for the appliance
            up = xdevices['serial']

            # obtains uplink information for branch
            uplinks = mdashboard.devices.getNetworkDeviceUplink(network_info, up)

            # obtains meraki sd wan traffic shaping uplink settings
            uplinksetting = mdashboard.uplink_settings.getNetworkUplinkSettings(network_info)

            # creating keys for dictionaries inside dictionaries
            uplinks_info = dict.fromkeys(['WAN1', 'WAN2'])
            uplinks_info['WAN1'] = dict.fromkeys(
                    ['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])
            uplinks_info['WAN2'] = dict.fromkeys(
                    ['interface', 'status', 'ip', 'gateway', 'publicIp', 'dns', 'usingStaticIp'])

            for uplink in uplinks:
                if uplink['interface'] == 'WAN 1':
                    for key in uplink.keys():
                        uplinks_info['WAN1'][key] = uplink[key]
                elif uplink['interface'] == 'WAN 2':
                    for key in uplink.keys():
                        uplinks_info['WAN2'][key] = uplink[key]

            secondary_uplink_indicator = False
            # loops through the variable uplinks_info which reveals the
            # value for each uplink key
            if (uplinks_info['WAN2']['status'] == "Active" or uplinks_info['WAN2']['status'] == "Ready") and (
                    uplinks_info['WAN1']['status'] == "Active" or uplinks_info['WAN1']['status'] == "Ready"):
                logging.info(f"Multiple uplinks are active for {netname}")
                secondary_uplink_indicator = True

                pubs = uplinks_info['WAN1']['publicIp']
                port = uplinksetting['bandwidthLimits']['wan1']['limitDown'] / 1000
                localsp = get_whois_info(pubs)

                pubsec = uplinks_info['WAN2']['publicIp']
                wan2port = uplinksetting['bandwidthLimits']['wan2']['limitDown'] / 1000

                if pubs == pubsec:
                    # Second uplink with same public IP detected
                    # using placeholder value for secondary uplink
                    pubsec = "1.2.3.4"
                    secisp = localsp
                else:
                    secisp = get_whois_info(pubsec)

            elif uplinks_info['WAN2']['status'] == "Active":
                pubs = uplinks_info['WAN2']['publicIp']
                port = uplinksetting['bandwidthLimits']['wan2']['limitDown'] / 1000
                localsp = get_whois_info(pubs)

            elif uplinks_info['WAN1']['status'] == "Active":
                pubs = uplinks_info['WAN1']['publicIp']
                port = uplinksetting['bandwidthLimits']['wan1']['limitDown'] / 1000
                localsp = get_whois_info(pubs)

            else:
                logging.error(f"No uplinks are active for {netname}")
                continue

            # If the site has two uplinks; create and update vwan site with
            wans = {'wan1': {'ipaddress': pubs, 'isp': localsp, 'linkspeed': port}}
            if secondary_uplink_indicator:
                wans['wan2'] = {'ipaddress': pubsec, 'isp': secisp, 'linkspeed': wan2port}

            site_config = get_site_config(vwan_hub_info['location'], virtual_wan['id'], privsub, netname, wans)

            # Create/Update the vWAN Site + Site Links
            virtual_wan_site_link_update = update_azure_virtual_wan_site_links(virtual_wan['resourceGroup'], netname,
                                                                                header_with_bearer_token, site_config)
            if virtual_wan_site_link_update is None:
                return

            # Create Virtual WAN Connection
            vwan_connection_result = create_virtual_wan_connection(virtual_wan['resourceGroup'], vwan_hub_info['vpnGatewayName'], netname,
                                                                AzureConfig.subscription_id, wans.items(), psk, header_with_bearer_token)
            if vwan_connection_result is None:
                return

            # Parse the vwan config file
            azure_instance_0 = "192.0.2.1"  # placeholder value
            azure_instance_1 = "192.0.2.2"  # placeholder value
            azure_connected_subnets = ['1.1.1.1']  # placeholder value

            # Get Azure VPN Gateway Instances
            for instance in vwan_config['properties']['ipConfigurations']:
                if instance['id'] == 'Instance0':
                    azure_instance_0 = instance['publicIpAddress']
                elif instance['id'] == 'Instance1':
                    azure_instance_1 = instance['publicIpAddress']

            # Get Azure connected subnets
            azure_connected_subnets = vwan_config['connectedVirtualNetworks']

            specific_tag = re.findall(f"(?i){MerakiConfig.tag_prefix}[0-9]+", nettag)

            # Build meraki configurations for Azure VWAN VPN Gateway Instance 0 & 1
            azure_instance_0_config = get_meraki_ipsec_config(netname, azure_instance_0, azure_connected_subnets, psk,
                                                                specific_tag[0])
            azure_instance_1_config = get_meraki_ipsec_config(f"{netname}-sec", azure_instance_1,
                                                                azure_connected_subnets, psk, f"{specific_tag[0]}-sec")

            new_meraki_vpns = merakivpns[0]

            if not any(site['name'] == netname for site in new_meraki_vpns):
                # appending new vpn config with original vpn config
                new_meraki_vpns.append(azure_instance_0_config)
                new_meraki_vpns.append(azure_instance_1_config)

            # Update Primary and Backup VPN tunnel shared keys
            for vpnpeers in merakivpns[0]:
                # matches against network name that is meraki network name
                # variable
                if vpnpeers['name'] == netname or vpnpeers['name'] == f'{netname}-sec':
                    if vpnpeers['secret'] != psk:
                        # update the pre shared key for the vpn dictionary
                        vpnpeers['secret'] = psk

            found_tagged_networks = True

        if not found_tagged_networks:
            logging.info("No tagged networks found.")
            return

        # Final Call to Update Meraki VPN config with Parsed Blob from Azure
        update_meraki_vpn = mdashboard.organizations.updateOrganizationThirdPartyVPNPeers(MerakiConfig.org_id,
                                                                                          new_meraki_vpns)

        logging.info("VPN Peers updated!")

        # Cleanup any found vwan-apply-now tags
        if len(remove_network_id_list) > 0:
            clean_meraki_vwan_tags(mdashboard, _VWAN_APPLY_NOW_TAG, tags_network)
    else:
        logging.info("Maintenance mode detected but it is not during scheduled hours "
                     f"or the {_VWAN_APPLY_NOW_TAG} tag has not been detected. Skipping updates")
