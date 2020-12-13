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
from passwordgenerator import pwgenerator

from __app__.shared_code.appliance import Appliance

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
        return None

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

    vpn_site_links = []
    for key in wans.keys():
        site = {
            'name': site_name + '-' + key,
            'properties': {
                'ipAddress': wans[key]['ipaddress'],
                'linkProperties': {
                    'linkProviderName': wans[key]['isp'],
                    'linkSpeedInMbps': wans[key]['linkspeed']
                }
            }
        }
        vpn_site_links.append(site)

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
                    "pfsGroup": "PFS14"
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


def get_mx_from_network_devices(network_devices: list):
    '''
    Returns only the MX information obtained from
    mdashboard.devices.getNetworkDevices(). If it does not exist,
    return an empty list.
    @param network_devices: mdashboard.devices.getNetworkDevices().
    @rtype:   list
    @return:  list of information of MX.
    '''
    result = []
    for network_device in network_devices:
        if network_device['model'][0:2] == 'MX':
            result.append(network_device)
    return result


def meraki_tag_placeholder_network_check_tags(mdashboard, meraki_network_list):

    all_tags = []
    current_tags = []
    placeholder_tags = []

    tags_network_id = None
    require_update = False

    # Loop through networks and find current tagging topology
    for network in meraki_network_list:
        if network['name'].lower() == MerakiConfig.tag_placeholder_network:
            tags_network_id = network['id']
            placeholder_tags = meraki_convert_tags_to_list(network['tags'])
            continue

        # Check if any vwan tags exist
        tags = network['tags']
        if not check_if_meraki_vwan_tags_exist(tags, network['name']):
            continue

        logging.info(f"Tags found for {network['name']} | Tags: {tags}")
        
        # Build list of found tags
        for tag in tags:
            if re.match(MerakiConfig.primary_tag_regex, tag):
                current_tags.append(tag)
                all_tags.append(tag)

    logging.info(f"Current placeholder tags: {placeholder_tags}")
    logging.info(f"Current tags on networks: {current_tags}")

    # Check if we are missing any tags in the tag-placeholder network    
    for tag in current_tags:
        found_primary = False
        found_secondary = False

        for placeholder_tag in placeholder_tags:
            if placeholder_tag.lower() == tag.lower():
                found_primary = True
            if placeholder_tag.lower() == tag.lower()+'-sec':
                found_secondary = True

        if not found_primary or not found_secondary:
            require_update = True

    # Do an update to the tags of tag-placeholder network if all tags don't exist
    if tags_network_id and require_update:
        logging.info("Not all tags were initialized, updating " \
                    f"{MerakiConfig.tag_placeholder_network} network.")       
        MerakiConfig.sdk_auth.networks.updateNetwork(tags_network_id, tags=" ".join(all_tags))

    return


def check_if_meraki_vwan_tags_exist(tags, network_name, vwan_hub_name=""):
    # Check if any vwan tags exist
    if not tags:
        logging.info(f"No tags found for {network_name}, skipping to next network")
        return False

    # Check if tags match the defined vwan hub
    if vwan_hub_name:
        hubs = []
        logging.info(f"Checking if vwan hub {vwan_hub_name} is found in tags {tags} for network {network_name}")
        for tag in tags:
            try:
                temp_vwan_hub_name = re.match(MerakiConfig.primary_tag_regex, tag).group(1)
                if temp_vwan_hub_name not in hubs:
                    hubs.append(temp_vwan_hub_name)
            except:
                continue
        
        if hubs:
            if len(hubs) > 1:
                logging.warning(f"Multiple tagged networks for {network_name} exist. This is not a supported configuration and may " \
                            "cause undesirable behavior. Please ensure only one tag exists for Virtual WAN on this network.")

            for hub in hubs:
                if hub.lower() == vwan_hub_name.lower():
                    return True
                
        logging.info(f"No vwan tags found for vwan hub {vwan_hub_name} on network {network_name}")
        return False
        

    # Check if any vwan tags exist in the list of tags
    if not any(re.match(MerakiConfig.primary_tag_regex, lowertag) \
                                        for lowertag in (tag.lower() for tag in tags)):

        logging.info(f"No vwan tags found for {network_name}, skipping to next network")
        return False

    return True


def clean_meraki_vwan_tags(mdashboard, remove_tag, tagged_networks):
    for network in tagged_networks:
        if remove_tag in str(network['tags']):
            new_tag_list = network['tags'].replace(remove_tag, '')
            MerakiConfig.sdk_auth.networks.updateNetwork(network['id'], tags=new_tag_list)

    return


def meraki_vwan_hubs(tags_network):
    hubs = []
    for network in tags_network:
        tags = network['tags']
        for tag in tags:
            try:
                vwan_hub_name = re.match(MerakiConfig.primary_tag_regex, tag).group(1)
                if vwan_hub_name not in hubs:
                    hubs.append(vwan_hub_name)
            except:
                continue

    return hubs


def find_azure_virtual_wan(virtual_wan_name, virtual_wans):
    virtual_wan = None
    for vwan in virtual_wans['value']:
        if vwan['name'] == virtual_wan_name:
            virtual_wan = vwan
            virtual_wan['resourceGroup'] = re.search(r'resourceGroups/(.*)/providers', virtual_wan['id']).group(1)
            break

    return virtual_wan


def check_vwan_hubs_exist(virtual_wan, tags):

    for tag in tags:
        if tag.lower() not in (vwan_hub['id'].rsplit('/', 1)[-1].lower() \
                                for vwan_hub in virtual_wan['properties']['virtualHubs']):
            return False

    return True


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


def get_azure_virtual_wan_hub_info(resource_group, vwan_hub_name, header_with_bearer_token):
    vwan_hub_endpoint = _get_microsoft_network_base_url(_AZURE_MGMT_URL, AzureConfig.subscription_id, resource_group)\
                        + f"/virtualHubs/{vwan_hub_name}?api-version=2020-05-01"
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

    # Assumption is made here that the defaultRouteTable is being used
    payload = {
        "VirtualWanResourceType": "RouteTable",
        "ResourceId": f"/subscriptions/{AzureConfig.subscription_id}/resourceGroups/{resource_group}/" \
                        f"providers/Microsoft.Network/virtualHubs/{virtual_wan_hub}/hubRouteTables/defaultRouteTable"
    }
    effective_routes_endpoint_response = requests.post(effective_routes_endpoint, json=payload, headers=header_with_bearer_token)

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
                    if not effective_routes_async_result['properties']['output']['value']:
                        logging.info("Virtual WAN hub likely not propagating routes, trying old effective routes APIs")
                        break
                    
                    for network in effective_routes_async_result['properties']['output']['value']:
                        if network['nextHopType'] == 'Remote Hub' or network['nextHopType'] == 'Virtual Network Connection':
                            for prefix in network['addressPrefixes']:
                                gateway_info['connectedVirtualNetworks'].append(prefix)
                    
                    return gateway_info
                except Exception as e:
                    logging.info("Could not obtain effective routes. Trying again...")
                    effective_routes_async_response = requests.get(effective_routes_endpoint_response.headers['Azure-AsyncOperation'],
                                                            headers=header_with_bearer_token)

                if x == 4:
                    logging.error("Could not obtain effective routes and 5 attempts.")
                    return None

            # Pull effective routes using April Virtual WAN APIs
            # If Virtual WAN hub has not been updated for routing service, use older effective routes API
            effective_routes_endpoint = _get_microsoft_network_base_url(_AZURE_MGMT_URL, AzureConfig.subscription_id, resource_group)\
                                + f"/virtualHubs/{virtual_wan_hub}/effectiveRoutes?api-version=2020-04-01"

            effective_routes_endpoint_response = requests.post(effective_routes_endpoint, headers=header_with_bearer_token)

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

    if vwan_connection_info.status_code > 399:
        logging.error("Could not create Virtual WAN connection.")
        logging.error(f"Response: {vwan_connection_info.text}")
        return None

    return vwan_connection_info.json()


class MerakiConfig:
    api_key = os.environ['meraki_api_key'].lower()
    org_name = os.environ['meraki_org_name']
    use_maintenance_window = os.environ['use_maintenance_window']
    maintenance_time_in_utc = int(os.environ['maintenance_time_in_utc'])
    tag_prefix = 'vwan-'
    primary_tag_regex = f"(?i)^{tag_prefix}([a-zA-Z0-9_-]+)-[0-9]+$"
    secondary_tag_regex = f"(?i)^{tag_prefix}([a-zA-Z0-9_-]+)-[0-9]+-sec$"
    org_id = None
    # authenticating to the Meraki SDK
    sdk_auth = meraki.DashboardAPI(api_key)


class AzureConfig:
    subscription_id = os.environ['subscription_id']
    vwan_name = os.environ['vwan_name']


def main(MerakiTimer: func.TimerRequest) -> None:
    start_time = dt.datetime.utcnow()
    utc_timestamp = start_time.replace(tzinfo=dt.timezone.utc).isoformat()

    logging.info('Python timer trigger function ran at %s', utc_timestamp)
    logging.info('Python version: %s', sys.version)

    # Obtain Meraki Org ID for API Calls
    result_org_id = MerakiConfig.sdk_auth.organizations.getOrganizations()
    for x in result_org_id:
        if x['name'] == MerakiConfig.org_name:
            MerakiConfig.org_id = x['id']

    # If no organization is mapped to the customer org name create logging error 
    if not MerakiConfig.org_id:
        logging.error("Could not find Meraki Organization Name.")
        return

    # Check if any config changes have been made to the Meraki configuration
    change_log = MerakiConfig.sdk_auth.organizations.getOrganizationConfigurationChanges(\
        MerakiConfig.org_id, total_pages=1, timespan=300)

    # Creating variable that indicates whether there has been a Meraki config change    
    dashboard_config_change_ts = False

    # Iterating through the event log to match events for vpn changes or network tag changes 
    for tag_events in change_log:
        if tag_events['label'] == 'Network tags' or tag_events['label'] == 'VPN subnets':
            # change detected, indicating config change by changing dashboard_config_change_ts to true
            dashboard_config_change_ts = True

    # If no maintenance mode, check if changes were made in last 5 minutes or 
    # if script has not been run within 5 minutes; check for updates
    if dashboard_config_change_ts is False and MerakiTimer.past_due is False and MerakiConfig.use_maintenance_window == _NO:
        logging.info("No changes in the past 5 minutes have been detected. No updates needed.")
        return

    # Meraki call to obtain Network information
    meraki_networks = MerakiConfig.sdk_auth.organizations.getOrganizationNetworks(
        MerakiConfig.org_id, total_pages='all'
        )

    # Check if tag placeholder network exists, if not create it
    # commenting out as this is no longer needed in v1 of Meraki SDK
    # tags_network = meraki_tag_placeholder_network_check(MerakiConfig.sdk_auth, meraki_networks)

    # Check if we should force changes even if during maintenance window
    # creating list of network IDs that can later be referenced to remove the
    # apply now tag once the script has executed
    remove_network_id_list = get_meraki_networks_by_tag(_VWAN_APPLY_NOW_TAG, meraki_networks)

    # if we are in maintenance mode or if update now tag is seen
    if (MerakiConfig.use_maintenance_window == _YES and MerakiConfig.maintenance_time_in_utc == start_time.hour) or \
            MerakiConfig.use_maintenance_window == _NO or len(remove_network_id_list) > 0:

        # variable with new and existing s2s VPN config
        merakivpns: list = []

        # performing initial get to obtain all Meraki existing VPN info to add to
        # merakivpns list above
        originalvpn = MerakiConfig.sdk_auth.appliance.getOrganizationApplianceVpnThirdPartyVPNPeers(MerakiConfig.org_id)
        merakivpns.append(originalvpn)

        # Get access token to authenticate to Azure
        access_token = get_bearer_token(_AZURE_MGMT_URL)
        if access_token is None:
            return
        header_with_bearer_token = {'Authorization': f'Bearer {access_token}'}

        # Get list of Azure Virtual WANs
        virtual_wans = get_azure_virtual_wans(header_with_bearer_token)
        if virtual_wans is None:
            return

        # Find virtual wan instance
        virtual_wan = find_azure_virtual_wan(AzureConfig.vwan_name, virtual_wans)
        if virtual_wan is None:
            logging.error(
                "Could not find vWAN instance.  Please ensure you have created your Virtual WAN resource prior to running "
                "this script or check that the system assigned identity has access to your Virtual WAN instance.")
            return

        # Complie list of hubs that are in scope for Meraki
        tagged_hubs = meraki_vwan_hubs(meraki_networks)
        logging.info(f"Tagged Virtual WAN Hubs found: {tagged_hubs}")

        # Check if VWAN Hubs in scope exist; if not log an error the hub doesn't exist
        hubs_exist = check_vwan_hubs_exist(virtual_wan, tagged_hubs)
        if(not hubs_exist):
            logging.error("Not all Virtual WAN hubs exist, please ensure all hubs are created.")
            return

        # Generate random password for site to site VPN config
        psk = pwgenerator.generate()

        logging.info("logging meraki vpns: " + str(merakivpns[0]))
        new_meraki_vpns = merakivpns[0]['peers']

        # Loop through each VWAN hub
        for hub in tagged_hubs:

            logging.info(f"Traversing Meraki networks with updates for VWAN Hub: {hub}")

            # Get Virtual WAN hub info
            vwan_hub_info = get_azure_virtual_wan_hub_info(virtual_wan['resourceGroup'], hub, header_with_bearer_token)

            # If no Virtual WAN hub or VPN Gateway, skip this hub
            if vwan_hub_info is None:
                continue

            # Get Virtual WAN Gateway Configuration
            vwan_config = get_azure_virtual_wan_gateway_config(virtual_wan['resourceGroup'], vwan_hub_info['name'], vwan_hub_info['vpnGatewayName'], header_with_bearer_token)
            if vwan_config is None:
                return

            # networks with vWAN in the tag
            found_tagged_networks = False
            for network in meraki_networks:
                # Check for placeholder network
                #if network['name'].lower() == MerakiConfig.tag_placeholder_network:
                #    logging.info(f"{network['name']} network found, skipping.")
                #    continue

                # Check if tags exist
                if not network['tags']:
                    logging.info(f"No tags found for {network['name']}, skipping to next network")
                    continue

                # Check if any vwan tags exist
                if not check_if_meraki_vwan_tags_exist(network['tags'], network['name'], vwan_hub_info['name']):
                    continue

                logging.info(f"Tags found for {network['name']} with hub {vwan_hub_info['name']} \
                    | Tags: {network['tags']}")

                # need network ID in order to obtain device/serial information
                network_info = network['id']

                # network name used to label Meraki VPN and Azure config
                netname = str(network['name']).replace(' ', '')

                try:
                    warm_spare_settings = MerakiConfig.sdk_auth.appliance.getNetworkApplianceWarmSpare(network_info)
                except Exception as e:
                    logging.error('Failed to fetch warm_spare_settings')
                    logging.error(e.message)

                if 'primarySerial' in warm_spare_settings:
                    appliance = Appliance(network_info,
                                          warm_spare_settings.get('enabled'),
                                          warm_spare_settings.get('primarySerial'),
                                          warm_spare_settings.get('spareSerial'),
                                          MerakiConfig.org_id)
                else:
                    logging.info(f"MX device not found in {network['name']}, skipping network.")
                    continue

                # check if appliance is on 15 firmware
                if not appliance.is_firmware_compliant():
                    logging.info(f"MX device for {network['name']} not running v15 firmware, skipping network.")
                    continue  # if box isnt firmware skip to next network

                # gets branch local vpn subnets
                va = MerakiConfig.sdk_auth.appliance.getNetworkApplianceVpnSiteToSiteVpn(network_info)

                # filter for subnets in vpn
                privsub = ([x['localSubnet'] for x in va['subnets'] if x['useVpn'] is True])

                # If the site has two uplinks; create and update vwan site with
                wans = appliance.get_wan_links()

                site_config = get_site_config(vwan_hub_info['location'], virtual_wan['id'], privsub, netname, wans)

                # Create/Update the vWAN Site + Site Links
                virtual_wan_site_link_update = update_azure_virtual_wan_site_links(virtual_wan['resourceGroup'], netname,
                                                                                    header_with_bearer_token, site_config)
                if virtual_wan_site_link_update is None:
                    logging.error(f"Virtual WAN Site Link for {network['name']} could not be created/updated, skipping to next network.")
                    continue

                # Create Virtual WAN Connection
                vwan_connection_result = create_virtual_wan_connection(virtual_wan['resourceGroup'], vwan_hub_info['vpnGatewayName'], netname,
                                                                    AzureConfig.subscription_id, wans.items(), psk, header_with_bearer_token)
                if vwan_connection_result is None:
                    logging.error(f"Virtual WAN Connection for {network['name']} could not be created, skipping to next network.")
                    continue

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
                if vwan_config['connectedVirtualNetworks']:
                    azure_connected_subnets = vwan_config['connectedVirtualNetworks']

                # Get specific vwan tag
                for tag in network['tags']:
                    if re.match(MerakiConfig.primary_tag_regex, tag):
                        specific_tag = tag

                # Build meraki configurations for Azure VWAN VPN Gateway Instance 0 & 1
                azure_instance_0_config = get_meraki_ipsec_config(netname, azure_instance_0,
                                                                azure_connected_subnets, psk, specific_tag)
                azure_instance_1_config = get_meraki_ipsec_config(f"{netname}-sec", azure_instance_1,
                                                                azure_connected_subnets, psk, f"['None']")

                primary_peer_exists = False
                secondary_peer_exists = False

                logging.info("Parsed Meraki VPN output: " + str(merakivpns[0]['peers']))
                for site in merakivpns[0]['peers']:
                    if site['name'] == netname:
                        primary_peer_exists = True
                    if site['name'] == f"{netname}-sec":
                        secondary_peer_exists = True

                if primary_peer_exists:
                    for vpn_peer in merakivpns[0]['peers']:
                        if vpn_peer['name'] == netname:
                            vpn_peer['secret'] = psk
                            vpn_peer['privateSubnets'] = azure_connected_subnets
                else:
                    new_meraki_vpns.append(azure_instance_0_config)

                if secondary_peer_exists:
                    for vpn_peer in merakivpns[0]['peers']:
                        if vpn_peer['name'] == f"{netname}-sec":
                            vpn_peer['secret'] = psk
                            vpn_peer['privateSubnets'] = azure_connected_subnets
                else:
                    new_meraki_vpns.append(azure_instance_1_config)

                found_tagged_networks = True

            if not found_tagged_networks:
                logging.info(f"No tagged networks found for hub {hub}.")
                return

            # Update Meraki VPN config
            update_meraki_vpn = MerakiConfig.sdk_auth.appliance.updateOrganizationApplianceVpnThirdPartyVPNPeers(
                MerakiConfig.org_id, new_meraki_vpns
                )

            logging.info("VPN Peers updated!")

            # Cleanup any found vwan-apply-now tags
            if len(remove_network_id_list) > 0:
                clean_meraki_vwan_tags(MerakiConfig.sdk_auth, _VWAN_APPLY_NOW_TAG, meraki_networks)
    else:
        logging.info("Maintenance mode detected but it is not during scheduled hours "
                     f"or the {_VWAN_APPLY_NOW_TAG} tag has not been detected. Skipping updates")
