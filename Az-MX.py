import requests, json, time
import subprocess
import meraki
import numpy as np
import re
import pycurl
from io import BytesIO
from operator import itemgetter

# Meraki credentials

api_key = '$meraki-dashboard-api-key'
orgid = '$meraki-org-id'
header = {"X-Cisco-Meraki-API-Key": "$meraki-dashboard-api-key", "Content-Type": "application/json"}

#Azure credentials 

subscription = '$subscription'

vpngw = '$vpngateway-name'
outputblobsasurl2 = '$ouputblobsasurl'


# logging into azure, please update with your username and password

def refreshToken():
    proc = subprocess.Popen("az login -u $username -p $password",stdout=subprocess.PIPE, shell=True)
    (cpu,err) = proc.communicate()
    return
refreshToken()

# getting auth token

tokens = []
def authtoken():
    proc = subprocess.Popen("az account get-access-token --subscription '+subscription+'",stdout=subprocess.PIPE, shell=True)
    (cpu,err) = proc.communicate()
    xi = cpu
    y = json.loads(xi.decode('utf-8'))
    token = y['accessToken']
    tokens.append(token)

    return
authtoken()

x = "Bearer " + tokens[0]

# going to try and download vpn connection now


headers = {'Authorization': 'Bearer + x','Content-Type': 'application/json',}
header1 = {'Authorization': x}
headers.update(header1)

#print(headers)

# Get list of vWAN stuff

vWANlist = json.loads(requests.get('https://management.azure.com/subscriptions/"+subscription+"/providers/Microsoft.Network/virtualWans?api-version=2019-11-01', headers=headers).content)

vpnlist = vWANlist

#print(vpnlist['value'])

value = vpnlist['value']

properties = value[0]
prop = properties['properties']
virtualhubs = prop['virtualHubs']
vpnsites = prop['vpnSites']

#start of meraki loop


branchsubnets = []
merakivpns = []


networkstags = 'https://api.meraki.com/api/v0/organizations/"+orgid+"/networks'
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
                (va)
                (va['subnets'])
                testextract = ([x['localSubnet'] for x in va['subnets'] if x['useVpn'] == True])  # for placeholder
                (testextract)

                privsub = str(testextract)[1:-1]

                devices = ma.devices.getNetworkDevices(network_info)
                x = devices[0]
                up = x['serial']
                modelnumber = x['model']
                print(modelnumber)

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
                    if uplinks_info['WAN2']['status'] == "Active":
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

                def sp():
                    b_obj = BytesIO()
                    crl = pycurl.Curl()
                    # Set URL value
                    crl.setopt(crl.URL, 'https://ipapi.co/' + pubs + '/json/')
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
                sp()
                localsp = splist[0]
    # need to get ISP out of function

                final = (["Model " + str(modelnumber) + str(" Meraki Network Name ") + str(netname) + " Public " + str(pubs) + " Private " +  str(privsub) + " port " + str(port) + " ISP " + localsp]) # added brackets
                branchsubnets.append(final)

#print(branchsubnets[1])

                netname2 = netname.replace(' ', '')
                print(netname2)
                if netname2 in str(vpnlist):
                    print("found")
                    vpnsitedata = '{"tags":{"key1":"value1"},"location":"West US","properties":{"virtualWan":{"id":"/subscriptions/'+subscriprion+'/resourceGroups/MitchellvMX/providers/Microsoft.Network/virtualWans/vWANstandard"},"addressSpace":{"addressPrefixes":['+str(privsub)+']},"deviceProperties": {"deviceVendor": "vendor1","deviceModel": "model01","linkSpeedInMbps": "200"},"isSecuritySite":"false","vpnSiteLinks":[{"name":"'+netname2+'-link","properties":{"ipAddress":"' + str(pubs) + '","linkProperties":{"linkProviderName":"'+str(localsp)+'","linkSpeedInMbps":"'+str(port)+'"}}}]}}'

                    createvpnsite = requests.put('https://management.azure.com/subscriptions/'+subscriprion+'/resourceGroups/MitchellvMX/providers/Microsoft.Network/vpnSites/'+ netname2 +'?api-version=2019-11-01', data=vpnsitedata, headers=headers)
                    print(createvpnsite)

                else:
                    
                    # creating the VPN site
                    print("privatesub")
                    print(str(privsub))


                    vpnsitedata1 = '{"tags":{"key1":"value1"},"location":"West US","properties":{"virtualWan":{"id":"/subscriptions/'+subscriprion+'/resourceGroups/MitchellvMX/providers/Microsoft.Network/virtualWans/vWANstandard"},"addressSpace":{"addressPrefixes":['+str(privsub)+']},"deviceProperties": {"deviceVendor": "vendor1","deviceModel": "model01","linkSpeedInMbps": "200"},"isSecuritySite":"false","vpnSiteLinks":[{"name":"'+netname2+'-link","properties":{"ipAddress":"'+str(pubs)+'","linkProperties":{"linkProviderName":"'+str(localsp)+'","linkSpeedInMbps":"'+str(port)+'"}}}]}}'


                    createvpnsite = requests.put('https://management.azure.com/subscriptions/'+subscription+'/resourceGroups/MitchellvMX/providers/Microsoft.Network/vpnSites/'+netname2+'?api-version=2019-11-01', data=vpnsitedata1, headers=headers)
                    print(createvpnsite)

                    # creating vpn connection between vpn site and vpn gateway


                    vpnconndata1 = '{"properties":{"remoteVpnSite":{"id":"/subscriptions/'+subscriprion+'/resourceGroups/MitchellvMX/providers/Microsoft.Network/vpnSites/'+netname2+'"},"vpnLinkConnections":[{"name":"'+netname2+'-conn","properties":{"vpnSiteLink":{"id":"/subscriptions/fba9b1df-d1b9-4fd7-8253-030be28fcf8b/resourceGroups/MitchellvMX/providers/Microsoft.Network/vpnSites/'+netname2+'/vpnSiteLinks/'+netname2+'-link"},"vpnConnectionProtocolType":"IKEv1"}}]}}'

                    createvpnaz = requests.put('https://management.azure.com/subscriptions/'+subscriprion+'/resourceGroups/MitchellvMX/providers/Microsoft.Network/vpnGateways/'+vpngw+'/vpnConnections/'+netname2+'-connection?api-version=2019-11-01',data=vpnconndata1,headers=headers)
                    print(createvpnaz.reason)


                # now we have to get the VPN config from Azure to update Meraki
                vpnsiteids = (vpnsites)

                res2 = list(map(itemgetter('id'), vpnsiteids))
                # making res3 to change single quotes to double quotes

                res3 = str(res2).replace("'", '"')


                # {"vpnSites": ["/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/vpnSites/abc"],"outputBlobSasUrl": "https://blobcortextesturl.blob.core.windows.net/folderforconfig/vpnFile?sp=rw&se=2018-01-10T03%3A42%3A04Z&sv=2017-04-17&sig=WvXrT5bDmDFfgHs%2Brz%2BjAu123eRCNE9BO0eQYcPDT7pY%3D&sr=b"}


                download = '{"vpnSites": '+str(res3)+', "outputBlobSasUrl":"'+outputblobsasurl2+'"}'
                print(str(download))
                print("look up")


                response = requests.post('https://management.azure.com/subscriptions/'+subscriprion+'/resourceGroups/MitchellvMX/providers/Microsoft.Network/virtualWans/vWANstandard/vpnConfiguration?api-version=2019-11-01', headers=headers,  data=str(download))

                print(response)

                # reading from container to fetch VPN configuration file


                getcontainer = json.loads(requests.get('https://config1581627241639.blob.core.windows.net/test2/config99999x').content)

                vpncontainer = list(map(itemgetter('vpnSiteConnections'), getcontainer))
                gwvpnconfig = list(map(itemgetter('gatewayConfiguration'),vpncontainer[0]))
                azpubip = list(map(itemgetter('IpAddresses'),gwvpnconfig))
                azinstance = list(map(itemgetter('Instance0'),azpubip))
                print(azinstance[0])
                azurepublic = azinstance[0]

                # getting PSK for s2s vpn

                psk = list(map(itemgetter('connectionConfiguration'), vpncontainer[0]))
                psk1 = list(map(itemgetter('PSK'), psk))
                psk2 = psk1[0]

                print("psk below")
                print(psk1)

                # mpw getting private private

                azprivatesubnets = list(map(itemgetter('hubConfiguration'), vpncontainer[0]))
                az_addressspace = list(map(itemgetter('AddressSpace'), azprivatesubnets))
                az_addressspace1 = az_addressspace[0]

                print("gw")
                print(az_addressspace)

                # now we need function to read through blob and get instance 0

                azvpnconfig2 = json.loads(requests.get(outputblobsasurl2).content)

                azpubip2 = []

                for d in azvpnconfig2:
                    if d['vpnSiteConfiguration']['Name'] == netname2:
                        pubazpub = d['vpnSiteConnections'][0]['gatewayConfiguration']['IpAddresses']['Instance0']
                        azpubip2.append(pubazpub)

                #updating the Meraki VPN config
                specifictag = re.findall(r'[v]+[W]+[A]+[N]+[-]+[0-999]', str(nettag))

                putdata1 = '{"name":"MicrosoftvWAN","publicIp":"192.0.0.0","privateSubnets":["0.0.0.0/0"],"secret":"meraki123","ipsecPoliciesPreset":"azure", "networkTags":"west"}'
                database = putdata1.replace("west", specifictag[0]) # right now this is wiping tags to none
                updatedata = database.replace('192.0.0.0', azurepublic)   # change that 145 with a variable we calculate from above
                updatedata1 = updatedata.replace('MicrosoftvWAN' , netname)
                addprivsub = updatedata1.replace("0.0.0.0/0", az_addressspace1)
                addpsk = addprivsub.replace('meraki123', psk2)
                merakivpns.append(addpsk)

vpndata = str(merakivpns)
data22 = vpndata.replace("'", "")
finaldata = ("{\"peers\":" + data22 + "}")
updatevpn1 = requests.put('https://api.meraki.com/api/v0/organizations/'+orgid+'/thirdPartyVPNPeers.json', data=finaldata, headers=header)

print(branchsubnets)
