import os
import meraki

from __app__.shared_code.interface import Interface

API_KEY = API_KEY = os.environ.get('meraki_api_key')
FIRMWARE = 'wired-15'
NOT_CONNECTED = 'Not connected'

class MX():
    '''
    MX encapsulates the information of a MX.
    '''

    def __init__(self, network_id: str='', mx: dict={}):
        '''
        Construct a new 'MX' object.

        @param   network_id: Network ID of Meraki Dashboard
        @param   mx:         Information of the MX obtianed from getNetworkDevice()
        @return:           None
        '''
        self.network_id = network_id
        self.name = mx.get('name', '')
        self.model = mx.get('model', '')
        self.firmware = mx.get('firmware', '')
        self.serial = mx.get('serial', '')
        self.wan1 = Interface('wan1', mx.get('wan1Ip'))
        self.wan2 = Interface('wan2', mx.get('wan2Ip'))
        if self.serial:
            self._get_up_link()
            self._get_up_link_settings()

    def _get_up_link(self):
        '''
        Obtains the uplink information of Meraki MX and updates
        self.wan1 and self.wan2.

        @return: None
        '''
        WAN_1 = 'WAN 1'
        WAN_2 = 'WAN 2'

        mdashboard = meraki.DashboardAPI(api_key=API_KEY, suppress_logging=True, print_console=True)
        org_uplinks = mdashboard.appliance.getOrganizationApplianceUplinkStatuses(MerakiConfig.org_id)
        
        uplinks = []
        
        for sites in org_uplinks:
            if sites['networkId'] == network_id:
                uplinks = sites['uplinks']
        
        for uplink in uplinks:
            if uplink['status'] != NOT_CONNECTED:
                if uplink['interface'] == WAN_1:
                    self.wan1.update(uplink)
                elif uplink['interface'] == WAN_2:
                    self.wan2.update(uplink)

    def _get_up_link_settings(self):
        '''
        Obtains the uplink configuration for SD-WAN and updates
        self.wan1 and self.wan2.

        @rtype: None
        '''
        WAN_1 = 'wan1'
        WAN_2 = 'wan2'

        mdashboard = meraki.DashboardAPI(api_key=API_KEY, suppress_logging=True, print_console=True)
        settings = mdashboard.appliance.getNetworkApplianceTrafficShapingUplinkBandwidth(self.network_id)
        self.wan1.update(settings['bandwidthLimits'][WAN_1])
        self.wan2.update(settings['bandwidthLimits'][WAN_2])

    def get_wan1_ip(self):
        '''
        Return the IP address configured on WAN 1

        @rtype:  str
        @return: IP address
        '''
        if self.wan1:
            return self.wan1.get_ip()

    def get_wan1_status(self):
        '''
        Return the status of WAN 1.

        @rtype:  str
        @return: Status
        '''
        if self.wan1:
            return self.wan1.get_status()

    def get_wan1_public_ip(self):
        '''
        Return the public IP address used to communicate to Meraki
        Dashboard for WAN 1.

        @rtype:  str
        @return: IP address
        '''
        if self.wan1:
            return self.wan1.get_public_ip()

    def get_wan2_ip(self):
        '''
        Return the IP address configured on WAN 2

        @rtype:  str
        @return: IP address
        '''
        if self.wan2:
            return self.wan2.get_ip()

    def get_wan2_status(self):
        '''
        Return the status of WAN 2.

        @rtype:  str
        @return: Status
        '''
        if self.wan2:
            return self.wan2.get_status()

    def get_wan2_public_ip(self):
        '''
        Return the public IP address used to communicate to Meraki
        Dashboard for WAN 2.

        @rtype:  str
        @return: IP address
        '''
        if self.wan2:
            return self.wan2.get_public_ip()

    def is_firmware_compliant(self):
        '''
        Return if the MX is compliant to the firmware version.

        @rtype:  boolean
        @return: True / False
        '''
        return self.firmware[0:8] == FIRMWARE
