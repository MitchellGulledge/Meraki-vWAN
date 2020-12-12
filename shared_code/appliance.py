import os
import meraki

from __app__.shared_code.mx import MX

API_KEY = os.environ.get('meraki_api_key')
PRIMARY_SERIAL = 'primarySerial'
SECONDARY_SERIAL = 'spareSerial'

class Appliance():
    '''
    Appliance encapsulates configuation of MX in a network.
    If HA is configured, self.warmspare_enabled will be True and
    self.secondary will also have the MX information.
    '''
    def __init__(self, network_id:str, enabled:bool, primary_serial:str, secondary_serial:str, org_id=None):
        '''
        Construct a new 'Appliance' object.

        @param network_id:       Network ID of Meraki Dashboard
        @param enabled:          If warmspare is enabled or not
        @param primary_serial:   Serial number of the primary MX
        @param secondary_serial: Serial number of the secondary MX
        @return:                 None
        '''
        self.network_id = network_id
        self.org_id = org_id
        self.warmspare_enabled = enabled
        self.primary = MX(network_id, self._get_mx(primary_serial), org_id) if primary_serial else MX()
        self.secondary = MX(network_id, self._get_mx(secondary_serial), org_id) if secondary_serial else MX()

    def _get_mx(self, serial: str):
        '''
        Obtains the information of the Meraki device by serial number.

        @param   serial: serial number
        @rtype:          dict or None
        @return:         Information of the Meraki device
        '''
        try:
            mdashboard = meraki.DashboardAPI(api_key=API_KEY, suppress_logging=True, print_console=True)
            return mdashboard.devices.getDevice(serial)
        except:
            return

    def get_wan_links(self):
        '''
        Returns a list of dictionaries which includes information of WAN links
        of the MX setup.

        @rtype:  dict
        @return: Information of WAN links
        '''
        links = {}
        if self.warmspare_enabled:
            public_ips = []
            if self.primary.wan1.public_ip and self.primary.wan1.public_ip not in public_ips:
                links['primary-wan1'] = {
                    'ipaddress': self.primary.wan1.public_ip,
                    'isp': self.primary.wan1.service_provider,
                    'linkspeed': self.primary.wan1.limit_down
                }
                public_ips.append(self.primary.wan1.public_ip)
            if self.primary.wan2.public_ip and self.primary.wan2.public_ip not in public_ips:
                links['primary-wan2'] = {
                    'ipaddress': self.primary.wan2.public_ip,
                    'isp': self.primary.wan2.service_provider,
                    'linkspeed': self.primary.wan2.limit_down
                }
                public_ips.append(self.primary.wan2.public_ip)
            if self.secondary.wan1.public_ip and self.secondary.wan1.public_ip not in public_ips:
                links['secondary-wan1'] = {
                    'ipaddress': self.secondary.wan1.public_ip,
                    'isp': self.secondary.wan1.service_provider,
                    'linkspeed': self.secondary.wan1.limit_down
                }
                public_ips.append(self.secondary.wan1.public_ip)
            if self.secondary.wan2.public_ip and self.secondary.wan2.public_ip not in public_ips:
                links['secondary-wan2'] = {
                    'ipaddress': self.secondary.wan2.public_ip,
                    'isp': self.secondary.wan2.service_provider,
                    'linkspeed': self.secondary.wan2.limit_down
                }
                public_ips.append(self.secondary.wan2.public_ip)
        else:
            links['wan1'] = {
                'ipaddress': self.primary.wan1.public_ip,
                'isp': self.primary.wan1.service_provider,
                'linkspeed': self.primary.wan1.limit_down
            }
            if self.primary.wan2.public_ip and self.primary.wan2.public_ip != self.primary.wan1.public_ip:
                links['wan2'] = {
                    'ipaddress': self.primary.wan2.public_ip,
                    'isp': self.primary.wan2.service_provider,
                    'linkspeed': self.primary.wan2.limit_down
                }
        return links

    def is_firmware_compliant(self):
        '''
        Checks if the firmware is compliant.

        @rtype:  boolean
        @return: True or False
        '''
        return self.primary.is_firmware_compliant()
