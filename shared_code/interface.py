from __app__.shared_code.helpers import get_whois_info

class Interface():
    '''
    Interface encapsulates the interface information of a Meraki device.
    '''

    def __init__(self, name:str, ip=None):
        '''
        Construct a new 'Interface' object.

        @param   name: Name of the interface e.g. WAN1
        @param   ip:   IP address configured on the interface
        @return:       None
        '''
        self.name = name
        self.status = None
        self.ip = ip
        self.gateway = None
        self.public_ip = None
        self.dns = None
        self.using_static_ip = None
        self.limit_up = None
        self.limit_down = None
        self.service_provider = None

    def get_ip(self):
        '''
        Returns the IP address of the interface

        @rtype:  str
        @return: IP address
        '''
        return self.ip

    def get_status(self):
        '''
        Returns the status of the interface

        @rtype:  str
        @return: Status
        '''
        return self.status

    def get_public_ip(self):
        '''
        Returns the public IP used to communicate with the Meraki Dashboard.
        This could be self.ip if the interface has a public IP confiugred.

        @rtype:  str
        @return: IP address
        '''
        return self.public_ip

    def update(self, data: dict):
        '''
        Updates the parameters of the class.
        The param data should be data obtained from getNetworkDeviceUplink
        or getNetworkUplinkSettings.

        @param   data: Dictionary including data of interface.
        @return:       None
        '''
        if data.get('status'):
            self.status = data['status']
        if data.get('ip'):
            self.ip = data['ip']
        if data.get('gateway'):
            self.gateway = data['gateway']
        if data.get('publicIp'):
            self.public_ip = data['publicIp']
            self.service_provider = get_whois_info(self.public_ip)
        if data.get('dns'):
            self.dns = data['dns']
        if data.get('usingStaticIp'):
            self.using_static_ip = data['usingStaticIp']
        if data.get('limitUp'):
            self.limit_up = int(float(data['limitUp'] / 1000))
        if data.get('limitDown'):
            self.limit_down = int(float(data['limitDown'] / 1000))

