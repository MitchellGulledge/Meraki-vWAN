from ipwhois import IPWhois

def get_whois_info(public_ip: str):
    '''
    Returns WAN ISP name.

    @param  public_ip: A public IP addres
    @rtype:            str
    @return:           WAN ISP name
    '''
    obj = IPWhois(public_ip)
    res = obj.lookup_whois()
    whois_info = res["nets"][0]['name']

    return whois_info