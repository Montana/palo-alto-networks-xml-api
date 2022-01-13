#!/usr/bin/python3
# Python 3 required for some of this on Palo Alto Networks.

from bs4 import BeautifulSoup as BS
import urllib2
import ssl
import urllib

username = "api_test"
password = "supersecurepassword"
firewall = "192.168.111.1"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def req_api(command, key):
    url = "https://%s/api/?key=%s&type=op&cmd=" % (
        firewall, key) + urllib.quote_plus(command)
    res = urllib2.urlopen(url, context=ctx)
    return res.read()


req_api_url = "https://%s/api/?type=keygen&user=%s&password=%s" % (
    firewall, username, password)
res_api_key = urllib2.urlopen(req_api_url, context=ctx)
soup = BS(res_api_key.read(), "lxml")
key = soup.find('key').text

soup = BS(req_api("<show><arp><entry name = 'all'/></arp></show>", key),
          "lxml")

arp_buffer = []

for e in soup("entry"):
    arp_buffer.append([
        e.status.text, e.ip.text, e.ttl.text, e.interface.text, e.port.text,
        e.mac.text
    ])
