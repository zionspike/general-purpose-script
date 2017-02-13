#!/usr/bin/python

import httplib
import socket
import sys

def getInput():
    x = raw_input()
    return x

print "\t################################################################"
print "\t#                             Kapi                             #"
print "\t#                    webServerFootPrint.py                     #"
print "\t#         Web server response header in file result.txt        #"
print "\t################################################################"

print "Enter IP/Url(s) Separated by [\\n] do not include http or https:"

urls = []
_input = getInput()
while not _input == '':
    urls.append(str(_input))
    _input=''
    _input = getInput()

open("result.txt","w+").write("url\tServer\tx-powered-by\tResponseCode\n")
for (x) in urls:
    try:
        print x
        conn = httplib.HTTPConnection(x)
        conn.request("GET", '/')
        res = conn.getresponse()
        print "\tResponse Code: " + str(res.status)
        print "\tx-powered-by : " + str(res.getheader('X-Powered-By'))
        print "\tServer : " + str(res.getheader('Server'))
        with open("result.txt", "a") as myfile:
            myfile.write("\n"+ x + "\t" + str(res.getheader('Server')) + "\t" + str(res.getheader('X-Powered-By')) + "\t" + str(res.status))
    except (httplib.HTTPResponse,socket.error,httplib.BadStatusLine):
        print "Error";