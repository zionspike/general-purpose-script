#!/usr/bin/python

from urlparse import urlparse
import requests
import argparse

requests.packages.urllib3.disable_warnings()

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

motd = '''
################################################################
                   
    ###########    ''' + color.BOLD + '''Tool: ''' + color.UNDERLINE + '''Backup files finder''' + color.END + '''
   *,     ####     ''' + color.BOLD + '''Version:''' + color.END + ''' 0.1
         ###.      ''' + color.BOLD + '''Date:''' + color.END + ''' 05-Mar-2019
        ###        
       ###         
     ####     *    
    ###.      #    
   ###########     ''' + color.BOLD + '''Author:''' + color.END + ''' Kapi.Z

################################################################
'''

print motd



parser = argparse.ArgumentParser(description='[!] Finding administrative pages HELP!')
parser.add_argument('-u', '--url', required=True, help='URL included http:// or https://')

args = parser.parse_args()

parsed = urlparse(args.url)

scheme = parsed.scheme if str(parsed.scheme) != "" else "http"
netloc = parsed.netloc if str(parsed.netloc) != "" else ""
path = parsed.path if str(parsed.path) != "" else ""
params = parsed.params if str(parsed.params) != "" else ""
query = parsed.query if str(parsed.query) != "" else ""
fragment = parsed.fragment if str(parsed.fragment) != "" else ""
hostname = parsed.hostname if str(parsed.hostname) != "" else ""
port = parsed.port if parsed.port != None else ""

print '\t[!] scheme  :', scheme
print '\t[!] netloc  :', netloc
print '\t[!] path    :', path
print '\t[!] params  :', params
print '\t[!] query   :', query
print '\t[!] fragment:', fragment
print '\t[!] hostname:', hostname, '(lower case)'
print '\t[!] port    :', port

_URIs = ["","archive","backup","bak","bin","code","source","src"]

_Extensions = ['','./','.0','.1','.2','.~','.arc','.bac','.back','.bak','.bak1','.bakup','.bakup1','.bck','.bk','.bkp','.bz2','.conf','.copy','.cs','.csproj','.cvsignore','.db','.default','.DS_Store','.gz','.inc','.lock','.lt','.nsx','.old','.org','.orig','.original','.rar','.sav','.save','.saved','.sql','.svn','.svnignore','.swo','.swp','.tar','.tar.gz','.tar.bz','.temp','.tmp','.tpl','.txt','.vb','.xml','.zip']


_Results = []
for ext in _Extensions:
	for uri in _URIs:
		url = scheme+"://"+hostname+(":" if str(port) != "" else "")+str(port) + path + uri + ext
		response = requests.head(url, verify=False, allow_redirects=False)
		response_code = str(response.status_code)
		if response_code[:1] == "2":
			print color.RED + "[+] URL: " + url + " \t => [" + response_code + "]" + color.END
			_Results.append(url + " ["+response_code+"] ")
		if response_code[:1] == "3":
			print color.RED + "[+] URL: " + url + " \t => [" + response_code + "]" + color.END
			_Results.append(url + " ["+response_code+"]" + " --> " + response.url)
		else:
			print "[!] URL: " + url + " \t => [" + response_code + "]"

print "[!] --------- Summary ---------"
if len(_Results) > 0:
	print "[+] Found: " + str(len(_Results)) + " potential URLs";
	for x in _Results:
		print "   [+] " + x

