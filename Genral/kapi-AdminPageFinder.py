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
                   
    ###########    ''' + color.BOLD + '''Tool: ''' + color.UNDERLINE + '''Admin pages finder''' + color.END + '''
   *,     ####     ''' + color.BOLD + '''Version:''' + color.END + ''' 0.1
         ###.      ''' + color.BOLD + '''Date:''' + color.END + ''' 03-Jan-2019
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
parser.add_argument('-t', '--type', type=str, choices=["DIR","RB","PHP","ASP","CFM","JSP","CGI","BRF","ALL"], required=True, help="Type of web application")

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

_URIs = ["acceso","account","adm","adtest","adm_auth","adm/admloginuser","adm/index","admin","admin_area","admin_area/admin","admin_area/index","admin_area/login","admin_login","admin-login","admin/account","admin/admin","admin/admin_login","admin/admin-login","admin/adminLogin","admin/controlpanel","admin/cp","admin/home","admin/index","admin/login","admin1","admin2","admin2/index","admin2/login","admin3","admin4","admin5","adminarea","adminarea/admin","adminarea/index","adminarea/login","admincontrol","admincontrol/login","admincp/index.asp","admincp/index","admincp/login.asp","administrator","administrator/account","administrator/index","administrator/login","administratorlogin","adminLogin","adminpanel","admloginuser","affiliate","backoffice","BackOffice/loginpage","bb-admin","bb-admin/admin","bb-admin/index","bb-admin/login","controlpanel","cp","home","instadmin","login","memberadmin","modelsearch/admin","modelsearch/index","modelsearch/login","moderator","moderator/admin","moderator/login","nsw/admin/login","pages/admin/admin-login","panel-administracion","panel-administracion/admin","panel-administracion/index","panel-administracion/login","portal","rcjakar/admin/login","siteadmin/index","siteadmin/login","user","usuario","usuarios","usuarios/login","webadmin","webadmin/admin","webadmin/index","webadmin/login","wp-login"]

_Extensions_PHP = ['.php']
_Extensions_ASP = ['.asp','.aspx','.asmx']
_Extensions_CFM = ['.cfm']
_Extensions_JSP = ['.jsp','.jsf','.do','.action']
_Extensions_CGI = ['.cgi']
_Extensions_BRF = ['.brf']
_Extensions_RB = ['.rb']

_Extensions = ['','/','.html','.htm']

if args.type == "DIR":
	pass
if args.type == "PHP":
	[_Extensions.append(x) for x in _Extensions_PHP]
if args.type == "ASP":
	[_Extensions.append(x) for x in _Extensions_ASP]
if args.type == "CFM":
	[_Extensions.append(x) for x in _Extensions_CFM]
if args.type == "JSP":
	[_Extensions.append(x) for x in _Extensions_JSP]
if args.type == "CGI":
	[_Extensions.append(x) for x in _Extensions_CGI]
if args.type == "BRF":
	[_Extensions.append(x) for x in _Extensions_BRF]
if args.type == "RB":
	[_Extensions.append(x) for x in _Extensions_RB]

if args.type == "ALL":
	[_Extensions.append(x) for x in _Extensions_PHP]
	[_Extensions.append(x) for x in _Extensions_ASP]
	[_Extensions.append(x) for x in _Extensions_CFM]
	[_Extensions.append(x) for x in _Extensions_JSP]
	[_Extensions.append(x) for x in _Extensions_CGI]
	[_Extensions.append(x) for x in _Extensions_BRF]
	[_Extensions.append(x) for x in _Extensions_RB]
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

