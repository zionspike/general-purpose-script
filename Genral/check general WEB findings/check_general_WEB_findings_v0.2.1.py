#!/usr/bin/env python
# Version 0.2
# Developed by Kapi
# This version is able to check the following vulnerabilities:
# [+] check_ssl_protocol
# [+] grab_cert
# [+] check_cert_self_sign
# [+] check_cert_wrong_host
# [+] check_cert_expiry
# [+] check_cert_weak_sign_algo
# [+] check_sweet32
# [+] check_heartbleed
# [+] check_ccs
# check_renego // is not in develop paln, if it's required then will develop
# [+] check_crime
# [+] check_beast
# [+] check_breach
# [+] check_poodle
# [+] check_freak
# [+] check_logjam
# [+] check_drown
# [+] check_rc4
# [+] check_ssl_weak_ciphers
# [+] check_xframe
# [+] check_banner
# [+] check_http_methods
# check_cookie_httponly // to add this feature in next version
# check_cookie_secure // to add this feature in next version

# Please install the following software with precise version of newer
# This script is developed with **testssl.sh version 2.8
# This script is developed with **sslscan version: 1.11.7-static
# root@BOEING:# which testssl.sh 
# /bin/testssl.sh
# root@BOEING:# ls -al /bin/testssl.sh 
# lrwxrwxrwx 1 root root 21 Jul  5 01:20 /bin/testssl.sh -> /kapi/tool/testssl.sh

import argparse
import sys
import re
import subprocess
import datetime
import pytz
import os
import urllib2
import urllib3
import ssl
import requests
global initStr
import httplib

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

# print bcolors.HEADER + "Testing color" + bcolors.ENDC
# print bcolors.OKBLUE + "Testing color" + bcolors.ENDC
# print bcolors.OKGREEN + "Testing color" + bcolors.ENDC
# print bcolors.WARNING + "Testing color" + bcolors.ENDC
# print bcolors.FAIL + "Testing color" + bcolors.ENDC
# print bcolors.BOLD + "Testing color" + bcolors.ENDC
# print bcolors.UNDERLINE + "Testing color" + bcolors.ENDC

initStr = "\
#########################################################################\n\
    Automatic checking for general WEB issues\n\
    check_general_WEB_finding.py 0.2\n\
    (version 0.2 19/09/2017 13:42 ITC)\n\
\n\
\n\
      This program is free software. https://github.com/zionspike/\n\
             modification under GPLv2 permitted.\n\
                 USE IT AT YOUR OWN RISK!\n\
                                                                   Kapi.Z\n\
#########################################################################"
# Setting up global variable
def init():
	print initStr

	global TO_COLLECT_PROOF
	TO_COLLECT_PROOF = False

	global TO_COLLECT_CSV
	TO_COLLECT_CSV = False
	
	global RESULT_DIC
	RESULT_DIC = {}

	global PROOF_DIR
	global CSV_DIR

	global REGEX_WEAK_CIPHER
	REGEX_WEAK_CIPHER = r'm([0-9]|[1-9][0-9]|((10[0-9])|(11[0-1])))[^0-9a-zA-Z].*bits[^\r\n$]'
	
	global REGEX_EXPORT_CIPHER
	REGEX_EXPORT_CIPHER = r'(mEXP|NULL-MD5)'

	global REGEX_eNULL_CIPHER
	REGEX_eNULL_CIPHER = r'(NULL)'

	global REGEX_aNULL_CIPHER
	REGEX_aNULL_CIPHER = r'(ADH|AECDH)'

	global REGEX_SWEET32_CIPHER
	REGEX_SWEET32_CIPHER = r"(DES|3DES)"

	global REGEX_GENERAL_CIPHER
	REGEX_GENERAL_CIPHER = r'[A-Z0-9]{2,}-[A-Z0-9-]*'

	global REGEX_DOMAIN_IN_TESTSSL_CERT_OUTPUT
	REGEX_DOMAIN_IN_TESTSSL_CERT_OUTPUT = "\(([\w]+\.+[\w\.]+)[^\d]\)"

	global REGEX_HTTPS_SCHEME
	REGEX_HTTPS_SCHEME = r'(https|HTTPS)://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
	
	global REGEX_SSLv2_NOT_ENABLE
	REGEX_SSLv2_NOT_ENABLE = r"SSLv2.*not\soffered"

	global REGEX_SSLv3_NOT_ENABLE
	REGEX_SSLv3_NOT_ENABLE = r"SSLv3.*not\soffered"

	global REGEX_TLS1_0_NOT_ENABLE
	REGEX_TLS1_0_NOT_ENABLE = r"TLS\s1\s+.*not\s+offered"

	global REGEX_TLS1_1_NOT_ENABLE
	REGEX_TLS1_1_NOT_ENABLE = r"TLS\s1\.1\s+.*not\s+offered"
	
	global REGEX_TLS1_2_NOT_ENABLE
	REGEX_TLS1_2_NOT_ENABLE = r"TLS\s1\.2\s+.*not\s+offered"

	global REGEX_ALLOWED_HTTP_METHODS
	REGEX_ALLOWED_HTTP_METHODS = r"\b(?:(?!POST|GET|HEAD|OPTIONS)\w)+\b"

# Get current time of zone UTC+7 (ICT)
def gettime():
	return str(datetime.datetime.now(tz=pytz.timezone('Asia/Bangkok')))

def validate_https_scheme(url):
	prog = re.compile(REGEX_HTTPS_SCHEME)
	if prog.match(url):
		return True
	else:
		return False

# Return True if the target is vulnerable, otherwise False
def validate_testssl_result(outputstr):
	result = re.compile('not vulnerable')
	if result.findall(outputstr):
		return False
	else:
		return True

def validate_testssl_breach_result(outputstr):
	result = re.compile('no HTTP compression \(OK\)')
	if result.findall(outputstr):
		return False
	else:
		return True

def validate_sslscan_sweet32_cipher(outputstr):
	is_vuln = False
	vuln_ciphers = []
	all_ciphers = list(set(re.findall(REGEX_GENERAL_CIPHER,outputstr)))
	for cipher in all_ciphers:
		if re.findall(REGEX_SWEET32_CIPHER,cipher):
			vuln_ciphers.append(cipher)
			is_vuln = True
	return is_vuln,vuln_ciphers

def validate_testssl_rc4_result(outputstr):
	result = re.compile('no RC4 ciphers detected')
	if result.findall(outputstr):
		return False
	else:
		return True

def validate_testssl_cert_result(outputstr):
	result = re.compile('Common Name \(CN\)')
	if result.findall(outputstr):
		return True
	else:
		return False

# Weak cipher denoted by:
# - Encryption key less than 128 bits (< 128) ("m([0-9]|[1-9][0-9]|((1[0-1][0-9])|(12[0-7])))[^0-9a-zA-Z].*bits[^\r\n$]")
# - Export class cipher suite
# - Null cipher
# - Cipher that support unauthenticated modes
def validate_sslscan_weak_cipher(url,outputstr):
	p = subprocess.Popen("sslscan --no-renegotiation --no-compression --no-heartbleed --no-fallback --no-check-certificate " + str(url) + " | grep -E '"+str(REGEX_WEAK_CIPHER)+"'", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	is_vuln = False
	vuln_ciphers = []
	all_ciphers = list(set(re.findall(REGEX_GENERAL_CIPHER,outputstr)))
	vuln_ciphers = list(set(re.findall(REGEX_GENERAL_CIPHER,output)))
	if re.findall(REGEX_WEAK_CIPHER,outputstr):
		is_vuln = True
	for cipher in all_ciphers:
		if re.findall(REGEX_EXPORT_CIPHER,cipher):
			vuln_ciphers.append(cipher)
			is_vuln = True
	for cipher in all_ciphers:
		if re.findall(REGEX_eNULL_CIPHER,cipher):
			vuln_ciphers.append(cipher)
			is_vuln = True
	for cipher in all_ciphers:
		if re.findall(REGEX_aNULL_CIPHER,cipher):
			vuln_ciphers.append(cipher)
			is_vuln = True
	vuln_ciphers = list(set(vuln_ciphers))
	return is_vuln,vuln_ciphers

def is_enable_sslv2(outputstr):
	result = re.findall(REGEX_SSLv2_NOT_ENABLE,outputstr)
	if result:
		return False
	else:
		return True

def is_enable_sslv3(outputstr):
	result = re.findall(REGEX_SSLv3_NOT_ENABLE,outputstr)
	if result:
		return False
	else:
		return True

def is_enable_tls1_0(outputstr):
	result = re.findall(REGEX_TLS1_0_NOT_ENABLE,outputstr)
	if result:
		return False
	else:
		return True

def is_enable_tls1_1(outputstr):
	result = re.findall(REGEX_TLS1_1_NOT_ENABLE,outputstr)
	if result:
		return False
	else:
		return True

def is_enable_tls1_2(outputstr):
	result = re.findall(REGEX_TLS1_2_NOT_ENABLE,outputstr)
	if result:
		return False
	else:
		return True

def check_SSL_protocol_version(url):
	if validate_https_scheme(url):
		print "[!] Checking supporting protocol"
		p = subprocess.Popen("testssl.sh -p " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		is_sslv2 = is_enable_sslv2(output)
		is_sslv3 = is_enable_sslv3(output)
		is_tls1_0 = is_enable_tls1_0(output)
		is_tls1_1 = is_enable_tls1_1(output)
		is_tls1_2 = is_enable_tls1_2(output)
		
		if is_sslv2:
			RESULT_DIC[url]["sslv2"] = True
			print bcolors.FAIL + "   [+] SSLv2 is enabled" + bcolors.ENDC
		else:
			RESULT_DIC[url]["sslv2"] = False
			print "   [-] SSLv2 is disabled"

		if is_sslv3:
			RESULT_DIC[url]["sslv3"] = True
			print bcolors.FAIL + "   [+] SSLv3 is enabled" + bcolors.ENDC
		else:
			RESULT_DIC[url]["sslv3"] = False
			print "   [-] SSLv3 is disabled"

		if is_tls1_0:
			RESULT_DIC[url]["tls1.0"] = True
			print "   [+] TLS1.0 is enabled"
		else:
			RESULT_DIC[url]["tls1.0"] = False
			print "   [-] TLS1.0 is disabled"

		if is_tls1_1:
			RESULT_DIC[url]["tls1.1"] = True
			print "   [+] TLS1.1 is enabled"
		else:
			RESULT_DIC[url]["tls1.1"] = False
			print "   [-] TLS1.1 is disabled"

		if is_tls1_2:
			RESULT_DIC[url]["tls1.2"] = True
			print "   [+] TLS1.2 is enabled"
		else:
			RESULT_DIC[url]["tls1.2"] = False
			print "   [-] TLS1.2 is disabled"

		if TO_COLLECT_PROOF == True:
			origin = url.replace("://", "_")
			origin = origin.replace("/","")
			origin = origin.replace(":","_")
			origin = origin + ".txt"
			filename = "general_protocol_" + origin
			f = open(PROOF_DIR + filename, 'w')
			f.write(output)
			f.close()
	else:
		RESULT_DIC[url]["sweet32"] = "skip"
		RESULT_DIC[url]["sslv2"] = "skip"
		RESULT_DIC[url]["sslv3"] = "skip"
		RESULT_DIC[url]["tls1.0"] = "skip"
		RESULT_DIC[url]["tls1.1"] = "skip"
		RESULT_DIC[url]["tls1.2"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to SWEET32
def check_sweet32(url):
	if validate_https_scheme(url):
		# print "[!] Checking SWEET32 (CVE-2016-2183)"
		p = subprocess.Popen("sslscan --no-renegotiation --no-compression --no-heartbleed --no-fallback --no-check-certificate " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] SWEET32\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] SWEET32\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		is_vuln,vuln_ciphers = validate_sslscan_sweet32_cipher(output)
		if not is_vuln:
			RESULT_DIC[url]["sweet32"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["sweet32"] = True
			print vuln_stmt
			output = output + "\n\n Vulnerable Ciphers:\n" + str(vuln_ciphers)+ "\n"
			print "   [+] Vulnerable ciphers: \t" + str(vuln_ciphers)
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_sweet32_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["sweet32"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to HeartBleed
def check_heartbleed(url):
	if validate_https_scheme(url):
		# print "[!] Checking HeartBleed (CVE-2014-0160)"
		p = subprocess.Popen("testssl.sh -B " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] HeartBleed\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] HeartBleed\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_result(output)
		if not vuln:
			RESULT_DIC[url]["heartbleed"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["heartbleed"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_heartbleed_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["heartbleed"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to CCS Injection
def check_ccs(url):
	if validate_https_scheme(url):
		# print "[!] Checking CCS Injection (CVE-2014-0224)"
		p = subprocess.Popen("testssl.sh -I " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] CCS Injection\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] CCS Injection\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_result(output)
		if not vuln:
			RESULT_DIC[url]["ccs"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["ccs"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_ccs_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["ccs"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

def check_renego(url):
	if validate_https_scheme(url):
		print "[!] Secure Client-Initiated Renegotiation##########3"
		p = subprocess.Popen("testssl.sh -R " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] CCS Injection\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] CCS Injection\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_result(output)
		if not vuln:
			RESULT_DIC[url]["renego"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["renego"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_renego_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["renego"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to CRIME
def check_crime(url):
	if validate_https_scheme(url):
		# print "[!] Checking CRIME (CVE-2012-4929)"
		p = subprocess.Popen("testssl.sh -C " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] CRIME\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] CRIME\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_result(output)
		if not vuln:
			RESULT_DIC[url]["crime"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["crime"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_crime_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["crime"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to BEAST
def check_beast(url):
	if validate_https_scheme(url):
		# print "[!] Checking BEAST (CVE-2011-3389)"
		p = subprocess.Popen("testssl.sh -A " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] BEAST\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] BEAST\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_result(output)
		if not vuln:
			RESULT_DIC[url]["beast"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["beast"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_beast_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()

	else:
		RESULT_DIC[url]["beast"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to BREACH
def check_breach(url):
	if validate_https_scheme(url):
		# print "[!] Checking BREACH (CVE-2013-3587)"
		p = subprocess.Popen("testssl.sh -T " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] BREACH\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] BREACH\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_breach_result(output)
		if not vuln:
			RESULT_DIC[url]["breach"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["breach"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_breach_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["breach"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to POODLE
def check_poodle(url):
	if validate_https_scheme(url):
		# print "[!] Checking POODLE, SSL (CVE-2014-3566)"
		p = subprocess.Popen("testssl.sh -O " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] POODLE\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] POODLE\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_result(output)
		if not vuln:
			RESULT_DIC[url]["poodle"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["poodle"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_poodle_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["poodle"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to FREAK
def check_freak(url):
	if validate_https_scheme(url):
		# print "[!] Checking FREAK (CVE-2015-0204)"
		p = subprocess.Popen("testssl.sh -F " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] FREAK\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] FREAK\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_result(output)
		if not vuln:
			RESULT_DIC[url]["freak"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["freak"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_freak_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["freak"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to LOGJAM
def check_logjam(url):
	if validate_https_scheme(url):
		# print "[!] Checking LOGJAM (CVE-2015-4000)"
		p = subprocess.Popen("testssl.sh -J " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] LOGJAM\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] LOGJAM\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_result(output)
		if not vuln:
			RESULT_DIC[url]["logjam"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["logjam"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_logjam_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["logjam"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that vulnerable to DROWN
def check_drown(url):
	if validate_https_scheme(url):
		# print "[!] Checking DROWN (2016-0800, CVE-2016-0703)"
		p = subprocess.Popen("testssl.sh -D " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] DROWN\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] DROWN\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_result(output)
		if not vuln:
			RESULT_DIC[url]["drown"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["drown"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_drown_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["drown"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

# Check cipher suite that use RC4 algorithm to encryption
def check_rc4(url):
	if validate_https_scheme(url):
		# print "[!] Checking RC4 (CVE-2013-2566, CVE-2015-2808)"
		p = subprocess.Popen("testssl.sh -4 " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] RC4\t\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] RC4\t\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		vuln = validate_testssl_rc4_result(output)
		if not vuln:
			RESULT_DIC[url]["rc4"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["rc4"] = True
			print vuln_stmt
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_rc4_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["rc4"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"


# Check cipher suite that use weak cipher suite
# Weak cipher denoted by:
# - Encryption key less than 128 bits (< 128)
# - Export class cipher suite
# - Null cipher
# - Cipher that support unauthenticated modes
def check_weak_cipher(url):
	if validate_https_scheme(url):
		# print "[!] Checking SSL weak cipher suite"
		p = subprocess.Popen("sslscan --no-renegotiation --no-compression --no-heartbleed --no-fallback --no-check-certificate " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = bcolors.FAIL + "[+] Weak cipher\t\tVulnerable" + " [" + gettime()  + "]" + bcolors.ENDC
		not_vuln_stmt = "[-] Weak cipher\t\tNOT Vulnerable" + " [" + gettime()  + "]"
		is_vuln,vuln_ciphers = validate_sslscan_weak_cipher(url,output)
		if not is_vuln:
			RESULT_DIC[url]["weakcipher"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["weakcipher"] = True
			print vuln_stmt
			output = output + "\n\n Vulnerable Ciphers:\n" + str(vuln_ciphers)+ "\n"
			print "   [+] Vulnerable ciphers: \t" + str(vuln_ciphers)
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_weak_cipher_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["weakcipher"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

def check_http_methods(url):
	is_finding = False
	output = ""
	print "[!] Checking allowed HTTP methods:"
	headers = {"User-Agent": "Linux / Firefox 44: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0", 
				"Accept-Encoding": "gzip, deflate",
				"Accept": "*/*",
				"Kapi":"Zionspike",
				"Connection": "keep-alive"
				}
	try:
		r = requests.options(url, headers=headers, verify=False, timeout=5, allow_redirects=False)
	except Exception as e:
		print "[!] Checking allowed HTTP methods has an error..."
		print e
	try:
		for key in r.headers:
			if str(key).lower() == "allow":
				print "   [!]" + str(key) + " => " + str(r.headers[key])
				result = re.findall(REGEX_ALLOWED_HTTP_METHODS, r.headers[key])
				if result:
					output = output + "[+] This URL allow  insecure HTTP method(s): " + str(url)+ "\n"
					print bcolors.FAIL + "      [+]The URL allow insecure HTTP method(s): " + bcolors.HEADER + ', '.join(str(x) for x in result)  + bcolors.ENDC
					RESULT_DIC[url]["insecure_http_method"] = True
					try:
						for key in r.headers:
							output = output + "   [+]" + str(key) + " => " + str(r.headers[key]) + "\n"
						if TO_COLLECT_PROOF == True:
							origin = url.replace("://", "_")
							origin = origin.replace("/","")
							origin = origin.replace(":","_")
							origin = origin + ".txt"
							filename = "general_insecureHTTPMethod_" + origin
							f = open(PROOF_DIR + filename, 'w')
							f.write(output)
							f.close()
					except Exception as e:
						pass
				else:
					RESULT_DIC[url]["insecure_http_method"] = False
	except Exception as e:
		pass

def check_xframe(url):
	is_finding = True
	output = ""
	# print "\n[+] Checking: " + str(url)
	headers = {"User-Agent": "Linux / Firefox 44: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0", 
				"Accept-Encoding": "gzip, deflate",
				"Accept": "*/*",
				"Kapi":"Zionspike",
				"Connection": "keep-alive"
				}
	try:
		r = requests.get(url, headers=headers, verify=False, timeout=5, allow_redirects=False)
	except Exception as e:
		print "[!] Checking HTTP header X-Frame-Options has an error..."
		print e
	
	vulnerable_headers = {}
	try:
		vulnerable_headers["X-Frame-Options"] =  str(r.headers['X-Frame-Options'])
		is_finding = False
	except Exception as e:
		pass
	if is_finding == True:
		RESULT_DIC[url]["clickjacking"] = True
		output = output + "[+] This URL does not set X-Frame-Options: " + str(url)
		print bcolors.FAIL + output + bcolors.ENDC
		output = output + "\n   [!] Printing all response headers:\n"
		print "   [!] Printing all response headers:"
		try:
			for key in r.headers:
				output = output + "      [+]" + str(key) + " => " + str(r.headers[key]) + "\n"
				print "      [!]" + str(key) + " => " + str(r.headers[key])
		except Exception as e:
			pass
		if TO_COLLECT_PROOF == True:
			origin = url.replace("://", "_")
			origin = origin.replace("/","")
			origin = origin.replace(":","_")
			origin = origin + ".txt"
			filename = "general_xframe_" + origin
			f = open(PROOF_DIR + filename, 'w')
			f.write(output)
			f.close()
	else:
		RESULT_DIC[url]["clickjacking"] = False
		print "[-] This URL do set X-Frame-Options"
		print "      [!] X-Frame-Options => " + str(r.headers["X-Frame-Options"])
	


def check_banner(url):
	is_finding = False
	output = ""
	vulnerable_headers = {}
	# print "\n[+] Checking: " + str(url)
	headers = {"User-Agent": "Linux / Firefox 44: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0", 
				"Accept-Encoding": "gzip, deflate",
				"Accept": "*/*",
				"Kapi":"Zionspike",
				"Connection": "keep-alive"
				}
	try:
		r = requests.get(url, headers=headers, verify=False, timeout=5, allow_redirects=False)
	except Exception as e:
		print "[!] Checking HTTP header X-Frame-Options has an error..."
		print e
	

	try:
		vulnerable_headers["server"] =  str(r.headers['server'])
		is_finding = True
	except Exception as e:
		pass

	try:
		vulnerable_headers["x-powered-by"] = str(r.headers['x-powered-by'])
		is_finding = True
	except Exception as e:
		pass

	if is_finding == True:
		RESULT_DIC[url]["info_in_banner"] = True
		output = output + "[+] This URL discloses information in HTTP banner: " + str(url)
		print bcolors.FAIL + output + bcolors.ENDC
		output = output + "\n   [!] Printing all response headers:\n"
		print "   [!] Printing all response headers:"
		try:
			for key in r.headers:
				if str(key).lower() == "x-powered-by" or str(key).lower() == "server":
					print bcolors.FAIL + "      [!]" + str(key) + " => " + str(r.headers[key]) + bcolors.ENDC
					output = output + bcolors.FAIL + "      [!]" + str(key) + " => " + str(r.headers[key]) + bcolors.ENDC + "\n"
				else:
					output = output + "      [+]" + str(key) + " => " + str(r.headers[key]) + "\n"
					print "      [!]" + str(key) + " => " + str(r.headers[key])
		except Exception as e:
			pass
		if TO_COLLECT_PROOF == True:
			origin = url.replace("://", "_")
			origin = origin.replace("/","")
			origin = origin.replace(":","_")
			origin = origin + ".txt"
			filename = "general_httpbanner_" + origin
			f = open(PROOF_DIR + filename, 'w')
			f.write(output)
			f.close()
	else:
		RESULT_DIC[url]["info_in_banner"] = False
		print "[-] This URL do not disclose information in HTTP banner"

def check_cookie_httponly(url):
	print "[!] Checking cookie_httponly"

def check_cookie_secure(url):
	print "[!] Checking cookie_secure"

def cert_info(url):
	if validate_https_scheme(url):
		# print "[!] Grabing SSL certificate"
		p = subprocess.Popen("testssl.sh -S " + str(url), stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		vuln_stmt = "[+] Grab SSL Cert.\tSucceed" + " [" + gettime()  + "]"
		not_vuln_stmt = "[-] Grab SSL Cert.\tFail" + " [" + gettime()  + "]"
		has_cert = validate_testssl_cert_result(output)
		if not has_cert:
			RESULT_DIC[url]["cert"] = False
			print not_vuln_stmt
		else:
			RESULT_DIC[url]["cert"] = True
			domain = url.split("//")[-1].split("/")[0].split(":")[0]
			print vuln_stmt
			is_self_sign = check_cert_self_sign(domain,output)
			if is_self_sign:
				print bcolors.FAIL + "   [+] SSL Self-Signed Certificate" + bcolors.ENDC
				RESULT_DIC[url]["cert_self_sign"] = True
			else:
				print "   [-] SSL Not Self-Signed Certificate"
				RESULT_DIC[url]["cert_self_sign"] = False
			
			is_wrong_host = check_cert_wrong_host(domain,output)
			if is_wrong_host:
				print bcolors.FAIL + "   [+] Certificate does not match supplied URI" + bcolors.ENDC
				RESULT_DIC[url]["cert_wrong_host"] = True
			else:
				print "   [-] Certificate matches supplied URI"
				RESULT_DIC[url]["cert_wrong_host"] = False
			
			is_expired = check_cert_expiry(domain,output)
			if is_expired:
				print bcolors.FAIL + "   [+] Certificate has expired" + bcolors.ENDC
				RESULT_DIC[url]["cert_expired"] = True
			else:
				print "   [-] Certificate is still valid"
				RESULT_DIC[url]["cert_expired"] = False
			
			is_weak_algo = check_cert_weak_sign_algo(domain,output)
			if is_weak_algo:
				print bcolors.FAIL + "   [+] Certificate weak hash algorithm" + bcolors.ENDC
				RESULT_DIC[url]["cert_weak_algo"] = True
			else:
				print "   [-] Certificate strong hash algorithm"
				RESULT_DIC[url]["cert_weak_algo"] = False
			
			if TO_COLLECT_PROOF == True:
				origin = url.replace("://", "_")
				origin = origin.replace("/","")
				origin = origin.replace(":","_")
				origin = origin + ".txt"
				filename = "general_cert_" + origin
				f = open(PROOF_DIR + filename, 'w')
				f.write(output)
				f.close()
	else:
		RESULT_DIC[url]["cert"] = "skip"
		RESULT_DIC[url]["cert_self_sign"] = "skip"
		RESULT_DIC[url]["cert_wrong_host"] = "skip"
		RESULT_DIC[url]["cert_expired"] = "skip"
		RESULT_DIC[url]["cert_weak_algo"] = "skip"
		print "URL: " + url + " is not a HTTPS scheme, skip this check!!!"

def check_cert_self_sign(domain,outputstr):
	result = re.findall('self-signed',outputstr)
	if not result:
		return False
	else:
		return True

def check_cert_wrong_host(domain,outputstr):
	result = re.findall('certificate does not match supplied URI',outputstr)
	if not result:
		return False
	else:
		return True

def check_cert_expiry(domain,outputstr):
	result = re.findall('expired',outputstr)
	if not result:
		return False
	else:
		return True

def check_cert_weak_sign_algo(domain,outputstr):
	result = re.findall('(MD5|SHA1)\swith',outputstr)
	if not result:
		return False
	else:
		return True

def get_csv_content(dictionary):
	header = "URL,"
	for domain in dictionary:
		for key in dictionary[domain]:
			header = header + key + ','
		break
	header = header[:len(header)-1]
	body = ""
	for domain in dictionary:
		aline = domain + ","
		for key in dictionary[domain]:
			aline = aline + str(dictionary[domain][key]) + ","
		aline = aline[:len(aline)-1]
		body = body + aline + "\n"
	csv_content = header + "\n" + body
	return csv_content

def check_connection_to_target(url):
	if len(url) < 5:
		return False
	print "[!] Checking connection to the target"
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	try:
		urllib2.urlopen(url, timeout=5, context=ctx)
		return True
	except urllib2.URLError as err: 
		if re.findall("https",url):
			try:
				p = subprocess.Popen("sslscan --no-renegotiation --no-compression --no-heartbleed --no-fallback --no-check-certificate " + str(url), stdout=subprocess.PIPE, shell=True)
				(output, err) = p.communicate()
				return True
			except Exception as e:
				return False
		return False

	# headers = {"User-Agent": "Linux / Firefox 44: Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0", 
	# 			"Accept-Encoding": "gzip, deflate",
	# 			"Accept": "*/*",
	# 			"Kapi":"Zionspike",
	# 			"Connection": "keep-alive"
	# 			}
	# try:
	# 	r = requests.get(url, headers=headers, verify=False, timeout=5, allow_redirects=False)
	# 	return True
	# except Exception as e:
	# 	print e
	# 	return False

	# try:
	# 	c = httplib.HTTPSConnection(url)
	# 	c.request("GET", "/")
	# 	response = c.getresponse()
	# 	# print response.status, response.reason
	# 	data = response.read()
	# 	# print data
	# 	return True
	# except Exception as e:
	# 	# raise e
	# 	return False



if __name__ == "__main__":
	init()
	parser = argparse.ArgumentParser(description='Checking for general findings')
	parser.add_argument("-f","--file_target", type=str, nargs='?', help='file that contain target with prefix HTTP/HTTPS',required=True)
	parser.add_argument("-oA","--output_dir", type=str, nargs='?', help='directory to store all proof files and CSV result')
	parser.add_argument("-oC","--output_csvdir", type=str, nargs='?', help='directory to store CSV result if you want to store only CSV result(this options will not generate any proof files)')
	parser.add_argument("-a","--check_all", help='check for all findings: SSL/TLS ciphers and certificate, X-Frame-Options, HTTP Banner, cookie with HTTPOnly and Secure flag', action="store_true")
	parser.add_argument("-s","--ssl_only", help='check for all findings of SSL/TLS: SWEET32, Heartbleed (CVE-2014-0160), CCS Injection (CVE-2014-0224), Renegotiation, CRIME (CVE-2012-4929), BEAST, BREACH, POODLE, Freak, Logjam, DROWN, RC4', action="store_true")
	parser.add_argument("-c","--cert_info", help='displays SSL certificate information and checking for common certificate weaknesses', action="store_true")
	
	# to implement
	parser.add_argument("-p","--protocol", help="check for SSL/TLS supportd protocols", action="store_true")

	parser.add_argument("-S","--sweet32", help="tests for SWEET32 vulnerability", action="store_true")
	parser.add_argument("-H","--heartbleed", help="tests for HeartBleed vulnerability", action="store_true")
	parser.add_argument("-I","--ccs", help="tests for CCS Injection vulnerability", action="store_true")
	# parser.add_argument("-R","--renego", help="tests for tests for renegotiation vulnerabilities", action="store_true")
	parser.add_argument("-C","--crime", help="tests for CRIME vulnerability", action="store_true")
	parser.add_argument("-B","--beast", help="tests for BEAST vulnerability", action="store_true")
	parser.add_argument("-T","--breach", help="tests for BREACH vulnerability", action="store_true")
	parser.add_argument("-O","--poodle", help="tests for POODLE vulnerability", action="store_true")
	parser.add_argument("-F","--freak", help="tests for FREAK vulnerability", action="store_true")
	parser.add_argument("-J","--logjam", help="tests for LogJam vulnerability", action="store_true")
	parser.add_argument("-D","--drown", help="tests for DROWN vulnerability", action="store_true")
	parser.add_argument("-4","--rc4", help="tests for RC4 vulnerability", action="store_true")
	parser.add_argument("-x","--xframe", help='tests for existing of HTTP header X-Frame-Options', action="store_true")
	parser.add_argument("-hb","--banner", help='tests for information disclosure in HTTP banner', action="store_true")
	parser.add_argument("-m","--http_method", help='tests allow http methods', action="store_true")
	# parser.add_argument("-ch","--cookie_httponly", help='tests for cookie HTTP only flag', action="store_true")
	# parser.add_argument("-cs","--cookie_secure", help='tests for cookie Secure flag', action="store_true")
	parser.add_argument("-wek","--weak_cipher", help='tests for SSL weak cipher suite', action="store_true")

	args = parser.parse_args()

	# Validate directory that to store output
	if args.output_dir:
		if os.path.isdir(str(args.output_dir)):
			TO_COLLECT_PROOF = True
			TO_COLLECT_CSV = True
			PROOF_DIR = (str(args.output_dir) + "/").replace("//", "/")
			CSV_DIR = PROOF_DIR
			print bcolors.OKBLUE + "[!] All proves and CSV result will be stored at '" + PROOF_DIR + "'" + bcolors.ENDC
		else:
			print bcolors.FAIL + "[!] Argument -oA should come with existing full directory path" + bcolors.ENDC
			exit(0)
	elif args.output_csvdir:
		if os.path.isdir(str(args.output_csvdir)):
			TO_COLLECT_CSV = True
			CSV_DIR = (str(args.output_csvdir) + "/").replace("//", "/")
			print bcolors.OKBLUE + "[!] Only CSV result will be stored at '" + CSV_DIR + "'" + bcolors.ENDC
		else:
			print bcolors.FAIL + "[!] Argument -oC should come with existing full directory path" + bcolors.ENDC
			exit(0)

	fname = args.file_target
	with open(fname) as f:
		for line in f:
			line = line.strip()
			print "\nURL: " + line
			if check_connection_to_target(line) == False:
				print bcolors.HEADER + "[!] Connection error, skipping this host" + bcolors.ENDC
			else:
				RESULT_DIC[str(line)] = {}
				if args.check_all:
					cert_info(line)
					check_SSL_protocol_version(line)
					check_sweet32(line)
					check_heartbleed(line)
					check_ccs(line)
					# check_renego(line)
					check_crime(line)
					check_beast(line)
					check_breach(line)
					check_poodle(line)
					check_freak(line)
					check_logjam(line)
					check_drown(line)
					check_rc4(line)
					check_weak_cipher(line)
					check_xframe(line)
					check_banner(line)
					check_http_methods(line)
					# check_cookie_httponly(line)
					# check_cookie_secure(line)
				elif args.ssl_only:
					cert_info(line)
					check_SSL_protocol_version(line)
					check_sweet32(line)
					check_heartbleed(line)
					check_ccs(line)
					# check_renego(line)
					check_crime(line)
					check_beast(line)
					check_breach(line)
					check_poodle(line)
					check_freak(line)
					check_logjam(line)
					check_drown(line)
					check_rc4(line)
					check_weak_cipher(line)
				else:
					if args.cert_info:
						cert_info(line)
					if args.protocol:
						check_SSL_protocol_version(line)
					if args.sweet32:
						check_sweet32(line)
					if args.heartbleed:
						check_heartbleed(line)
					if args.ccs:
						check_ccs(line)
					# if args.renego:
						# check_renego(line)
					if args.crime:
						check_crime(line)
					if args.beast:
						check_beast(line)
					if args.breach:
						check_breach(line)
					if args.poodle:
						check_poodle(line)
					if args.freak:
						check_freak(line)
					if args.logjam:
						check_logjam(line)
					if args.drown:
						check_drown(line)
					if args.rc4:
						check_rc4(line)
					if args.xframe:
						check_xframe(line)
					if args.banner:
						check_banner(line)
					# if args.cookie_httponly:
					# 	check_cookie_httponly(line)
					# if args.cookie_secure:
					# 	check_cookie_secure(line)
					if args.weak_cipher:
						check_weak_cipher(line)
					if args.http_method:
						check_http_methods(line)
				print "-----------------------------------------------------------------"
	time_now = (gettime()[0:19]).replace(" ","-").replace(":","")
	if TO_COLLECT_CSV == True:
		# print get_csv_content(RESULT_DIC)
		filename = "general_result_"+time_now+".csv"
		f = open(CSV_DIR + filename, 'w')
		content = get_csv_content(RESULT_DIC)
		f.write(content)
		f.close()
	print "[~] Finish, " + time_now