#!/usr/bin/env python

# Universal Decoder v1.0
# Author: Kapi.Z
# Version 1.0

# Ref: http://temp.crypo.com
# Ref: http://hackers.co.id

import urllib
import base64
import sys
import binascii
import sys
import struct
import string

b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
zong22 = "ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2"
atom128 = "/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC"
megan35 = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5"
hazz15 = "HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5"
tripo5 = "ghijopE+G78lmnIJQRXY=abcS/UVWdefABCs456tDqruvNOPwx2KLyz01M3Hk9ZFT"
tigo3fx = "FrsxyzA8VtuvwDEqWZ/1+4klm67=cBCa5Ybdef0g2hij9nopMNO3GHIRSTJKLPQUX"
gila7 = "7ZSTJK+W=cVtBCasyf0gzA8uvwDEq3XH/1RMNOILPQU4klm65YbdeFrx2hij9nopG"
feron74 = "75XYTabcS/UVWdefADqr6RuvN8PBCsQtwx2KLyz+OM3Hk9ghi01ZFlmnjopE=GIJ4"
esab46 = "ABCDqrs456tuvNOPwxyz012KLM3789=+QRSTUVWXYZabcdefghijklmnopEFGHIJ/"

def base64_encoder(plaintext):
	result = base64.b64encode(plaintext)
	return result

def base64_decoder(cipher):
	result = base64.b64decode(cipher)
	result = urllib.unquote(result).decode('utf8')
	return result

# CAESAR
def ROT_n_AZ(cipher,n):
	list_of_int_char = []
	for x in cipher:
		int_char = int(binascii.hexlify(x),16)
		list_of_int_char.append(int_char)
	result = ""
	for inte in list_of_int_char:
		if (inte >= 65 and inte <= 90):
			inte = inte + n
			if inte > 90:
				inte = (inte - 90) + 64
			result = result + struct.pack("B", inte)
		elif (inte >= 97 and inte <= 122):
			inte = inte + n
			if inte > 122:
				inte = (inte - 122) + 96
			result = result + struct.pack("B", inte)
		else:
			result = result + struct.pack("B", inte)
	filtered_string = filter(lambda x: x in string.printable, result)
	return filtered_string

def ROT_n_byte(cipher,n):
	list_of_int_char = []
	for x in cipher:
		int_char = int(binascii.hexlify(x),16)
		list_of_int_char.append(int_char)
	result = ""
	for inte in list_of_int_char:
		inte = inte + n
		if inte > 255:
			inte = inte - 256
		result = result + struct.pack("B", inte)

	filtered_string = filter(lambda x: x in string.printable, result)
	return filtered_string

def zong22_encoder(plaintext):
	srch = dict(zip(b, zong22))
	b64 = base64.b64encode(plaintext)
	result = "".join([srch[x] for x in b64])
	return result

def zong22_decoder(cipher):
	revlsrch = dict(zip(zong22, b))
	b64 = "".join([revlsrch[x] for x in cipher])
	result = base64.b64decode(b64)
	result = urllib.unquote(result).decode('utf8') 
	return result

def atom128_encoder(plaintext):
	srch = dict(zip(b, atom128))
	b64 = base64.b64encode(plaintext)
	result = "".join([srch[x] for x in b64])
	return result

def atom128_decoder(cipher):
	revlsrch = dict(zip(atom128, b))
	b64 = "".join([revlsrch[x] for x in cipher])
	result = base64.b64decode(b64)
	result = urllib.unquote(result).decode('utf8') 
	return result

def megan35_encoder(plaintext):
	srch = dict(zip(b, megan35))
	b64 = base64.b64encode(plaintext)
	result = "".join([srch[x] for x in b64])
	return result

def megan35_decoder(cipher):
	revlsrch = dict(zip(megan35, b))
	b64 = "".join([revlsrch[x] for x in cipher])
	result = base64.b64decode(b64)
	result = urllib.unquote(result).decode('utf8') 
	return result

def hazz15_encoder(plaintext):
	srch = dict(zip(b, hazz15))
	b64 = base64.b64encode(plaintext)
	result = "".join([srch[x] for x in b64])
	return result

def hazz15_decoder(cipher):
	revlsrch = dict(zip(hazz15, b))
	b64 = "".join([revlsrch[x] for x in cipher])
	result = base64.b64decode(b64)
	result = urllib.unquote(result).decode('utf8') 
	return result

def tripo5_encoder(plaintext):
	srch = dict(zip(b, tripo5))
	b64 = base64.b64encode(plaintext)
	result = "".join([srch[x] for x in b64])
	return result

def tripo5_decoder(cipher):
	revlsrch = dict(zip(tripo5, b))
	b64 = "".join([revlsrch[x] for x in cipher])
	result = base64.b64decode(b64)
	result = urllib.unquote(result).decode('utf8')
	return result

def tigo3fx_encoder(plaintext):
	srch = dict(zip(b, tigo3fx))
	b64 = base64.b64encode(plaintext)
	result = "".join([srch[x] for x in b64])
	return result

def tigo3fx_decoder(cipher):
	revlsrch = dict(zip(tigo3fx, b))
	b64 = "".join([revlsrch[x] for x in cipher])
	result = base64.b64decode(b64)
	result = urllib.unquote(result).decode('utf8')
	return result

def gila7_encoder(plaintext):
	srch = dict(zip(b, gila7))
	b64 = base64.b64encode(plaintext)
	result = "".join([srch[x] for x in b64])
	return result

def gila7_decoder(cipher):
	revlsrch = dict(zip(gila7, b))
	b64 = "".join([revlsrch[x] for x in cipher])
	result = base64.b64decode(b64)
	result = urllib.unquote(result).decode('utf8')
	return result

def feron74_encoder(plaintext):
	srch = dict(zip(b, feron74))
	b64 = base64.b64encode(plaintext)
	result = "".join([srch[x] for x in b64])
	return result

def feron74_decoder(cipher):
	revlsrch = dict(zip(feron74, b))
	b64 = "".join([revlsrch[x] for x in cipher])
	result = base64.b64decode(b64)
	result = urllib.unquote(result).decode('utf8')
	return result

def esab46_encoder(plaintext):
	srch = dict(zip(b, esab46))
	b64 = base64.b64encode(plaintext)
	result = "".join([srch[x] for x in b64])
	return result

def esab46_decoder(cipher):
	revlsrch = dict(zip(esab46, b))
	b64 = "".join([revlsrch[x] for x in cipher])
	result = base64.b64decode(b64)
	result = urllib.unquote(result).decode('utf8')
	return result

def try_decode_all(cipher):
	print "\n[!] Cipher: " + cipher
	try:
		print "[+] base64_decoder : " + base64_decoder(cipher)
	except Exception as e:
		print "[-] Error on base64_decoder()"
	try:
		print "[+] zong22_decoder : " + zong22_decoder(cipher)
	except Exception as e:
		print "[-] Error on zong22_decoder()"
	try:
		print "[+] atom128_decoder : " + atom128_decoder(cipher)
	except Exception as e:
		print "[-] Error on atom128_decoder()"
	try:
		print "[+] megan35_decoder : " + megan35_decoder(cipher)
	except Exception as e:
		print "[-] Error on megan35_decoder()"
	try:
		print "[+] hazz15_decoder : " + hazz15_decoder(cipher)
	except Exception as e:
		print "[-] Error on hazz15_decoder()"
	try:
		print "[+] tripo5_decoder : " + tripo5_decoder(cipher)
	except Exception as e:
		print "[-] Error on tripo5_decoder()"
	try:
		print "[+] tigo3fx_decoder : " + tigo3fx_decoder(cipher)
	except Exception as e:
		print "[-] Error on tigo3fx_decoder()"
	try:
		print "[+] gila7_decoder : " + gila7_decoder(cipher)
	except Exception as e:
		print "[-] Error on gila7_decoder()"
	try:
		print "[+] feron74_decoder : " + feron74_decoder(cipher)
	except Exception as e:
		print "[-] Error on feron74_decoder()"
	try:
		print "[+] esab46_decoder : " + esab46_decoder(cipher)
	except Exception as e:
		print "[-] Error on esab46_decoder()"


if __name__ == '__main__':
	plaintext = "flag{h0w_pl41n_73x7_b3_3nc0d3d}"
	base64_cipher = "ZmxhZyU3Qmgwd19wbDQxbl83M3g3X2IzXzNuYzBkM2QlN0Q="
	zong22_cipher = "LO7gLexz5OHQPWRQU957UN3zXzHz=c0F=F1GIFKvXc5N1r52"
	atom128_cipher = "LxrXLsgmbxWq0kcq+8br+6wmSmWmjlPtjtTVKt15Slb6TJbC"
	megan35_cipher = "j2rXjsexb2WqnvDqlIbrl1CxRxWxhwNthtSVitG/Rwb1Sub5"
	hazz15_cipher = "wrY7wbz=yrQG3SPGE4yYEFp=+=Q=uoidudJMvdNe+oyFJxy5"
	tripo5_cipher = "/6xB/2=0Q6Awdy9wVjQxV5k0m0A0czGKcKnOSKh4mzQ5nLQT"
	tigo3fx_cipher = "60NY6O+RW05MBHPM=xWN=fLRwR5RlIV3l3Dom3rewIWfDGWX"
	gila7_cipher = "wIY1wbzxyI/53Fn5ETyYEO9xBx/xur=dudCmvdZNBryOCeyG"
	feron74_cipher = "8z0x816nAzwislGiBYA0By=nWnwnvmSZvZdgNZ5LWmAydFA4"
	esab46_cipher = "MWhRMi0nwWQg9lHg7Dwh7VGnvnQnKm5jKjNeLjBUvmwVNkw/"

	plaintext = "uftu"
	for x in xrange(0,26):
		print "[+] ROT a-zA-Z (" + str(x) + "): " + str(ROT_n_AZ(plaintext,x))

	# print "[+] base64_encoder : " + base64_encoder(plaintext)
	# print "[+] base64_decoder : " + base64_decoder(base64_cipher)

	# print "[+] zong22_encoder : " + zong22_encoder(plaintext)
	# print "[+] zong22_decoder : " + zong22_decoder(zong22_cipher)

	# print "[+] atom128_encoder : " + atom128_encoder(plaintext)
	# print "[+] atom128_decoder : " + atom128_decoder(atom128_cipher)

	# print "[+] megan35_encoder : " + megan35_encoder(plaintext)
	# print "[+] megan35_decoder : " + megan35_decoder(megan35_cipher)

	# print "[+] hazz15_encoder : " + hazz15_encoder(plaintext)
	# print "[+] hazz15_decoder : " + hazz15_decoder(hazz15_cipher)

	# print "[+] tripo5_encoder : " + tripo5_encoder(plaintext)
	# print "[+] tripo5_decoder : " + tripo5_decoder(tripo5_cipher)

	# print "[+] tigo3fx_encoder : " + tigo3fx_encoder(plaintext)
	# print "[+] tigo3fx_decoder : " + tigo3fx_decoder(tigo3fx_cipher)

	# print "[+] gila7_encoder : " + gila7_encoder(plaintext)
	# print "[+] gila7_decoder : " + gila7_decoder(gila7_cipher)

	# print "[+] feron74_encoder : " + feron74_encoder(plaintext)
	# print "[+] feron74_decoder : " + feron74_decoder(feron74_cipher)

	# print "[+] esab46_encoder : " + esab46_encoder(plaintext)
	# print "[+] esab46_decoder : " + esab46_decoder(esab46_cipher)

	test_cipher = base64_cipher
	try_decode_all(test_cipher)
	test_cipher = zong22_cipher
	try_decode_all(test_cipher)
	test_cipher = atom128_cipher
	try_decode_all(test_cipher)
	test_cipher = megan35_cipher
	try_decode_all(test_cipher)
	test_cipher = hazz15_cipher
	try_decode_all(test_cipher)
	test_cipher = tripo5_cipher
	try_decode_all(test_cipher)
	test_cipher = tigo3fx_cipher
	try_decode_all(test_cipher)
	test_cipher = gila7_cipher
	try_decode_all(test_cipher)
	test_cipher = feron74_cipher
	try_decode_all(test_cipher)
	test_cipher = esab46_cipher
	try_decode_all(test_cipher)