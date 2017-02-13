from httplib2 import Http
from urllib import urlencode
import re
print "\t################################################################"
print "\t#                             Kapi                             #"
print "\t#                 Scan Links On a Web Page                     #"
print "\t################################################################"
site = raw_input("Enter Site name including http, https: ")
h = Http()
resp, content = h.request(site, "GET", headers={'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:32.0) Gecko/20100101 Firefox/32.0'})
#print content
links = re.findall(r"<a.*?\s*href=\"(.*?)\".*?>(.*?)</a>", content)
f = open('result.txt','w')
for link in links:
	print(link[0])
	f.write(link[0] + "\n") # python will convert \n to os.linesep
f.close() # you can omit in most cases as the destructor will call if
print "*** Result on result.txt"