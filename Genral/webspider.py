#!/usr/bin python
import sys
import re
import urllib2
import urlparse
import platform
import os
import time


funct_list = ['DEBUG', 'ADDRESS','SHOWVARS', 'START', 'HELP', 'TIMEOUT', 'EXIT']
var_dict = {}
helpScreen = '''
                        
-------------------------------------------------------------------------------
This module is a simple but effective Python web spider. I borrowed the main
algorithm from http://blog.theanti9.com and added a few modifications which
include logging for internal and external links found and most importantly
changed the algorithm to log (BUT NOT FOLLOW!) links to any external websites.
What you get as an end result is a simple program that can find all links on
a given domain, log each one in a .txt file for you, and follow each link to
other pages as long as they are on the same domain...

This web crawler grabs links off of webpages, logs them, and follows them if
they are on the same domain. The end result from the scan is two log files
which when finished will contain every link found on a particular site. Handy
for mapping a website, finding hard to find pages, and general snooping around.

Once you specify your options by executing the "ADDRESS" command, you must
execute either "START" to connect to the website and begin the enumeration
process. If any errors occur, you should be notified. The program is not
perfect, but hey I'm not Microsoft!!!

!!!THE MORE SPECIFIC THE URL YOU GIVE IS, THE MORE ACCURATE IT WILL BE IN
DETERMINING WHAT LINKS ARE INTERNAL V.S. EXTERNAL. FOR THE BEST ACCURACY, ENTER
URLS AS ROOT DOMAIN AND THE .com/.org/.net EXTENSION FOLLOWING!!!

NOTE: each time the program runs, it will create a folder named "logfiles" to
write logs to!!!

(Press Ctrl+C or use EXIT to exit console)

________________________________________________________________________________
MODULE COMMANDS:
     Usage ->   Enter the ADDRESSS command to choose a host, and the START
                command to begin crawling

     "ADDRESS": specify the URL of the site to crawl. NOTE: if you don't prefix
     the address with \"http://\", the program will do so automatically, so for
     better accuracy, enter the complete URL yourself!
         -if a subdomain is chosen as the address, then only links within
          the same subdomain will be flagged as "internal".

     "START": start the crawling process

     "SHOWVARS": shows all of the parameters you have set including variables
         for addresses, port numbers, timeouts, etc.

 
'''
welcome = """
WEB CRAWLER/DOMAIN SPIDER by A.J. Atkinson
                  _.._
                .'    '.
               /   __   \\
            ,  |   ><   |  ,
           . \\  \\      /  / .
            \\_'--`(  )'--'_/
              .--'/()\'--.
             /  /` '' `\  \\
               |        |
                \\      /
                                                                                                  
"""

def getOSVersion():
    try:
        system = platform.system()
        if system == 'Windows':
            os.system('cls')
        else:
            try:
                os.system('clear')
            except:
                pass
        return system
    except:
        pass



class CRAWLER(object):
        debug = 0
        rootpath = os.getcwd()
        logpath = rootpath + "/logfiles"
        logDir = 'logfiles'
        OSflag = 0
        flag = 0
        crawled = set([])
        internalLinks = set([])
        externalLinks = set([])
        keywordregex = re.compile('<meta\sname=["\']keywords["\']\scontent=["\'](.*?)["\']\s/>')
        linkregex = re.compile('<a\s*href=[\'|"](.*?)[\'"].*?>')
        def main(self):
                try:
                        if self.OSflag == 0:
                                OS = getOSVersion()
                        else:
                                pass
                except:
                        pass
                try:
                    if not os.path.exists('logfiles'):
                        os.makedirs('logfiles')
                    os.chdir('logfiles')
                except OSError:
                    print "ERROR: check permissions, couldn't create directory %s" % self.logDir
                    
                print welcome
                print "\t***Type HELP for command listing***\n"
                print "Working from %s\n" % os.getcwd()
                while self.flag == 0:
                        try:
                                prompt = raw_input("$Crawler> ")
                                prompt = prompt.upper()
                                prompt = prompt.strip(" ")
                                if prompt in funct_list:
                                        exec('self' + '.' + prompt + '()')
                                else:
                                        print "\t\nInvalid Command...Refer to \"HELP\" if needed"
                        except KeyboardInterrupt:
                                answer = raw_input("\nYou pressed Ctrl+C, do you wish to exit?(y/n) ")
                                if answer == "y" or answer == "Y":
                                        self.BACK()
                                elif answer == "N" or answer == "n":
                                            print "Good, we have unfinished business to attend to!"
                                else:
                                        pass
                                
        def logWrite(self):
                print "Current directory is: ", os.getcwd()
                try:
                        #Checking for root host directory
                        print "\n\tStopping crawling process..."
                        print "\tChecking for hostname directory..." 
                        os.makedirs(self.domain)
                        print "\tDirectory doesn't exist, creating it in %s" % self.domain
                except:
                        #If exists already, use it
                        print "\tOk, using existing directory %s..." % self.domain
                #At this point, log dir is created or already exists. Either way, CHDIR to it now
                os.chdir(self.domain)
                try:
                        #Checking for internal/external text logfile
                        print "\tChecking for internal/external logfiles..."
                        os.makedirs('internal_links')
                        os.makedirs('external_links')
                        print "\tCreating logs \"internal_links\" and \"external_links\"..."
                except:
                        #If they exist already, simply CHDIR to them later in the code (do nothing here)
                        print "\tOk, internal and external directories already exist, moving along..."
                #Filename is the time and date. 
                filename = time.strftime("%a, %d %b %Y %H%M%S", time.localtime())
                filename = filename + ".txt"
                #Place internal log in internal directory, external in external directory
                os.chdir('internal_links')
                internal = open(filename, 'a+')
                print "\n\tStopping crawling process and writing to logs..."
                internal.write("CRAWLED SITE: (%s) -----> %s\n" % (self.URLstring, time.ctime()))
                internal.write("-----Begin internal link results-----\n")
                IList = list(self.internalLinks)
                IList.sort()
                for i in IList:
                        internal.write(i+ "\n")
                internal.write("-----End of internal addresses-----\n")
                internal.close()
                os.chdir(self.logpath + "/" + self.domain)
                os.chdir('external_links')
                external = open(filename, 'a+')
                external.write("-----Begin external link results-----\n")
                external.write("CRAWLED SITE: (%s) -----> %s\n" % (self.URLstring, time.ctime()))
                EList = list(self.externalLinks)
                EList.sort()
                for i in EList:
                        external.write(i + "\n")
                external.write("-----End of external addresses-----\n")
                external.close()
                self.clearLogs()
                
        def clearLogs(self):
                self.internalLinks = set([])
                self.externalLinks = set([])
                return
            
        def START(self):
                try:
                        #Make initial URL the first address to crawl
                        tocrawl = set([var_dict['Address']])
                        scanTime = time.ctime()
                        scanTime = scanTime[:19]
                        self.scanTime = scanTime
                        print "\tStarting scan at %s\n" % str(scanTime)
                        time.sleep(2)
                        if var_dict.has_key('Address') == False:
                                print "FALSE!!!"
                                return
                        while 1 :
                                try:
                                        self.URLstring = var_dict['Address']
                                        self.crawling = tocrawl.pop()
                                        print "\n\nCrawling: %s" % self.crawling
                                        self.url = urlparse.urlparse(self.crawling)
                                        try:
                                                response = urllib2.urlopen(self.crawling)
                                        except:
                                                continue
                                        msg = response.read()
                                        links = self.linkregex.findall(msg)
                                        self.crawled.add(self.crawling)
                                        for link in (links.pop(0) for _ in xrange(len(links))):
                                                if link.startswith('/'):
                                                        link = 'http://' + self.url[1] + link
                                                elif link.startswith('#'):
                                                        link = 'http://' + self.url[1] + self.url[2] + link
                                                elif not link.startswith('http'):
                                                        link = 'http://' + self.url[1] + '/' + link
                                                if link not in self.crawled:
                                                        if self.URLstring in link:
                                                                print "\tInternal Link: %s" % link
                                                                tocrawl.add(link)
                                                                self.internalLinks.add(link)
                                                        else:
                                                            print "\tExternal Link: %s" % link 
                                                            self.externalLinks.add(link)
                                        
                                except KeyboardInterrupt:
                                        print "\n\t***YOU PRESSED CTRL+C***\n"
                                        self.logWrite()
                                        break

                                    
                                except KeyError:
                                        self.logWrite()
                                        break

                except KeyError:
                        print "You must first specify a URL to crawl!"
                        #URLstring = raw_input("Enter domain name to scan (i.e. \"example.com\")\n$Domain> ")
                        #domain = URLstring
                        #self.domain = domain
                        #if "http://" not in URLstring:
                        #        URLstring = "http://" + URLstring
                        #var_dict['Address'] = URLstring
                        #print "\tURL chosen = ", URLstring
                        self.ADDRESS()
                        self.START()
                os.chdir(self.logpath)

        def HELP(self):
                print helpScreen
                return

        def DEBUG(self):
            if self.debug == 1:
                del self.debug
                print "\t\nDebug mode off\n"
            else:
                self.debug = 1
                print "\t\nDebug mode on\n"
    

                
        def ADDRESS(self):
                URLstring = raw_input("\n\tEnter domain name to scan (i.e. \"example.com\")\n\t$Domain> ")
                if "http://" in URLstring:
                    URLstring = URLstring.strip("http://")
                domain = URLstring
                self.domain = domain
                if "http://" not in URLstring:
                        URLstring = "http://" + URLstring
                var_dict['Address'] = URLstring
                print "\tURL chosen = ", URLstring

        
        def EXIT(self):
                answer = raw_input("\t\nAre you sure you want to close the framework? (Yes/No)> ")
                answer = answer.strip()


                answer = answer.upper()
                if answer == "YES":
                        sys.exit(0)
                elif answer == "NO":
                        print "\tGood, we have unfinished business to attend to!"
                else:
                        print "\tPlease enter yes or no, no funny business!"

        def SHOWVARS(self):
            dataArray = []
            for i in var_dict:
                dataArray.append(i + " : " + str(var_dict[i]))
            dataArray.sort()
            print "\n\t\t-----------User Specified Variables------------"
            for i in dataArray:
                print "\t\t" + i 


            if self.debug == 1:
                print "\n\t\t----------Class Methods and Attributes---------"
                for i in dir(self):
                    print "\t\t" + i


        
instance = CRAWLER()
instance.main()