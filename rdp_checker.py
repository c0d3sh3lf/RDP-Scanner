#!/usr/bin/python

__author__ = "Sumit Shrivastava"
__version__ = "1.0.0"
__description__ = """
Author: Sumit Shrivasava
Version 1.0.0

RDP Scanner

This script can be used to check if a system is enabled for RDP at application level. At times,
companies usually block the RDP from the application layer and not the network layer. If you run
nmap or any tool that works on the network layer, it will show that RDP is enabled. This tool will
check the accessiblity of terminal services from application layer.

Dependencies:
 - nmap
"""

import xml.dom.minidom
import optparse, sys, subprocess, re, os

open_re = re.compile(r"Security\slayer")
closed_re = re.compile(r"^Received\sunhandled\spacket")
status_dict = {}


def check_rdp(ip_addr):
    try:
        nmap_command = "nmap -sV -Pn -n -p3389 --script=rdp-enum-encryption -A -vv -oX output.xml " + str(ip_addr).strip()
        nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, shell=True)
        nmap_process.communicate()
        parse_output()
    except:
        print "[-] Error occured while running script"


def parse_output():
    ip_addr, rdp_status = parseXMLFile(readXMLFile("output.xml"))
    if not(rdp_status == "fail"):
        print "[+]", str(ip_addr), "-", str(rdp_status)
    os.remove("output.xml")


def readXMLFile(inputfilename):
    DOMTree = xml.dom.minidom.parse(inputfilename)
    return DOMTree


def parseXMLFile(DOMTree):
    try:
        portscan = DOMTree.documentElement
        ports = portscan.getElementsByTagName('ports')[0].getElementsByTagName('port')
        ip_addr = portscan.getElementsByTagName('host')[0].getElementsByTagName('address')[0].getAttribute('addr')
        for port in ports:
            if (port.getAttribute("portid") == "3389"):
                script_output = port.getElementsByTagName('script')[0].getAttribute('output')
        if open_re.search(script_output):
            rdp_status = "Accessible"
        elif closed_re.match(script_output):
            rdp_status = "Inaccessible"
        else:
            rdp_status = "Undetermined"
    except:
        print "[-] Error parsing the output.xml file."
        ip_addr = ""
        rdp_status = "fail"
    status_dict[ip_addr] = rdp_status
    return (ip_addr, rdp_status)


def writeCSV(outputfilename):
    csvfile = open(outputfilename, "w")
    outputdata = "IP Address,RDP Status\n"
    for ip_addr in status_dict.keys():
        outputdata += ip_addr + "," + status_dict[ip_addr] + "\n"
    csvfile.write(outputdata)
    csvfile.flush()
    csvfile.close()
    print "[+]", outputfilename, "written successfully."


def main():
    parser = optparse.OptionParser("python rdp_checker.py -i INPUTFILE -c CSVFILE\n\r\n\rIf CSVFILE not provided, CSV filename will be same as that of INPUTFILE \n" + __description__)
    parser.add_option("-i", "--input", dest="inputfile", help="List of IP addresses with one IP address per line")
    parser.add_option("-c", "--csv", dest="csvfile", help="Output CSV filename")
    options, args = parser.parse_args()
    if not (options.inputfile):
        print "[-] Input file is required"
        parser.print_help()
        sys.exit(1)
    else:
        if not (options.csvfile):
            options.csvfile = options.inputfile.split(".")[0] + ".csv"
        else:
            if not (options.csvfile.split(".")[len(options.csvfile.split(".")) - 1] == "csv"):
                options.csvfile = options.csvfile + ".csv"
        ip_addresses = open(options.inputfile, "r").readlines()
        counter = 0
        for ip_address in ip_addresses:
            ip_address = ip_address.strip()
            total = len(ip_addresses)
            percentage = float(counter*100)/float(total)
            print "[+] Processing %d of %d [%s] IP addresses. Percentage complete: %.2f %s" % (counter+1, total, ip_address, percentage, "%")
            check_rdp(ip_address)
            counter += 1
        writeCSV(options.csvfile)


if __name__ == "__main__":
    main()
