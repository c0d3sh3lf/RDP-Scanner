Usage: python rdp_checker.py -i INPUTFILE -c CSVFILE

If CSVFILE not provided, CSV filename will be same as that of INPUTFILE 

This script can be used to check if a system is enabled for RDP at application level. At times, companies usually block the RDP from the application layer and not the network layer. If you run nmap or any tool that works on the network layer, it will show that RDP is enabled. This tool will check the accessiblity of terminal services from application layer.

Dependencies:
 - nmap
 
 Options:
 - -h, --help            show this help message and exit
 - -i INPUTFILE, --input=INPUTFILE  List of IP addresses with one IP address per line
 - -c CSVFILE, --csv=CSVFILE  Output CSV filename
