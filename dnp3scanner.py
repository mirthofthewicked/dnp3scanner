#!/usr/bin/env python

import argparse
import socket
import sys
from IPy import IP
from crccheck.crc import Crc16Dnp


#Initial concept by Chris Sistrunk. I'm just trying to make his dreams come true.

def scanner(target, port):
    resp = ''

    # Attempt connection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Add functionality to allow user to change timeout at some point
        s.settimeout(float(500) / float(1000))
        s.connect((str(target), port))
    except:
        print "Failed to connect"
        s.close()
        
    # Concept with first 100, will expand to 65535 after I get this working
    for i in xrange(101):
       #From Chris: Then it creates the 10 byte message starting at address 0
       msg = "056405c9" + hex(i)[2:].zfill(2) + "000000"
       crc = getCRC(msg)
       fullmsg = msg + crc

       # Sends the message
       try:
           s.send(fullmsg)
       except:
           print "Failed to send"

       #Waits for response
       try:
           resp = s.recv(1024)
       except:
           print "Failed to receive"

       #Parses response
       if resp:
           print "Response received.."
           print resp
           # Will add this later..
           #> Stores DNP3 response info in a db
           #writedb(resp)

    s.close()


def writedb(data):
    # This will end up using sqlite ?? he wanted a database
    print "In ur databases, storin' ur dudes"


def getCRC(string):
    data = bytearray.fromhex(string)
    crc = hex(Crc16Dnp.calc(data))
    val2 = crc[2:4].zfill(2)
    val1 = crc[4:6].zfill(2) 
    return (val1 + val2)


    
def main():
    parser_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
            description = 'Scans an IP address on all TCP ports using DNP3',
            formatter_class=parser_formatter)

    parser.add_argument('--target', required=True, action='store', 
            dest='target', help='Supply one target IP address')

    parser.add_argument('--port', required=False, action='store', 
            dest='port', default=20000, help='Supply a TCP port')

    # Todo: Will add scanning a network range or list of IPs

    args = parser.parse_args()

    # Check if input supplied is a valid IP address
    try:
        IP(args.target)
    except:
        print "Not a valid IP, please supply a valid IP address."
        sys.exit(1)

    # Check if input supplied is a valid TCP port
    if not (int(args.port) > 0 and int(args.port) <= 65535):
        print "Please supply a valid port"
        sys.exit(1)

    # Add some keyboard exception to stop the scanner..
    scanner(args.target, args.port)

if __name__ == '__main__':
    main()

