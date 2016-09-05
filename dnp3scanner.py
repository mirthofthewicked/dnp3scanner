#!/usr/bin/env python

import argparse
import socket
import sys
from IPy import IP
from crccheck.crc import Crc16Dnp


#Initial concept by Chris Sistrunk. I'm just trying to make his dreams come true.

def scanner(target, port):
  
    # Attempt connection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Add functionality to allow user to change timeout at some point
        s.settimeout(float(500) / float(1000))
        s.connect((str(target), port))
    except:
        print "Failed to connect"
        s.close()
        
    try: 
        # This next section needs to be optimized..obviously... to go from x00x00x00x00 to xFFxFFxFFxFF
        # First set
        for i in xrange(256):
           #From Chris: Then it creates the 10 byte message starting at address 0
           msg = "056405c9" + hex(i)[2:].zfill(2) + "000000"
           crc = getCRC(msg)
           fullmsg = (msg + crc).upper()
           ping(s, fullmsg)

        # Second set
        for i in xrange(256):
           msg = "056405c9ff" + hex(i)[2:].zfill(2) + "0000"
           crc = getCRC(msg)
           fullmsg = (msg + crc).upper()
           ping(s, fullmsg)

        # Third set
        for i in xrange(256):
           msg = "056405c9ffff" + hex(i)[2:].zfill(2) + "00"
           crc = getCRC(msg)
           fullmsg = (msg + crc).upper()
           ping(s, fullmsg)

        # Fourth set
        for i in xrange(256):
           msg = "056405c9ffffff" + hex(i)[2:].zfill(2)
           crc = getCRC(msg)
           fullmsg = (msg + crc).upper()
           ping(s, fullmsg)

    # This doesn't seem to be working..
    except KeyboardInterrupt:
        print "User Aborted. Closing.."
        s.close()
        sys.exit(1)

    s.close()

def ping(conn, msg):
   #fullhexmsg = r"\x" + r"\x".join(msg[n : n+2] for n in range(0, len(msg), 2))
   resp = ''
   # Sends the message
   try:
       conn.send(msg)
   except:
       print "Failed to send: " + msg

   #Waits for response
   try:
       resp = conn.recv(1024)
   except:
       print "Failed to receive" 

   #Parses response
   if resp:
       print "Response received.."
       print resp
       # Will add this later..
       #> Stores DNP3 response info in a db
       #writedb(resp)

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

