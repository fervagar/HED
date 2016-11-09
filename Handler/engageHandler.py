#!/usr/bin/env python
# -*- coding: latin-1 -*-

'''
 * Copyright (C) 2016 Fernando Vañó García
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *	Fernando Vanyo Garcia <fernando@fervagar.com>
'''

from slave import *;
from os import geteuid;

#subnet = '10.0.0.0/0';     ## Adjust for the HoneyNet

## In the Handler we only have to assure than the IP addres ##
## is a valid IP addres of the Subnet ##
def checkIP(ip):
    try:
        n, b = subnet.split('/');
        ip = unpack('!L', socket.inet_aton(ip))[0];
        n = unpack('!L', socket.inet_aton(n))[0];
        b = int(b);
        return ((n >> (32-b)) == (ip >> (32-b)));
    except:
        return False;
    
def process_udp(addr):
    '''
    * addr[0] <- Source Address 
    * addr[1] <- Source Port
    '''
    rAddr = addr[0];
    rPort = addr[1];
    
    info("Received a UDP packet from %s:%d" % (rAddr,rPort));
    if checkIP(rAddr):
        Slave(rAddr, rPort).start();
    else:
        info("Seems like the IP address is not from the subnet");
        info("IP: %s; Subnet: %s" % (rAddr, subnet));

def checkData(data):
    ''' The data must be the Initial Signature: '''
    init_sig = ".??.#0#0#.??.";
    data = data.split('#');
    return len(data) == 4 and data[1] == data[2] == '0';

def start_udp_handler():
    lhost = ''; ## All interfaces 
    lport = 7692;

    try:
        usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
    except socket.error, msg:
        error('Creating UDP socket ' + str(msg[0]) + ' : ' + msg[1]);
        return -1;

    try:
        usock.bind((lhost, lport));
    except socket.error, msg:
        error('Binding the UDP socket ' + str(msg[0]) + ' : ' + msg[1]);
        return -2;

    info("Listening in port %d/udp" % lport);
    while True:
        try:
            data, addr = usock.recvfrom(16);
            if checkData(data):
                process_udp(addr);
            else:
                ## TODO Send a ICMP 'Port unreachable' type 3; code: 3
                None;
        except KeyboardInterrupt:
            info("KeyboardInterrupt detected... Closing.");
            return 0;

def main():
    ## Check root permissions
    if geteuid() != 0:
        print("Please, run again with root permissions");
        exit(-1);
    start_udp_handler();

if __name__ == '__main__':
      main();
