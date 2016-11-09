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

from __future__ import print_function;
from thread import start_new_thread;
from threading import Thread, Lock;
from struct import pack, unpack;
from sys import stdout, stderr;
from datetime import datetime;
from random import randint;
from time import sleep;
from sniffer.sniffer import verifyArgs, startsniff;
import socket;

TIMEOUT_TCP = 2;            ## Seconds to wait in the TCP socket
TIMEOUT_SNIFFER = 10;        ## Seconds to wait capturing the traffic

def error(*err):
    now = datetime.now().strftime("%d/%m/%Y @ %H:%M:%S.%f");
    print("[%s] Handler ERROR:" % now, *err, file=stderr);
    stderr.flush();

def info(*msg):
    now = datetime.now().strftime("%d/%m/%Y @ %H:%M:%S.%f");
    print("[%s] Handler INFO:" % now, *msg, file=stdout);
    stdout.flush();

def check_flow(rAddr, rPort):
    Slave.mutex.acquire();
    
    if rAddr in Slave.active_engages.keys():
        if rPort in Slave.active_engages[rAddr]:
            ## The flow is being sniffed
            Slave.mutex.release();
            return False;
        else:
            ## Add the port to the existing list
            Slave.active_engages[rAddr].append(rPort);
    else:
        ## Add a new list for this IP addr
        Slave.active_engages[rAddr] = [];
        Slave.active_engages[rAddr].append(rPort);

    Slave.mutex.release();
    return True;

def clear_flow(rAddr, rPort):
    Slave.mutex.acquire();
    
    try:
        Slave.active_engages[rAddr].remove(rPort);
        ret = True;
    except:
        ret = False;
    finally:
        Slave.mutex.release();
        return ret;

def get_free_tcp_port(ip):
    tmpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    r = randint(1025,65535);
    result = tmpsock.connect_ex((ip, r));
    while not result:
        r = randint(1025,65535);
        result = tmpsock.connect_ex((ip, r));
    return r;

## Warning: t_port is a list in order to return the generated value
def sendUDPpong(rAddr, rPort, tport):
    ## Send a UDP packet with a (available) random TCP port in the payload
    tcp_port = get_free_tcp_port('0.0.0.0');
    tport.append(tcp_port);         ## For the caller function

    try:
        usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
        payload = ".??.#%d#.??." % tcp_port;    ## TCP port encapsulated within the signature protocol
        usock.sendto(payload, (rAddr, rPort));
    except:
        return False;
    return True;

def open_tcp_socket(port):
    tcpsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    tcpsock.bind(('', port));
    tcpsock.listen(1);  ## Only 1 connection request

    #info("DEBUG TCP PORT: %d" % port);

    return tcpsock;

def close_tcp_socket_w_timeout(tcpsock, tmutex):
    acquired = False;
    try:
        sleep(TIMEOUT_TCP);
        tmutex.acquire();
        acquired = True;
        tcpsock.shutdown(socket.SHUT_RDWR);
        tcpsock.close();
    except socket.error, msg:
        None;
    finally:
        ## Release the mutex if acquired
        if acquired:
            tmutex.release();

def start_tcp(tcpsock, udpAddr, engage_info):
    tmutex = Lock();
    acquired = False;
    start_new_thread(close_tcp_socket_w_timeout, (tcpsock, tmutex, ));
    try:
        clientsocket, address = tcpsock.accept();
        ## Check if the Addres is from who iniciated the exchange
        if address[0] == udpAddr:
            data = clientsocket.recv(32);
            engage_info.append(data);
        tmutex.acquire();
        acquired = True;
        clientsocket.close();
        tcpsock.shutdown(socket.SHUT_RDWR);
        tcpsock.close();
    except socket.error, msg:
        ## The timeout is defeated
        None;
    finally:
        ## Release the mutex if acquired
        if acquired:
            tmutex.release();

def checkIP(data):
    try:
        ip = int(data);
    except:
        return '';

    try:
        ip = socket.inet_ntoa(pack("!L", ip)).split('.');
    except:
        return '';

    ip.reverse();
    return '.'.join(map(str, ip));

def checkPort(data):
    try:
        p = socket.ntohs(int(data));
    except:
        return 0;
    return p;

###| Check if the received data satisfy our format |###
def validate_data(data, ret_list):
    '''
    The received data must satisfy the following format:
    .??.#ip#port#.??.
    where...
     ip <- A valid IP address (a 32-bit packed IPv4 address)
     port <- A valid port number (a 16-bit positive integer from network)
     .??. <- "Signature" symbols
    '''
    data = data.split('#');

    if len(data) != 4:
        return False;
    if data[0] == data[3] and data[0] == '.??.':
        ip = checkIP(data[1]);
        if len(ip) == 0:
            return False;

        port = checkPort(data[2]);
        if port <= 0 or port >= 65535:
            return False;

        ret_list.append(port);
        ret_list.append(ip);
        return True;
    else:
        return False;


def start_sniffer(ip, port):
    ''' IP and Port of the arguments pertain to the remote "attacker" '''
    #info("DEBUG Attacker info: %s:%d" % (ip, port));
    #info("DEBUG Initiating sniffer...");

    if verifyArgs(ip, port, TIMEOUT_SNIFFER):
        startsniff(ip, port, TIMEOUT_SNIFFER);


class Slave(Thread):
    """ Helper class responible for the port knocking and the posterior sniff """

    ## Global Static variables shared by all the instances ##
    active_engages = {};    ## Dictionary for active engages.
    mutex = Lock();         ## Lock for access the dictionary

    def __init__(self, rAddr, rPort):
        Thread.__init__(self);
        ##super(Slave, self).__init__();
        self.rAddr = rAddr;
        self.rPort = rPort;

    def run(self):
        ## Check if this flow is being sniffed
        if check_flow(self.rAddr, self.rPort):
            info("Capture thread for %s:%d started" % (self.rAddr, self.rPort));
            self.tcp_port = [];
            if sendUDPpong(self.rAddr, self.rPort, self.tcp_port):
                self.tcp_port = self.tcp_port.pop();    ## Return the generated random port
                self.engage_info = [];
                start_tcp(open_tcp_socket(self.tcp_port), self.rAddr, self.engage_info);
                ## Check if we obtained something from the tcp socket
                if len(self.engage_info) > 0:
                    if validate_data(self.engage_info.pop(), self.engage_info):
                        self.attAddr = self.engage_info.pop();
                        self.attPort = self.engage_info.pop();
                        start_sniffer(self.attAddr, self.attPort);
            if not clear_flow(self.rAddr, self.rPort):
                error("Something bad has happened at the end of the flow %s:%d" % (rAddr, rPort));
            info("Capture thread for %s:%d finished" % (self.rAddr, self.rPort));

