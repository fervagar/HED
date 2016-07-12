#!/usr/bin/env python
# -*- coding: latin-1 -*-

## Fernando Vañó García
## Modified version of Pycket program, written by Alexis Le Dinh
## Original Pycket: https://github.com/alexis-ld

from __future__ import print_function;
from argparse import ArgumentParser;
from os import path, mkdir, remove;
from sys import stdout, stderr;
from datetime import datetime;
from socket import inet_aton;
from time import sleep;
import PcapWriter;
import capture;

logPath = './pcapFiles';    # Don't add the final slash '/'
MAX_TIMEOUT = 60;           # Max 10 seconds

def error(*error):
    now = datetime.now().strftime("%d/%m/%Y @ %H:%M:%S.%f");
    print("[%s] Sniffer ERROR:" % now, *error, file=stderr);

def info(*msg):
    now = datetime.now().strftime("%d/%m/%Y @ %H:%M:%S.%f");
    print("[%s] Sniffer INFO:" % now, *msg, file=stdout);

def checkPathDirectory():
    global logPath;

    if path.exists(logPath):
        if path.isdir(logPath):
            return;
        else:
            remove(logPath);
    mkdir(logPath);
    return;

def startsniff(ipAddr, port, timeout):
    global logPath;

    filename = logPath + '/' + (datetime.now().strftime("capture-%m-%d-%H:%M:%S.%f"));
    info('starting capture (%s:%d)' % (ipAddr, port));
    ## Create the object
    test = capture.Capture(ipAddr, port);
    ## Start the capture
    test.start();
    ## Wait the specified timeout
    try:
        sleep(timeout);
    except:
        None;
    finally:
        ## Stop the capture
        test.stopCapture();
        ## Wait for the threads
        test.join();

    ## Store the capture
    checkPathDirectory();
    dump = PcapWriter.PcapWriter(filename);
    dump.write(test.result);
    dump.close_file();

## Verify IP, Port and Timeout
## Warning: IP may be in BIG ENDIAN
def verifyArgs(i, p, t):
    if len(i.split('.')) != 4:
        return False;
    try:
        inet_aton(i);
    except:
        return False;
    
    return (p > 0 and p < 65536) \
            and (t > 0 and t < MAX_TIMEOUT);

def main():
    parser = ArgumentParser(description='This program is a sniffer that stores the packets of a given stream for a timeout. Finally, send a RST to the both sides of the communication in order to finish the connection.');
    parser.add_argument('-i', metavar='IP', type=str, help='Remote IP address', required=True);
    parser.add_argument('-p', metavar='Port', type=int, help='Remote Port number', required=True);
    parser.add_argument('-t', metavar='Timeout', type=int, help='Timeout (in seconds)', required=True);

    args = vars(parser.parse_args());
    
    ipAddr = args['i'];
    port = args['p'];
    timeout = args['t'];

    if verifyArgs(ipAddr, port, timeout):
        startsniff(ipAddr, port, timeout);
    else:
        error('Bad values! (IP: %s && Port: %d)' % (ipAddr, port));


if __name__ == '__main__':
    main();
