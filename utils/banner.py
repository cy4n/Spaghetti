#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import os
import sys
from color import Color

class Banner:

	r = Color().red(1)  
	g = Color().green(1)
	y = Color().yellow(1)
	b = Color().blue(1)
	c = Color().cyan(1)
	p = Color().purple(1)
	w = Color().white(0)
	e = Color().end()

	def banner(self):
		print Banner.y+"  _____             _       _   _   _ "+Banner.e
		print Banner.y+" |   __|___ ___ ___| |_ ___| |_| |_|_|"+Banner.e
		print Banner.y+" |__   | . | .'| . |   | -_|  _|  _| |"+Banner.e
		print Banner.y+" |_____|  _|__,|_  |_|_|___|_| |_| |_|"+Banner.e
		print Banner.y+"       |_|     |___|          "+Banner.r+"v0.1.1\n"+Banner.e
		print Banner.w+"|| Spaghetti - Web Application Security Scanner"+Banner.e
		print Banner.w+"|| Codename - "+Banner.y+"\"MR.Robot\""+Banner.e
		print Banner.w+"|| Momo Outaadi (@M4ll0k)"+Banner.e
		print Banner.w+"|| https://github.com/m4ll0k/Spaghetti\n"+Banner.e

	def usage(self,exit=False):
		name = os.path.basename(sys.argv[0])
		self.banner()
		print "Usage:\n"
		print "\t-u --url\tTarget URL (eg: http://example.com)"
		print "\t-s --scan\tScan Options:\n"
		print "\t\t0:\tFull Scan"
		print "\t\t1:\tBroken Auth. (Admin Panel,Backup,...)"
		print "\t\t2:\tDisclosure (IP and Emails)"
		print "\t\t3:\tInjection (SQL,LDAP...)"
		print "\t\t4:\tOther (Allow Method,...)"
		print "\t\t5:\tKnown Vulns (Shellsock and Struts)\n"
		print "\t--agent\t\tUse the specified user-agent"
		print "\t--random-agent\tUse a random user-agent"
		print "\t--redirect\tRedirect Target URL, default=True"
		print "\t--timeout\tSet timeout (eg: 0.001)"
		print "\t--cookie\tSet cookie"
		print "\t--proxy\t\tSet proxy, (host:port)"
		print "\t--verbose\tVerbose output"
		print "\t--version\tShow version"
		print "\t--help\t\tShow this help and exit\n"
		print "Example:\n"
		print "\t"+name+" --url http://example.com --scan [0-5]\n"
		if exit:
			sys.exit(0)

	def version(self,exit=False):
		print "\nSpaghetti - Web Application Security Scanner (v0.1.1)\n"
		if exit:
			sys.exit(0)