#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import sys
import time
import socket
import getopt

from net import utils
from utils import banner
from utils import output
from crawler import crawler

from modules.fingerprints import checkall
from modules.discovery.other import other
from modules.discovery.vulns import vulns
from modules.discovery.broken import broken
from modules.discovery.disclosure import disclosure
from modules.discovery.injection import injection

class Spaghetti(object):

	ban    = banner.Banner()
	output = output.Output()

	def main(self,kwargs):
		agent = "Mozilla/5.0 (Windows NT 6.2; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0"
		redirect = True
		timeout = None
		cookie = None
		proxy = None
		# args...
		if len(sys.argv) < 2:
			self.ban.usage(True)
		try:
			opts,args = getopt.getopt(kwargs,'u:s:',['url=','scan=','agent=','random-agent',
				'redirect=','timeout=','cookie=','proxy=','verbose','version','help'])
		except getopt.error,e:
			self.ban.usage(True)
		for o,a in opts:
			if o in ('-u','--url'):
				self.url = utils.Parser(a).host_path()
				if not self.url:
					self.output.less('Try with target url!')
					sys.exit(0)
			if o in ('-s','--scan'):
				self.scan = a
				if self.scan not in ('0','1','2','3','4','5'):
					self.output.less('Check scan option and try!')
					sys.exit(0)
			if o in ('--agent'):
				agent = a 
			if o in ('--random-agent'):
				pass
			if o in ('--redirect'):
				redirect = a 
			if o in ('--timeout'):
				timeout = a 
			if o in ('--cookie'):
				cookie = a 
			if o in ('--proxy'):
				proxy = a 
			if o in ('--verbose'):
				pass
			if o in ('--version'):
				self.ban.version(True)
			if o in ('--help'):
				self.ban.usage(True)
		
		self.fingerprints(
			agent,proxy,redirect,timeout,self.url,cookie
			)
		urls = self.crawler(
			agent,proxy,redirect,timeout,self.url,cookie)
		#
		if urls == None or urls == []: urls == []; urls.append(self.url)
		#
		if self.scan == "0":
			self.broken(
				agent,proxy,redirect,timeout,self.url,cookie
				)
			self.disclosure(
				agent,proxy,redirect,timeout,self.url,cookie
				)
			self.injection(
				agent,proxy,redirect,timeout,urls,cookie
				)
			self.other(
				agent,proxy,redirect,timeout,self.url,cookie
				)
			self.vulns(
				agent,proxy,redirect,timeout,self.url,cookie
				)
		elif self.scan == "1":
			self.broken(
				agent,proxy,redirect,timeout,self.url,cookie
				)
		elif self.scan == "2":
			self.disclosure(
				agent,proxy,redirect,timeout,self.url,cookie
				)
		elif self.scan == "3":
			self.injection(
				agent,proxy,redirect,timeout,urls,cookie
				)
		elif self.scan == "4":
			self.other(
				agent,proxy,redirect,timeout,self.url,cookie
				)
		elif self.scan == "5":
			self.vulns(
				agent,proxy,redirect,timeout,self.url,cookie
				)

	def fingerprints(self,a,p,r,t,u,c):
		self.ban.banner()
		self.starttime()
		checkall.Checkall(
			agent=a,proxy=p,redirect=r,timeout=t,url=u,cookie=c
			).run(
			)

	def broken(self,a,p,r,t,u,c):
		broken.Broken(
			agent=a,proxy=p,redirect=r,timeout=t,url=u,cookie=c
			).run(
			)

	def disclosure(self,a,p,r,t,u,c):
		disclosure.Disclosure(
			agent=a,proxy=p,redirect=r,timeout=t,url=u,cookie=c
			).run(
			)
	
	def injection(self,a,p,r,t,u,c):
		injection.Injection(
			agent=a,proxy=p,redirect=r,timeout=t,links=u,cookie=c
			).run(
			)
	
	def other(self,a,p,r,t,u,c):
		other.Other(
			agent=a,proxy=p,redirect=r,timeout=t,url=u,cookie=c
			).run(
			)

	def vulns(self,a,p,r,t,u,c):
		vulns.Vulns(
			agent=a,proxy=p,redirect=r,timeout=t,url=u,cookie=c
			).run(
			)

	def crawler(self,a,p,r,t,u,c):
		return crawler.Crawler(
			agent=a,proxy=p,redirect=r,timeout=t,url=u,cookie=c
			).process(
			)

	def starttime(self):
		self.output.plus('Target: %s'%self.url)
		self.output.plus('Starting: %s'%time.strftime('%d/%m/%Y %H:%M:%S'))
		print ""

if __name__ == "__main__":
	try:
		main = Spaghetti()
		main.main(sys.argv[1:])
	except KeyboardInterrupt:
		sys.exit(output.Output().less('Exiting...'))