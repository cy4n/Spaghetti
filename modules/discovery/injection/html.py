#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import re
import sys

from net import utils
from net import parameters
from net import request
from utils import output

class Html:
	def __init__(self,agent,proxy,redirect,timeout,links,cookie):
		self.links = links 
		self.cookie = cookie
		self.check = utils.Checker()
		self.output = output.Output()
		self.param = parameters
		self.request = request.Request(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout
			)

	def run(self):
		info = {
		'name'        : 'HTML',
		'fullname'    : 'HTML',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking HTML Injection'
		}

		if '--verbose' in sys.argv:
			self.output.info('Checking HTML Injection...')	
		
		try:
			payload = "=<h1><a href=\"http://www.google.com\">Click Spaghetti!</a></h1>"
			for link in self.links:
				urls = self.param.Parameters(link,payload).process()
				if len(urls) > 1:
					for url in urls:
						resp = self.request.send(url,cookies=self.cookie)
						if resp.status_code == 200:
							if re.search(payload,resp.content):
								self.output.plus('That site may be vulnerable to HTML Injection under: %s'%(url))
								break

				elif len(urls) == 1:
					resp = self.request.send(urls[0],cookies=self.cookie)
					if resp.status_code == 200:
						if re.search(payload,resp.content):
							self.output.plus('That site may be vulnerable to HTML Injection under: %s'%(url))
							break
		except Exception,e:
			pass