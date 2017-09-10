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

class Robots:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
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
		'name'        : 'Robots',
		'fullname'    : 'Robots',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking Robots file'
		}

		if '--verbose' in sys.argv:
			self.output.info('Checking Robots Path...')	
		
		try:
			url = self.check.path(self.url,'robots.txt')
			resp = self.request.send(url,cookies=self.cookie)
			if resp.status_code == 200 and resp.content:
				paths = re.findall(r'\ (/\S*)',resp.content)
				for path in paths:
					if path.startswith('/'): path = path[1:]
					url2 = self.check.path(self.url,path) 
					resp2 = self.request.send(url,cookies=self.cookie)
					print " - [%s] %s"%(resp.status_code,url2)
		except Exception,e:
			pass