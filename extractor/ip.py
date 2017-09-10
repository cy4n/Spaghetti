#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import sys

from net import request
from parser import parse
from utils import output

class Ip:
	
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
		self.cookie = cookie
		self.parser = parse
		self.output = output.Output()
		self.request = request.Request(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout
			)

	def run(self):
		if '--verbose' in sys.argv:
			self.output.info('Searching private IP...')
		
		list_ip = []
		try:
			resp = self.request.send(url=self.url,cookies=self.cookie)
			ip = self.parser.Parse(resp._content).getip()
			if len(ip) == 1:
				list_ip.append(ip[0])
			elif len(ip) > 1:
				for x in ip:
					if x not in list_ip:
						list_ip.append(x)
			return list_ip
		except Exception,e:
			pass