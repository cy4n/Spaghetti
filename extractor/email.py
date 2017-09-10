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

class Email:
	
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
			self.output.info('Starting search emails...')
		
		list_email = []
		try:
			resp = self.request.send(url=self.url,cookies=self.cookie)
			emails = self.parser.Parse(resp._content).getmail()
			if len(emails) == 1:
				list_email.append(emails[0])
			elif len(emails) > 1:
				for x in emails:
					if x not in list_email:
						list_email.append(x)
			return list_email
		except Exception,e:
			pass