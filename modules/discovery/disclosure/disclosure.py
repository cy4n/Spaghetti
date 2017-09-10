#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import sys
import ip
import email

from utils import output

class Disclosure:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url
		self.cookie = cookie
		self.output = output.Output()
		self.agent = agent
		self.proxy = proxy
		self.redirect = redirect
		self.timeout = timeout
		self.url = url 
		self.cookie = cookie

	def run(self):
		if '--verbose' in sys.argv:
			self.output.test('Disclosure attacks...')
		
		try:
			email.Email(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			ip.IP(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
		except Exception,e:
			pass