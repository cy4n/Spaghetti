#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import re

from net import request
from utils import output

class Htmlobject:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
		self.cookie = cookie
		self.output = output.Output()
		self.request = request.Request(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout
			)

	def run(self):
		info = {
		'name'        : 'Htmlobject',
		'fullname'    : 'Htmlobject',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking Html Object'
		}

		try:
			resp = self.request.send(self.url,cookies=self.cookie)
			if re.search(r'<object.*?>.*?<\/object>',resp.content,re.I):
				self.output.plus('Found HTML Object. Logs the existence of HTML object tags available under: %s'%(url))
		except Exception,e:
			pass