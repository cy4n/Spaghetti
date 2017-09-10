#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import re

from net import utils
from net import request
from utils import output

class Apachexss:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
		self.cookie = cookie
		self.check = utils.Checker()
		self.output = output.Output()
		self.request = request.Request(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout
			)

	def run(self):
		info = {
		'name'        : 'Apachexss',
		'fullname'    : 'Apache Xss',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Check if Apache is vunlnerabile to XSS'
		}

		try:
			resp = self.request.send(self.url,headers={'Expect':'<script>alert(xss)</script>'},cookies=self.cookie)
			if re.search(r'<script>alert\(xss\)<\/script>',resp.content,re.I):
				self.output.plus('Apache is vulnerable to XSS via the Expect header.')
		except Exception,e:
			pass