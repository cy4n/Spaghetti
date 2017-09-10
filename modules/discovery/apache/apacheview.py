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

class Apacheview:
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
		'name'        : 'Apacheview',
		'fullname'    : 'Apache MultiViews',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checks if MultiViews option is present in Apache'
		}

		try:
			url = self.check.path(self.url,'index')
			resp = self.request.send(url,headers={'Negotiate':'Spaghetti'},cookies=self.cookie)
			if resp.status_code == 406:
				index = re.findall(r'href=(\W*\w*\W*\.\w*)',resp.content)
				if index:
					self.output.plus('Apache MultiViews option is enabled. See also http://www.wisec.it/sectou.php?id=4698ebdc59d15')
		except Exception,e:
			pass