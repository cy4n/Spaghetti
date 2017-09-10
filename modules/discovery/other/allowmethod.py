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

class Allowmethod:
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
		'name'        : 'Allowmethod',
		'fullname'    : 'Allow Method',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking Allow Method'
		}

		db = open('data/allowmethod.txt','rb')
		db_files = ([x.split('\n') for x in db])
		
		try:
			for file in db_files:
				resp = self.request.send(self.url,method=file[0],cookies=self.cookie)
				if re.search(r'allow|public',str(resp.headers.keys()),re.I):
					allow = resp.headers['allow']
					if allow == None: allow = resp.headers['public']
					if allow != None and allow != '':
						self.output.plus('Allow HTTP Methods: %s'%allow)
						break
		except Exception,e:
			pass