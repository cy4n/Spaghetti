#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import sys

from net import utils
from net import parameters
from net import request
from utils import output

class Multipleindex:
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
		'name'        : 'Multipleindex',
		'fullname'    : 'Multipleindex',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking Multiple Index'
		}

		db = open('data/multipleindex.txt','rb')
		db_files = ([x.split('\n') for x in db])

		if '--verbose' in sys.argv:
			self.output.info('Checking Multiple Index...')	
		
		try:
			for file in db_files:
				url = self.check.path(self.url,file[0])
				resp = self.request.send(url,cookies=self.cookie)
				if resp.status_code == 200 and resp.content:
					self.output.plus('Index page available under: %s'%(url))
		except Exception,e:
			pass