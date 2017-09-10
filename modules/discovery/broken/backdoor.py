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
from net import request
from utils import output

class Backdoor:
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
		'name'        : 'Backdoor',
		'fullname'    : 'Common Backdoor',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Check common backdoor'
		}

		db = open('data/backdoor.txt','rb')
		db_dirs = ([x.split('\n') for x in db])

		if '--verbose' in sys.argv:
			self.output.info('Checking common backdoors...')	
		
		try:
			for dirs in db_dirs:
				url = self.check.path(self.url,dirs[0])
				resp = self.request.send(url,cookies=self.cookie)
				if resp.status_code == 200 and resp.content:
					self.output.plus('Backdoor file available under: %s'%(url))
		except Exception,e:
			pass