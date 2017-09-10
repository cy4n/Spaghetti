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

class Admin:
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
		'name'        : 'Admin',
		'fullname'    : 'Admin Panel',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Check common administration interfaces'
		}

		db = open('data/admin.txt','rb')
		db_files = ([x.split('\n') for x in db])
		
		if '--verbose' in sys.argv:
			self.output.info('Checking common admin panel...')
		
		try:
			for file in db_files:
				url = self.check.path(self.url,file[0])
				resp = self.request.send(url,cookies=self.cookie)
				if resp.content and resp.status_code == 200:
					self.output.plus('Admin Interface available under: %s'%url)
		except Exception,e:
			pass