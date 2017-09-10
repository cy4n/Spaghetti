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

class Apachestatus:
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
		'name'        : 'Apachestatus',
		'fullname'    : 'Apache Server Status',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Apache (mod_status) information disclosure'
		}

		db = open('data/status.txt','rb')
		db_files = ([x.split('\n') for x in db])
		try:
			for file in db_files:
				url = self.check.path(self.url,file[0])
				resp = self.request.send(url,cookies=self.cookie)
				if re.search(r'Apache Server Status for|Status for',resp.content):
					self.output.plus('Apache (mod_status) information disclosure under: %s'%resp.url)
					break
		except Exception,e:
			pass