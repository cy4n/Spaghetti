#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import re
import sys

from net import utils
from net import request
from utils import output

class Directories:
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
		'name'        : 'Directories',
		'fullname'    : 'Common Directories',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Check Common Directories'
		}

		db = open('data/common_dirs2.txt','rb')
		db_dirs = ([x.split('\n') for x in db])
		
		if '--verbose' in sys.argv:
			self.output.info('Checking common directory...')	
		
		try:
			for dirs in db_dirs:
				url = self.check.path(self.url,dirs[0])
				resp = self.request.send(url,cookies=self.cookie)
				if url+"/" == resp.url:
					if resp.status_code == 200 and resp.content:
						self.output.plus('Directory available under: %s'%(url))
						if re.search('Index of',resp.content):
							self.output.less('Indexing enabled under: %s'%(url))
		except Exception,e:
			pass