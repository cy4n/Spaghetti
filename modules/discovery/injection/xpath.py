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
from net import parameters
from net import request
from utils import output

class Xpath:
	def __init__(self,agent,proxy,redirect,timeout,links,cookie):
		self.links = links 
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
		'name'        : 'Xpath',
		'fullname'    : 'Xpath',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking XPath Injection'
		}

		db = open('data/xpath.txt','rb')
		db_files = ([x.split('\n') for x in db])

		if '--verbose' in sys.argv:
			self.output.info('Checking XPath Injection...')	
		
		try:
			for file in db_files:
				for link in self.links:
					
					urls = self.param.Parameters(link,file[0]).process()
					
					if len(urls) > 1:
						for url in urls:
							resp = self.request.send(url,cookies=self.cookie)
							if resp.status_code == 200:
								if re.search(r'XPATH syntax error:|XPathException',resp.content,re.I):
									self.output.plus('That site may be vulnerable to XPath Injection under: %s'%(url))
									break
				
					elif len(urls) == 1:
						resp = self.request.send(urls[0],cookies=self.cookie)
						if resp.status_code == 200:
							if re.search(r'XPATH syntax error:|XPathException',resp.content,re.I):
								self.output.plus('That site may be vulnerable to XPath Injection under: %s'%(url))
								break
		except Exception,e:
			pass