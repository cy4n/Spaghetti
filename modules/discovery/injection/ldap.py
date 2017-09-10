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

class Ldap:
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
		'name'        : 'LDAP',
		'fullname'    : 'LDAP',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking LDAP Injection'
		}

		db = open('data/ldap.txt','rb')
		db_files = ([x.split('\n') for x in db])

		if '--verbose' in sys.argv:
			self.output.info('Checking LDAP Injection...')	
		
		try:
			for file in db_files:
				for link in self.links:
					urls = self.param.Parameters(link,file[0]).process()
					if len(urls) > 1:
						for url in urls:
							resp = self.request.send(url,cookies=self.cookie)
							if resp.status_code == 200:
								error = self.error(resp.content)
								if error != None:
									self.output.plus('That site may be vulnerable to LDAP Injection under: %s'%(url))
									break
				
					elif len(urls) == 1:
						resp = self.request.send(urls[0],cookies=self.cookie)
						if resp.status_code == 200:
							error = self.error(resp.content)
							if error != None:
								self.output.plus('That site may be vulnerable to LDAP Injection under: %s'%(url))
								break
		except Exception,e:
			pass

	def error(self,data):
		ldap = False
		if re.search(r'supplied argument is not a valid ldap|javax.naming.NameNotFoundException|javax.naming.directory.InvalidSearchFilterException|Invalid DN syntax',data):
			ldap = True
		elif re.search(r'LDAPException|com.sun.jndi.ldap|Search: Bad search filter|Protocol error occurred|Size limit has exceeded|The alias is invalid|Module Products.LDAPMultiPlugins',data):
			ldap = True
		elif re.search(r'Object does not exist|The syntax is invalid|A constraint violation occurred|An inappropriate matching occurred|Unknown error occurred',data):
			ldap = True
		elif re.search(r'The search filter is incorrect|Local error occurred|The search filter is invalid|The search filter cannot be recognized|IPWorksASP.LDAP',data):
			ldap = True
		if ldap:
			return "LDAP Injection"
		else:
			return None