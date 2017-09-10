#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

from utils import output
from extractor import email

class Email:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
		self.cookie = cookie
		self.output = output.Output()
		self.email = email.Email(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout,
			url = url,
			cookie = cookie
			)

	def run(self):
		info = {
		'name'        : 'Email',
		'fullname'    : 'Email',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Find emails'
		}

		email = self.email.run()
		
		try:
			if len(email) == 1:
				self.output.plus('Found email: %s'%email[0])
			elif len(email) > 1:
				self.output.plus('Found emails: %s'%str(email).split('[')[1].split(']')[0])
		except Exception,e:
			pass