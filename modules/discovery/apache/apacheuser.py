#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

from net import utils
from net import request
from utils import output

class Apacheuser:
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
		'name'        : 'Apacheuser',
		'fullname'    : 'Apache Enum Users',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Apache (mod_userdir) Enumeration Users'
		}

		try:
			url = self.check.path(self.url,'/~bin')
			resp = self.request.send(url,cookies=self.cookie)
			if (resp.status_code == 200 and resp.content)or(resp.status_code == 403 and resp.content):
				self.output.plus('Apache (mod_userdir) enumeration user is possible.')
		except Exception,e:
			pass