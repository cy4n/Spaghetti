#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import sys

import rfi
import php
import sql
import xss
import ldap
import html
import xpath

from utils import output

class Injection:
	def __init__(self,agent,proxy,redirect,timeout,links,cookie):
		self.links = links
		self.cookie = cookie
		self.output = output.Output()
		self.agent = agent
		self.proxy = proxy
		self.redirect = redirect
		self.timeout = timeout

	def run(self):
		if '--verbose' in sys.argv:
			self.output.test('Injection Attacks...')
		try:
			rfi.Rfi(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				links=self.links,cookie=self.cookie).run()
			xss.Xss(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				links=self.links,cookie=self.cookie).run()
			php.PHP(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				links=self.links,cookie=self.cookie).run()
			sql.Sql(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				links=self.links,cookie=self.cookie).run()
			ldap.Ldap(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				links=self.links,cookie=self.cookie).run()
			html.Html(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				links=self.links,cookie=self.cookie).run()
			xpath.Xpath(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				links=self.links,cookie=self.cookie).run()
		except Exception,e:
			pass