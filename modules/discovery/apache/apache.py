#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import apachestatus
import apacheuser
import apacheview
import apachexss

class Apache:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url
		self.cookie = cookie
		self.agent = agent
		self.proxy = proxy
		self.redirect = redirect
		self.timeout = timeout
		self.url = url 
		self.cookie = cookie

	def run(self):
		try:
			apachestatus.Apachestatus(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			apacheuser.Apacheuser(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			apacheview.Apacheview(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			apachexss.Apachexss(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
		except Exception,e:
			print e