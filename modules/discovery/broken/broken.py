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

import logs
import admin
import files
import backdoor
import backupdir
import backupfile
import directories

from net import request
from net import utils
from utils import output

class Broken:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url
		self.cookie = cookie
		self.output = output.Output()
		self.agent = agent
		self.proxy = proxy
		self.redirect = redirect
		self.timeout = timeout
		self.url = url 
		self.cookie = cookie

	def run(self):
		if '--verbose' in sys.argv:
			self.output.test('Broken auth attacks...')
		try:
			logs.Logs(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			admin.Admin(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			files.Files(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			backdoor.Backdoor(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			backupdir.Backupdir(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			backupfile.Backupfile(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
			directories.Directories(
				agent=self.agent,proxy=self.proxy,
				redirect=self.redirect,timeout=self.timeout,
				url=self.url,cookie=self.cookie).run()
		except Exception,e:
			pass