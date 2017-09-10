#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

from utils import output
from extractor import ip

class IP:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
		self.output = output.Output()
		self.ip = ip.Ip(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout,
			url = url,
			cookie = cookie
			)

	def run(self):
		info = {
		'name'        : 'IP',
		'fullname'    : 'IP',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Find private IP'
		}

		ip = self.ip.run()
		
		try:
			if len(ip) == 1:
				self.output.plus('Found IP: %s'%ip[0])
			elif len(ip) > 1:
				self.output.plus('Found IP: %s'%str(ip).split('[')[1].split(']')[0])
		except Exception,e:
			pass