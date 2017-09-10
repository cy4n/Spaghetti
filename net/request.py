#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import utils

class Request:
	# random user-agent
	ragent = utils.RandomAgent()
	# check url
	check  = utils.Checker()

	def __init__(self,**kwargs):
		# user-agent 
		self.agent = None if "agent" not in kwargs else kwargs["agent"]
		# default proxy is None
		self.proxy = None if "proxy" not in kwargs else	kwargs["proxy"]
		# default redirect is True
		self.redirect = True if "redirect" not in kwargs else kwargs["redirect"]
		# default timeout is None
		self.timeout = None if "redirect" not in kwargs else kwargs["timeout"]

	def send(self,url,method="GET",payload=None,headers=None,cookies=None):
		# 
		if payload is None: payload = {}
		if headers is None: headers = {}
		if cookies is not None: cookies = {cookies:''}
		# random user-agent
		if "--random-agent" in sys.argv:
			headers['User-Agent'] = Request.ragent
		else:
			headers['User-Agent'] = self.agent
		# requests session
		request = requests.Session()
		req = requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
		# get method 
		if method.upper() == "GET":
			if payload: url = "%s"%Request.check.payload(url,payload)
			req = request.request(
				method = method.upper(),
				url = url,
				headers = headers,
				cookies = cookies,
				timeout = self.timeout,
				allow_redirects = self.redirect,
				proxies = {'http':self.proxy,'https':self.proxy},
				verify = False
				)
		# post method
		elif method.upper() == "POST":
			req = request.request(
				method = method.upper(),
				url = url,
				data = payload,
				headers = headers,
				cookies = cookies,
				timeout = self.timeout,
				allow_redirects = self.redirect,
				proxies = {'http':self.proxy,'https':self.proxy},
				verify = False
				)
		else:
			req = request.request(
				method = method.upper(),
				url = url,
				data = payload,
				headers = headers,
				cookies = cookies,
				timeout = self.timeout,
				allow_redirects = self.redirect,
				proxies = {'http':self.proxy,'https':self.proxy},
				verify = False
				)
		# return all attrs
		return req