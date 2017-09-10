#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import random
import urlparse

def RandomAgent():
	agents = (
		'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1',
		'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)',
		'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16',
		'Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US',
		'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.6.01001)',
		'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0',
		'Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1',
		'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:11.0) Gecko/20100101 Firefox/11.0',
		'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.0.3705)',
		'Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1',
		'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
		'Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.01',
		'Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1',
		'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
		'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0',
		'Mozilla/5.0 (Windows NT 6.3; WOW64; rv:34.0) Gecko/20100101 Firefox/34.0)'
		)
	return str(agents[random.randint(0,len(agents)-1)])

class Checker:
	def payload(self,url,payload):
		if url.endswith('/') and payload.startswith('/'):
			return url[:-1]+"?"+payload[1:]
		
		elif not url.endswith('/')and(payload.startswith('/')):
			return url+"?"+payload[1:]
		
		elif url.endswith('/')and not(payload.startswith('/')):
			return url[:-1]+"?"+payload 
		
		else:
			return url+"?"+payload

	def path(self,url,path):
		if url.endswith('/') and path.startswith('/'):
			if not path.endswith('/'):
				return str(url[:-1]+path)
			else:
				return str(url+path[:-1])
		
		elif not url.endswith('/') and not path.startswith('/'):
			if not path.endswith('/'):
				return str(url+"/"+path)
			else:
				return str(url+"/"+path[:-1])

		else:
			if not path.endswith('/'):
				return str(url+path)
			else:
				return str(url+path[:-1])

	def url(self,url):
		if url.startswith('//'):
			url = url.split('//')[1]
			return 'http://'+url

class Parser:
	def __init__(self,url):
		self.url = url 
		self.scheme = urlparse.urlsplit(url).scheme
		self.netloc = urlparse.urlsplit(url).netloc
		self.path = urlparse.urlsplit(url).path
		self.query = urlparse.urlsplit(url).query

	def host(self):
		if self.netloc == "":
			return self.path.split('/')[0]
		else:
			return self.netloc

	def host_path(self):
		if self.netloc == "":
			return "http://"+self.path
		else:
			return self.scheme+"://"+self.netloc+self.path

	def complete(self):
		if self.netloc == "":
			return "http://"+self.path+"?"+self.query
		else:
			return self.scheme+"://"+self.netloc+self.path+"?"+self.query