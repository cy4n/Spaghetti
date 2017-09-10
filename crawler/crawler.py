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
from net import request
from utils import output
from extractor import form

class Crawler:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
		self.cookie = cookie
		self.check = utils.Checker()
		self.output = output.Output()
		self.parser = utils.Parser(self.url)
		self.form = form.Form(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout,
			url = url,
			cookie = cookie
			)
		self.request = request.Request(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout
			)

	def links(self):
		links = []
		urls = []
		try:
			resp = self.request.send(url=self.url,cookies=self.cookie)
			href = re.findall(r'href=[\'"]?([^\'" >]+)',resp.content)
			src = re.findall(r'src=[\'"]?([^\'" >]+)',resp.content)
			for x in href:
				if self.parser.host() in x:
					if x.startswith('//'):
						links.append(self.check.url(x))
					elif x.startswith('/'):
						links.append(self.check.path(self.url,x))
					elif x.startswith('www.'):
							links.append("http://"+x)
					else:
						links.append(x)
			for y in src:
				if self.parser.host() in y:
					if y.startswith('//'):
						links.append(self.check.url(y))
					elif y.startswith('/'):
						links.append(self.check.path(self.url,y))
					elif y.startswith('wwww.'):
						links.append("http://"+y)
					else:
						links.append(y)
			for i in links:
				if i not in urls:
					urls.append(i)
			return urls
		except Exception,e:
			pass

	def robots(self):
		links = []
		try:
			url = self.check.path(self.url,'robots.txt')
			resp = self.request.send(url=url,cookies=self.cookie)
			if resp.status_code == 200:
				robots = re.findall(r'Allow: (\/.*)|Disallow: (\/.*)',resp.content)
				for x in robots:
					for y in x:
						if y != '':
							url_ = (self.check.path(self.url,y))
							links.append(url_)
			return links
		except Exception,e:
			pass

	def sitemap(self):
		links = []
		try:
			url = self.check.path(self.url,'sitemap.xml')
			resp = self.request.send(url=url,cookies=self.cookie)
			if resp.status_code == 200:
				sitemap = re.findall(r'<loc>(.+?)</loc>',resp.content)
				for x in sitemap:
					links.append(x)
			return links
		except Exception,e:
			pass

	def process(self):
		if '--verbose' in sys.argv:
			self.output.test('Starting crawler and searching for "%s"'%self.url)
		links  = []
		try:
			link = self.links()
			link += self.robots()
			link += self.sitemap()
			link += self.form.get()
			for x in link:
				if '=' in x:
					if x not in links:
						links.append(x)
		except Exception,e:
			pass
		return links