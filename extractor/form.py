#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

import re
import urllib

from net import utils
from utils import text
from net import request
from BeautifulSoup import BeautifulSoup

class Form:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
		self.cookie = cookie
		self.check = utils.Checker()
		self.request = request.Request(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout
			)

	def run(self):
		forms = []
		try:
			resp = self.request.send(url=self.url,cookies=self.cookie)
			soup = BeautifulSoup(resp.content)
			for match in soup.findAll('form'):
				if match not in forms:
					forms.append(match)
			return forms
		except Exception:
			pass

	def action(self,act):
		if act == []: pass
		else:
			if isinstance(act,list):
				act = act[0].split('"')[1]
			if act.startswith('//'):
				return act.split('//')[1]
			elif act == "/" or act == []:
				return self.url
			else:
				if act.startswith('www.'):
					return 'http://'+act
				else:
					return act

	def method(self,met):
		if isinstance(met,list):
			met = met[0].split('"')[1]
		return met.upper()

	def namevalue(self,name,value):
		if isinstance(name,list):
			name = name[0].split('"')[1]
		if isinstance(value,list):
			value = value[0].split('"')[1]
		return name+"="+value

	def get(self):
		forms = self.run()
		links = []
		setting = []
		params = []
		for form in forms:
			form = text.utf8(form)
			multi_form = form.split('<input')
			for x in multi_form:
				x = text.utf8(x)
				try:
					method = re.findall(r'method=(\S*)',x,re.I)
					method = self.method(method)
				except:
					method = 'GET'
				if method not in setting:
					setting.append(method)
				try:
					action = re.findall(r'action=(\S*)',x,re.I)
					action = self.action(action)
				except:
					action = self.action(action)
				if action not in setting:
					setting.append(action)
				if 'name' and 'value' in x:
					try:
						name = re.findall(r'name=(\S*)',x,re.I)
						value = re.findall(r'value=(\S*)',x,re.I)
					except:
						pass
					if name and value:
						params.append(self.namevalue(name,value))
			try:
				a = setting[1]
				params = params[len(params) == 1:][:-1]
				para = dict(x.split('=') for x in params)
				data = urllib.unquote(urllib.urlencode(para))
				if method == "GET":
					links.append(self.check.payload(a,data))
			except Exception:
				pass
		return links