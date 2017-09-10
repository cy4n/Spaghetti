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

class Sql:
	def __init__(self,agent,proxy,redirect,timeout,links,cookie):
		self.links = links 
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
		'name'        : 'Sql',
		'fullname'    : 'Sql',
		'author'      : 'Momo Outaadi (M4ll0k)',
		'description' : 'Checking SQL Injection'
		}

		db = open('data/sql.txt','rb')
		db_files = ([x.split('\n') for x in db])

		if '--verbose' in sys.argv:
			self.output.info('Checking SQL Injection...')	
		
		try:
			for file in db_files:
				for link in self.links:
					urls = self.param.Parameters(link,file[0]).process()
					
					if len(urls) > 1:
						for url in urls:
							resp = self.request.send(url,cookies=self.cookie)
							error = self.dberror(resp.content)
							if error != None:
								self.output.plus('That site may be vulnerable to %s under: %s'%(error,url))
								break
				
					elif len(urls) == 1:
						resp = self.request.send(urls[0],cookies=self.cookie)
						error = self.dberror(resp.content)
						if error != None:
							self.output.plus('That site may be vulnerable to %s under: %s'%(error,url))
							break
		except Exception,e:
			pass

	def dberror(self,data):
		# mysql errors
		if re.search(r'supplied argument is not a valid MySQL|Column count doesn\'t match value count at row|mysql_fetch_array()|on MySQL result index|You have an error in your SQL syntax;|You have an error in your SQL syntax near|MySQL server version for the right syntax to use|\[MySQL]\[ODBC|Column count doesn\'t match|valid MySQL result|MySqlClient.',data):
			return "MySql Injection"
		# mssql errors
		if re.search(r'System.Data.OleDb.OleDbException|\[Microsoft]\[ODBC SQL Server Driver]|\[Macromedia]\[SQLServer JDBC Driver]|SqlException|System.Data.SqlClient.SqlException|Unclosed quotation mark after the character string|mssql_query()|Microsoft OLE DB Provider for ODBC Drivers|Microsoft OLE DB Provider for SQL Server|Incorrect syntax near|Sintaxis incorrecta cerca de|Syntax error in string in query expression|Unclosed quotation mark before the character string|Data type mismatch in criteria expression.|ADODB.Field (0x800A0BCD)|the used select statements have different number of columns',data): 
			return "MSSQL-Based Injection"
		# java sql errors
		if re.search(r'java.sql.SQLException|java.sql.SQLSyntaxErrorException|org.hibernate.QueryException: unexpected char:|org.hibernate.QueryException: expecting \'',data):
			return "Java.SQL Injection"
		# postgresql errors
		if re.search(r'PostgreSQL query failed:|supplied argument is not a valid PostgreSQL result|pg_query() \[:|pg_exec() \[:|valid PostgreSQL result|Npgsql.|PostgreSQL query failed: ERROR: parser:',data): 
			return "PostgreSQL Injection"
		# db2 errors
		if re.search(r'\[IBM]\[CLI Driver]\[DB2/6000]|DB2 SQL error',data):
			return "DB2 Injection"
		# interbase errors
		if re.search(r'<b>Warning</b>: ibase_|Unexpected end of command in statement|Dynamic SQL Error',data):
			return "Interbase Injection"
		# sybase errors
		if re.search(r'Sybase message:',data):
			return "Sybase Injection"
		# oracle errors
		if re.search(r'Oracle error',data): 
			return "Oracle Injection"
		# sqlite errors
		if re.search(r'SQLite/JDBCDriver|System.Data.SQLite.SQLiteException|SQLITE_ERROR|SQLite.Exception',data):
			return "SQLite Injection"
		return None