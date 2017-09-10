#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# Spaghetti: Web Application Security Scanner
#
# @url: https://github.com/m4ll0k/Spaghetti
# @author: Momo Outaadi (M4ll0k)
# @license: See the file 'LICENSE.txt'

from color import Color

class Output:
	
	r = Color().red(1) 
	g = Color().green(1)
	y = Color().yellow(1)
	b = Color().blue(1)
	w = Color().white(0)
	e = Color().end()

	def plus(self,String):
		print ('{}[+]{} {}{}{}'.format(
			Output.g,
			Output.e,
			Output.w,
			String,
			Output.e)
		)
	
	def less(self,String):
		print ('{}[-]{} {}{}{}'.format(
			Output.r,
			Output.e,
			Output.w,
			String,
			Output.e)
		)

	def test(self,String):
		print ('{}[*]{} {}{}{}'.format(
			Output.b,
			Output.e,
			Output.w,
			String,
			Output.e)
		)
	
	def info(self,String):
		print ('{}[i]{} {}{}{}'.format(
			Output.y,
			Output.e,
			Output.w,
			String,
			Output.e)
		)