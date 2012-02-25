#!/usr/bin/env python

# Copyright (c) 2012
# 	Lars-Dominik Braun <lars@6xq.net>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import os, re, sys, subprocess, pyinotify

class Classifier (object):
	# files in junk are spam
	SPAMDIR = re.compile (r'mail/\.Junk/(new|cur)')
	# exclude: Unsure messages, temporary directory, trashed messages (see
	# http://cr.yp.to/proto/maildir.html), dovecot files
	EXCLUDE = re.compile (r'mail/(\.Unsure/(new|cur)|[^/]+/(tmp|.*:2,[A-S]*T[U-Z]*$)|.*dovecot)')

	SPAM = 1
	HAM = 2
	UNSURE = 3

	def statusFromFile (self, path):
		"""
		filter mail through bogofilter and return spam status
		"""

		ret = subprocess.call (['bogofilter', '-I', path])
		if ret == 2:
			return self.UNSURE
		elif ret == 1:
			return self.HAM
		elif ret == 0:
			return self.SPAM
		elif ret == 3:
			raise Exception ('bogofilter returned error')

	def statusFromPath (self, path):
		"""
		get spam status from file path
		"""

		if self.SPAMDIR.search (path):
			return self.SPAM
		else:
			return self.HAM
	
	def isExcluded (self, path):
		"""
		is path excluded?
		"""

		return self.EXCLUDE.search (path)
	
	def setStatus (self, curStatus, newStatus, path):
		"""
		tell bogofilter to set new spam status for message
		"""
		if curStatus != newStatus:
			bogoopts = None
			if curStatus == self.UNSURE:
				if newStatus == self.HAM:
					bogoopts = '-n'
				elif newStatus == self.SPAM:
					bogoopts = '-s'
			elif curStatus == self.SPAM and newStatus == self.HAM:
				bogoopts = '-Sn'
			elif curStatus == self.HAM and newStatus == self.SPAM:
				bogoopts = '-Ns'
			print 'bogoopts %s' % bogoopts
			ret = subprocess.call (['bogofilter', bogoopts, '-I', path])
			print 'bogofilter returned %i' % ret
			return True
		else:
			return False


	def updateStatus (self, path):
		"""
		does all the magic
		"""
		if self.isExcluded (path):
			return False
		curStatus = self.statusFromFile (path)
		newStatus = self.statusFromPath (path)
		return self.setStatus (curStatus, newStatus, path)

class EventHandler(pyinotify.ProcessEvent):
	def __init__ (self, wm, mask, classifier):
		pyinotify.ProcessEvent.__init__ (self)

		self.wm = wm
		self.mask = mask
		self.classifier = classifier

	def process_IN_MOVED_TO (self, event):
		self.classifier.updateStatus (event.pathname)

	def process_IN_CREATE (self, event):
		# make sure new directories are watched as well
		if event.mask & pyinotify.IN_ISDIR:
			wdd = self.wm.add_watch(event.pathname, self.mask, rec=True)
		else:
			self.classifier.updateStatus (event.pathname)

if __name__ == '__main__':
	c = Classifier ()
	wm = pyinotify.WatchManager()
	mask = pyinotify.IN_MOVED_TO | pyinotify.IN_CREATE
	handler = EventHandler(wm, mask, c)
	notifier = pyinotify.Notifier(wm, handler)
	wdd = wm.add_watch(os.path.expanduser ('mail/'), mask, rec=True)
	notifier.loop()

