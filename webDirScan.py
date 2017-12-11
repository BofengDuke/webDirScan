#!/usr/bin/python3
#-*- coding:utf-8 -*-

'''
Author:	Duke
Description: This script will help you to scan web path,maybe you can find something interesting. 
'''

import os,sys,platform,time
import threading
import requests
import argparse
import warnings
import logging
import logging.handlers
import traceback

from pprint import pprint
from queue import Queue
from bs4 import BeautifulSoup


if platform.python_version() < "3":
	from urlparse import urlparse
else:
	from urllib.request import urlparse

warnings.filterwarnings("ignore")

# requests config
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0"
HEADERS = {
	'User-Agent': USER_AGENT
}
TIMEOUT = 10
IS_VERIFY = False
IS_ALLOW_REDIRECTS = False
THREAD_NUM = 10

CREATE_LOG = False




class WebRequestThread(threading.Thread):
	"""docstring for WebRequestThread"""
	def __init__(self, baseurl,pathQueue,result_2xx,result_3xx,result_4xx,result_5xx):
		"""
		Param:
			- baseurl: such as http://example.com/bar/
		"""
		super(WebRequestThread, self).__init__()
		self.baseurl = baseurl
		self.pathQueue = pathQueue
		self.result_2xx = result_2xx
		self.result_3xx = result_3xx
		self.result_4xx = result_4xx
		self.result_5xx = result_5xx

	def run(self):
		while not self.pathQueue.empty():
			path = self.pathQueue.get()
			if path.startswith('/'):
				path = path.lstrip('/')
				url = self.baseurl+path
			else:
				url = self.baseurl+path

			try:
				r = requests.get(url,headers=HEADERS,timeout=TIMEOUT,verify=IS_VERIFY,allow_redirects=IS_ALLOW_REDIRECTS)
				r.encoding = r.apparent_encoding
				soup = BeautifulSoup(r.text,'lxml')

				# If it is 404 page,pass it.
				if soup.title != None and '404' in soup.title.string:
					continue
				# Get url and title info
				if soup.title == None:
					continue
				else:
					data = r.url + "|"+soup.title.string
				
				print(soup.title)

				if  200 <= r.status_code < 300:
					self.result_2xx.add(data)
				elif 300 <= r.status_code < 400:
					self.result_3xx.add(data)
				elif 400 <= r.status_code < 500:
					pass
					# self.result_4xx.add(r.url)
				elif 500 <= r.status_code:
					self.result_5xx.add(data)
				else:
					continue

			except requests.exceptions.ConnectionError as e:
				if CREATE_LOG:
					logging.error(" url : ",url)
					# logging.error("ConnectionError: "+e," url : ",url)
			except requests.exceptions.Timeout as e:
				if CREATE_LOG:
					logging.error(" url : ",url)
			except Exception as e:
				if CREATE_LOG:
					logging.error(" url : ",url)
					# logging.error("Exception: "+e," url : ",url)


def isWebCanAccess(baseurl):
	""" Test the base url whether can access normal or not.
	"""
	try:
		r = requests.get(baseurl,headers=HEADERS,timeout=TIMEOUT,verify=IS_VERIFY,allow_redirects=IS_ALLOW_REDIRECTS)
		return True
	except requests.exceptions.ConnectionError as e:
		print(baseurl+' ConnectionError: ',e)
		return False
	except requests.exceptions.Timeout as e:
		print(baseurl+' Timeout ',e)
		return False
	except Exception as e:
		print(baseurl+' Exception ',e)
		return False
				

def singleWebScan(baseurl,pathList,threadNum):
	""" Scan the input address by path queue
	Param:
	- baseurl : the base url to scan, just like 'http://baidu.com'
	
	Return:
	-result_all = {
		'baseurl':'http://baidu.com',
		'result_2xx':['/index.html',...],
		'result_3xx':['...'],
		'result_4xx':['...'],
		'result_5xx':['...']
	}
	"""

	# The result of HTTP code like 200,302,404,500 and so on.
	result_2xx = set()
	result_3xx = set()
	result_4xx = set()
	result_5xx = set()
	result_all = {}

	# Checked if the host can be accessed.
	# If not, will be pass.
	baseurl = baseurl.rstrip('\n')
	host = urlparse(baseurl).scheme +"://"+ urlparse(baseurl).netloc
	if not isWebCanAccess(host):
		return None

	hasScanPath = set()
	toScanPath = Queue()
	for path in urlparse(baseurl).path.rstrip('/').split('/'):
		newPath = host+"/"+path
		toScanPath.put(newPath)

	while not toScanPath.empty():
		
		# To recursive scan the web url
		currentPath = toScanPath.get()
		if not currentPath.endswith('/'):
			currentPath = currentPath +"/"

		pathQueue = Queue()
		for path in pathList:
			pathQueue.put(path.strip('\n'))

		try:
			threads = []
			for i in range(threadNum):
				thread = WebRequestThread(currentPath,pathQueue,result_2xx,result_3xx,result_4xx,result_5xx)
				thread.start()
				threads.append(thread)

			for thread in threads:
				thread.join()
		except KeyboardInterrupt as e:
			traceback.print_exc()
			sys.exit()
		hasScanPath.add(currentPath)
		for url in result_2xx:
			url = url.split('|')[0]
			
			if len(url.split('.')) > 1:
				# This url end with like index.html,not REST like a/b or a/b/
				continue

			if url not in hasScanPath and url not in toScanPath:
				toScanPath.put(url)

	result_all['baseurl'] = baseurl
	result_all['result_2xx'] = list(result_2xx)
	result_all['result_3xx'] = list(result_3xx)
	result_all['result_4xx'] = list(result_4xx)
	result_all['result_5xx'] = list(result_5xx)

	return result_all

def mutipleWebScan(baseurlQueue,pathList,threadNum):
	""" Scan multiple baseurl
	Return:
	- result_all = [{'baseurl':'xxx.xx','result_2xx':['xx',...],'result_3xx':['xx',...],'result_4xx':[...],'result_5xx':[..]},
					{...}, ...
					]
	"""
	result_all = []

	while not baseurlQueue.empty():
		baseurl = baseurlQueue.get()
		result = singleWebScan(baseurl,pathList,threadNum)
		if result != None :
			result_all.append(result)

	return result_all

def outputToFile(result_all,fileName):
	"""	This function will write result to text file.
	"""
	fp = open(fileName,'w+')
	for result in result_all:
		fp.write('--------------------------------\n')
		baseurl = result.get('baseurl')
		fp.write('base url: '+baseurl+"\n")
		result_2xx = result.get('result_2xx')
		result_3xx = result.get('result_3xx')
		result_4xx = result.get('result_4xx')
		result_5xx = result.get('result_5xx')

		if len(result_2xx) != 0:
			fp.write('HTTP CODE 200\n')
			result_2xx = [line+"\n" for line in result_2xx]
			fp.writelines(result_2xx)

		if len(result_3xx) != 0:
			fp.write('HTTP CODE 3xx\n')
			result_3xx = [line+"\n" for line in result_3xx]
			fp.writelines(result_3xx)

		if len(result_4xx) != 0:
			fp.write('HTTP CODE 4xx\n')
			result_4xx = [line+'\n' for line in result_4xx]
			fp.writelines(result_4xx)

		if len(result_5xx) != 0:
			fp.write('HTTP CODE 5xx\n')
			result_5xx = [line+'\n' for line in result_5xx]
			fp.writelines(result_5xx)




def usage():
	example = """
Example:
  base usage: 
    python3 %s -u https://example.com --pathlist pathlist.txt
    python3 %s --urllist urllist.txt --pathlist pathlist.txt

  output to console: -vv
    python3 %s -u https://example.com --pathlist pathlist.txt -vv

  output to file: -o
    python3 %s -u https://example.com --pathlist pathlist.txt -o output.txt

  modify the thread number,default is 10: --thread
    python3 %s -u https://example.com --pathlist pathlist.txt -vv  -o output.txt --thread 20 

	"""
	return example

def getArgParse():
	""" Parse the arg which from console.

	"""
	description = "This script is to help you to scan the web path."
	parser = argparse.ArgumentParser(description=description)

	parser.add_argument('-hh',help="more help for this script",action='store_true')

	inputGroup = parser.add_argument_group("INPUT")
	inputGroup.add_argument('-u','--url',help='The base url to scan.Like -u http://baidu.com')
	inputGroup.add_argument('--urllist',help='The base url list to casn.Like -ul urllist.txt')
	inputGroup.add_argument('--pathlist',help='The path to be scaned. Like -pl pathlist.txt')

	outputGroup = parser.add_argument_group("OUTPUT")
	outputGroup.add_argument('-v','--verbose',help='This option whill print result in console.',action='store_true')
	outputGroup.add_argument('-o','--output',help='Output the result to text file.')
	outputGroup.add_argument('--log',help='Create a log file to record error message.')

	otherGroup = parser.add_argument_group("OTHER")
	otherGroup.add_argument('--thread',help='The thread number to scan.Default is 10.',type=int,default=10)

	args = parser.parse_args()
	return args

def main():
	args = getArgParse()
	
	result_all = []
	pathList = []

	if len(sys.argv) == 1:
		os.system('python %s -hh'%sys.argv[0])
		sys.exit(1)

	if args.hh:
		os.system('python %s -h'%sys.argv[0])
		print(usage())
		sys.exit(1)

	if args.pathlist:
		pathFile = args.pathlist
		fp = open(pathFile,'r')
		pathList = fp.readlines()
		fp.close()

	else:
		print(usage())
		sys.exit(1)

	if args.thread:
		threadNum = args.thread
	else:
		threadNum = THREAD_NUM
	
	if args.log:
		global CREATE_LOG
		CREATE_LOG = True

		DEFAULT_LOG_FILE = args.log
		fmt = '%(asctime)s - %(filename)s:%(lineno)s - %(message)s'  
		formatter = logging.Formatter(fmt)   # 实例化formatter  
		handler = logging.handlers.RotatingFileHandler(DEFAULT_LOG_FILE, maxBytes = 1024*1024, backupCount = 5) # 实例化handler   
		handler.setFormatter(formatter)      # 为handler添加formatter  
		logger = logging.getLogger('log')    # 获取名为log的logger  
		logger.addHandler(handler)           # 为logger添加handler  
		logger.setLevel(logging.ERROR)  

	if args.url:
		baseurl = args.url
		result = singleWebScan(baseurl,pathList,threadNum)
		if result != None:
			result_all.append(result)
	elif args.urllist:
		urlFile = args.urllist
		fp = open(urlFile,'r')
		baseurlList = fp.readlines()
		fp.close()

		baseurlQueue = queue.Queue()
		for url in baseurlList:
			baseurlQueue.put(url)

		result_all = mutipleWebScan(baseurlQueue,pathList,threadNum)
	else:
		print(usage())
		sys.exit(1)

	if args.verbose:
		pprint(result_all)

	if args.output:
		outputFile = args.output
		outputToFile(result_all,outputFile)

	

if __name__ == '__main__':
	main()


