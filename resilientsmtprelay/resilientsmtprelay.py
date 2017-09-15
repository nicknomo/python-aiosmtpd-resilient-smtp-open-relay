import asyncio
import threading
import time
import re
import sys
import os
import dns.resolver
import distutils.util
from smtplib import SMTP as Client
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope
from configparser import SafeConfigParser

HELOname = 'myhost.mydomain.com'
smtprelayport = '10025'
bindip = '127.0.0.1'

#This is the backup gateway ip if you have one
backupgwip = '192.168.1.2'
backupgwipv6 = 'fd00:0:0:1::2'

#This is the interface windows associates with your ipv6 backup gateway
#This could still be your default adapter, or maybe a secondary adapter
#When the primary attempt at your default ipv4 and ipv6 gateway fails, it tries this adapter
#To find the correct adapter USE:  netsh int ipv6 show interfaces    
# THE DEFAULT IS ALMOST CERTAINLY WRONG!!!!
ipv6intnum = '3'


### These are BACKUP DNS providers in case your main dns provider fails
### It also is what the system will ping to attempt to check for internet connectivity
dnsproviderlist = ['8.8.8.8','8.8.4.4','4.2.2.1','2001:4860:4860::8888','2001:4860:4860::8844','2001:470:1f10:c6::2']

#How many times we will send a failed email
retrycount = 2

#How many times we will wait to resend a failed email
retrydelay = 2

#Enable ipv6 lookups (you can still use ipv6 dns servers)
ipv6enabled = False

relayoflastresortenabled = True
relayoflastresort = '192.168.1.3'


lock = threading.Lock()

def isipv6(ip):
	if ":" in ip:
		return True
	else:
		return False

def isbadtoroute(ip):
	if (isipv6(ip)):
		if (ip=='::1'):
			return True
		block = ip.split(':')
		if (block[0][:2]=='fe'):
			return True
		if (block[0][:2]=='fd'):
			return True
		if (block[0][:2]=='fc'):
			return True
		if (block[0][:2]=='ff'):
			return True
		return False
		
	octet = ip.split(".")
	
	if (octet[0]=='127'):
		return True
	if (octet[0]=='10'):
		return True
	if (int(octet[0])>=239):
		return True
	if (octet[0]=='172'):
		if ( (int(octet[1])>=16) and (int(octect[1])<=31) ):
			return True
	if (octet[0]=='192'):
		if (octet[1]=='168'):
			return True
	
	return False
	

def is_valid_ipv4_address(ip):
	pattern = re.compile(r"""
	        ^
	        (?:
	          # Dotted variants:
	          (?:
	            # Decimal 1-255 (no leading 0's)
	            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
	          |
	            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
	          |
	            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
	          )
	          (?:                  # Repeat 0-3 times, separated by a dot
	            \.
	            (?:
	              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
	            |
	              0x0*[0-9a-f]{1,2}
	            |
	              0+[1-3]?[0-7]{0,2}
	            )
	          ){0,3}
	        |
	          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
	        |
	          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
	        |
	          # Decimal notation, 1-4294967295:
	          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
	          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
	          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
	        )
	        $
	    """, re.VERBOSE | re.IGNORECASE)
	return pattern.match(ip) is not None
	

def is_valid_ipv6_address(ip):
	pattern = re.compile(r"""
	        ^
	        \s*                         # Leading whitespace
	        (?!.*::.*::)                # Only a single whildcard allowed
	        (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
	        (?:                         # Repeat 6 times:
	            [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
	            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
	        ){6}                        #
	        (?:                         # Either
	            [0-9a-f]{0,4}           #   Another group
	            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
	            [0-9a-f]{0,4}           #   Last group
	            (?: (?<=::)             #   Colon iff preceeded by exacly one colon
	             |  (?<!:)              #
	             |  (?<=:) (?<!::) :    #
	             )                      # OR
	         |                          #   A v4 address with NO leading zeros 
	            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
	            (?: \.
	                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
	            ){3}
	        )
	        \s*                         # Trailing whitespace
	        $
	    """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
	return pattern.match(ip) is not None

def isvalidip(ip):
	if (isipv6(ip)):
		return is_valid_ipv6_address(ip)
	else:
		return is_valid_ipv4_address(ip)
	

def deleteroute(ip):
	if (isbadtoroute(ip)):
		return
		
	if (isipv6(ip)==True):
		if (ipv6enabled):
			print("Deleting route: " + ip)
			os.system('route delete ' + ip + '/128')
	else:
		print("Deleting route: " + ip)
		os.system('route delete ' + ip)
		
def addroute(ip):
	if (isbadtoroute(ip)):
		return
		
	if (isipv6(ip)==True):
		if (ipv6enabled):
			print("ADDING ROUTE: " + ip)
			os.system('netsh interface ipv6 add route ' + ip + '/128 interface=\"' + ipv6intnum + '\" ' + backupgwipv6 )
	else:
		print("ADDING ROUTE: " + ip)
		os.system('route add ' + ip + ' ' + backupgwip + ' metric 5')
	
	

###Clears all routes that were added
def cleardnsroutes():
	for dnsprovider in dnsproviderlist:
		deleteroute(dnsprovider)
		
		
###Temporarily adds routes to dns providers
def adddnsroutes():
	for dnsprovider in dnsproviderlist:
		addroute(dnsprovider)



class mailsender(threading.Thread):	

	email_to = ''
	email_from = ''
	data = ''
	envelope = None
	lock = None
	
		
	def __init__(self,mail_from,recipient,envelopedata):
		threading.Thread.__init__(self)
		self.email_from = mail_from
		self.email_to = recipient
		self.data = envelopedata.content
		self.envelope = envelopedata
		self.lock = lock
		
		
	## Here we run the actual DNS query
	def runmxquery(self,dnsrequest,host):	
		#This is a list of the MX hostnames we'll need to search for
		mxlist = []	
		
		#first we get answers to the MX record request
		try:
		    	answers = dnsrequest.query(host, 'MX')
		    	for rdata in answers:
		    		dnsmx = rdata.to_text()
		    		#MX records return a priority and a hostname
		    		#We need to separate the two for proper sorting
		    		temp = dnsmx.split()
		    		tempint = int(temp[0])
		    		mxlist.append((tempint,temp[1]))
		    	
		except BaseException as e:
			print(e)
		
								
		#if there are no mx records, we return an empty set
		if mxlist: 
			#Here we sort the mx records by priority, so the most important are chosen first
			mxlist = sorted(mxlist, key=lambda tup: tup[0])
			return mxlist
		else:
			return []


	def runAquery(self,dnsrequest,mxlist):	
		#this is a list of the DNS results in IP form
		dnslist = []	
		
		for mxrecord in mxlist:
			try:
			    	answers = dnsrequest.query(mxrecord[1], 'A')
			    	for rdata in answers:
			    		dnsip = rdata.to_text()
			    		dnslist.append(dnsip)
		    	
			except BaseException as e:
				print(e)
				
		if (not ipv6enabled):
			return dnslist

		
		#Now we'll gather ipv6 ips', and put them at the end of the list
		for mxrecord in mxlist:

			try:
				answers = dnsrequest.query(mxrecord[1], 'AAAA')
				for rdata in answers:
			    		dnsip = rdata.to_text()
			    		dnslist.append(dnsip)
	
			except BaseException as e:
				print(e)	
		
		#Hopefully we'll have IP addresses to return now					
		return dnslist


	



	#This will gather MX records and return IP addresses
	def getmxrecords(self,email):
		_, _, domain = email.partition('@')
		dnsrequest = dns.resolver.Resolver()
		dnsrequest.timeout = 3
		dnsrequest.lifetime = 6
		mxlist = []
		dnslist = []
		
		try:
			#We try the default dns server first
			mxlist = self.runmxquery(dnsrequest,domain)
			
			if (mxlist):
				dnslist = self.runAquery(dnsrequest,mxlist)
				if (dnslist):
					return dnslist
		
		except BaseException as e:
			print("mx records exception")
			print(e)
		
		print("Now in MX records middle")
		
		if not dnslist:
			#Now we search our alternate servers
			for dnsserver in dnsproviderlist:
				if ( isipv6(dnsserver) and not ipv6enabled ) : 
					print("Skipping ipv6 DNS provider")
					continue
				try:
					dnsrequest.nameservers = [dnsserver]
					mxlist = self.runmxquery(dnsrequest,domain)
					if (mxlist): 
						dnslist = self.runAquery(dnsrequest,mxlist)
						if (dnslist): 
							return dnslist
			
				except BaseException as e:
					print(e)
			
			
		
		return dnslist
		
	
	def generateSMTP(self,ip,recipient,message=None):
		if (not message):
			message=self.data
			
		client = Client(ip, '25',HELOname,8)
		#unfortunately, sending the additional options did not work well in SMTPlib.
		#r = client.sendmail(self.email_from, [recipient], message, self.envelope.mail_options, self.envelope.rcpt_options)
		r = client.sendmail(self.email_from, [recipient], message)	
	
	
	def run(self):
		self.sendemail(self.email_to)
	
	
	def sendemail(self,recipient,message=None,isNDR=None):
		failmessage = ""
		try:
			self.lock.acquire()
			cleardnsroutes()
			iplist = self.getmxrecords(recipient)
			self.lock.release()
			
			if not iplist:
				self.lock.acquire()
				adddnsroutes()
				iplist = self.getmxrecords(recipient)
				cleardnsroutes()
				if not iplist:
					raise Exception('Could Not send email to ' + self.email_to + '. There were no IPs returned from DNS lookup, the domain is likely malformed')
				self.lock.release()			
			
			
			for x in range(retrycount):
				for ip in iplist:
					self.lock.acquire()
					try:
						self.generateSMTP(ip,recipient,message)
						self.lock.release()
						return
			
					except BaseException as e:
						print(e)
						failmessage=str(e)
						self.lock.release()		
					

					## Try out the other gateway
					self.lock.acquire()
					addroute(ip)
					
					try:					
						self.generateSMTP(ip,recipient,message)
						self.lock.release()
						return
			
					except BaseException as e:
						print(e)
						failmessage=failmessage + " \n" + str(e) + " \n"
						self.lock.release()					
					
					deleteroute(ip)
						
				time.sleep(retrydelay)			
				
			if (relayoflastresortenabled):
				self.lock.acquire()
				try:
					self.generateSMTP(relayoflastresort,recipient,message)
					self.lock.release()
					return
					
				except BaseException as e:
					print(e)
					failmessage=failmessage + " \n" + str(e) + " \n"
					self.lock.release()
					if (not isNDR):
						self.sendemail(self.email_from,failmessage,True)
			else:
				if (not isNDR):
					self.sendemail(self.email_from,failmessage,True)
				
			
			
			
		except BaseException as e:
			print(e)
			failmessage=str(e)
			self.lock.release()
			cleardnsroutes()
			time.sleep(30)
			
			if (relayoflastresortenabled):
				self.lock.acquire()
				try:
					self.generateSMTP(relayoflastresort,recipient,message)
					self.lock.release()
					return
					
				except BaseException as e:
					print(e)
					failmessage=failmessage + " \n" + str(e) + " \n"
					self.lock.release()
					if (not isNDR):
						self.sendemail(self.email_from,failmessage,True)
				
			else:
				if (not isNDR):
					self.sendemail(self.email_from,failmessage,True)
					
			
	
	





class CustomHandler:

	def validate(self, email):
		if len(email) > 7:
			if re.match("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email) != None:
				return True
			return False

	async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
		valid = False
		try:
			valid = self.validate(address)
		except BaseException as e:
	        	print(e)
	        	
		if not valid:
			return '501 5.5.4 invalid email address'
		envelope.rcpt_tos.append(address)
		return '250 OK'

	async def handle_DATA(self, server, session, envelope):
	        peer = session.peer
	        mail_from = envelope.mail_from
	        rcpt_tos = envelope.rcpt_tos
	        data = envelope.content
	        threads = list()
	        # Process message data...
	        error_occurred=False
	        try:
	        	for recipient in rcpt_tos:
	        		send = mailsender(mail_from,recipient,envelope)
	        		send.start()
	        	
	        except BaseException as e:
	        	print(e)
	        	
	        if error_occurred:
	            return '500 Could not process your message'
	        return '250 OK'




def getValuesFromConfigFile(configfile):
	global dnsproviderlist,HELOname,smtprelayport,bindip,backupgwip,backupgwipv6,ipv6intnum,retrydelay,retrycount,ipv6enabled,relayoflastresortenabled,relayoflastresort
	parser = SafeConfigParser()
	parser.read(configfile)
	for section_name in parser.sections():		
		for name, value in parser.items(section_name):
			if (name=='dnsproviderlist'):
				list = [e.strip() for e in value.split(',')]
				newlist=[]
				for element in list:
					if ( (isvalidip(element)) and (not isbadtoroute(element)) ):
						newlist.append(element)
					else:
						print("Invalid ip address: " + element)
				if (newlist):
					dnsproviderlist=newlist
					print(name + ": ")
					print(dnsproviderlist)
					
				else:
					print("Using default DNS provider list")
				
				
			if (name=='heloname'):
				HELOname=value
				print(name + ": " + value)
				
			if (name=='smtprelayport'):
				if ( (int(value) > 0) and ( int(value) < 65535) ):
					smtprelayport = value
					
				else:
					print("Invalid port assignment, using default of 10025")
				
				
			if (name=='bindip'):
				if (isvalidip(value)):
					bindip = value
				else:
					print("Invalid binding IP, using localhost")
				print(name + ": " + value)
				
			if (name=='backupgwip'):
				if (isvalidip(value)):
					backupgwip = value
				else:
					print("Invalid backup gateway (ipv4), using default of 192.168.1.2")
				print(name + ": " + value)
								
			if (name=='backupgwipv6'):
				if (isvalidip(value)):
					backupgwipv6 = value
				else:
					print("Invalid backup gateway (ipv6), using default of fd00:0:0:1::2")
				
				print(name + ": " + value)
				
			if (name=='ipv6intnum'):
				ipv6intnum = value
				print(name + ": " + value)
				
			if (name=='retrydelay'):
				if ((int(value)>0) and (int(value)<=7200)):
					retrydelay = int(value)
				else:
					print("The retry delay must be between 1 and 7200 seconds")
				print(name + ": " + value)
				
			if (name=='retrycount'):
				if ((int(value)>=0) and (int(value)<=50)):
					retrycount = int(value) + 1
				else:
					print("The retry count must be between 0 and  ")				
				print(name + ": " + value)
				
			if (name=='ipv6enabled'):
				try:
					ipv6enabled = bool(distutils.util.strtobool(value))
					print(name + ": " + value)
				
				except BaseException as e:
					print(e)
					print("IPV6 will be disabled")
					
			if (name=='relayoflastresortenabled'):				
				try:
					relayoflastresortenabled = bool(distutils.util.strtobool(value))
					print(name + ": " + value)
				
				except BaseException as e:
					print(e)
					print("Relay of last resort disabled")
				
			if (name=='relayoflastresort'):
				if (isvalidip(value)):
					relayoflastresort = value
					print(relayoflastresort)
				else:
					print("Invalid Relay of last resotr, using default of 192.168.1.3")
				print(name + ": " + value)
				
			
			
			


if __name__ == '__main__':
	handler = CustomHandler()
	controller = Controller(handler, hostname=bindip, port=smtprelayport)
	# Run the event loop in a separate thread.
	
	try:
		getValuesFromConfigFile('settings.ini')
		
		
	except BaseException as e:
		print(e)
		print("Error Reading settings.ini")
	
	print("test")
	print(relayoflastresortenabled)
	print(relayoflastresort)
	
	controller.start()


	input('SMTP server running. Press Return to stop server and exit. \n')
	controller.stop()
