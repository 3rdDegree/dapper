#!/usr/bin/python

import getopt
import subprocess
import os
import random
import socket
import sys

# Check dependencies
missing_ldap = False

try:
	import ldap
	import ldap.schema

except ImportError:
	missing_ldap = True



class Ui:
	def __init__(self):
		self.INDENT = 0
		self.MAX_WIDTH = 80
		
		self.good_times = ("W00t", "Sweet", "Score", "Great news", "Booyaa", "Yippie", "Rad", "Excellent", "Shablang")
		self.bad_times  = ("Crap", "Oh darn", "WTF", "This sucks", "Now what!?", "SON-OF-A", "Dammit")

		self.logging = False
		self.log = None

		
		self.PURPLE = "\033[95m"
		self.CYAN = "\033[96m"
		self.DARKCYAN = "\033[36m"
		self.BLUE = "\033[94m"
		self.GREEN = "\033[92m"
		self.YELLOW = "\033[93m"
		self.RED = "\033[91m"
		self.BOLD = "\033[1m"
		self.UNDERL = "\033[4m"
		self.ENDC = "\033[0m"
		self.backBlack = "\033[40m"
		self.backRed = "\033[41m"
		self.backGreen = "\033[42m"
		self.backYellow = "\033[43m"
		self.backBlue = "\033[44m"
		self.backMagenta = "\033[45m"
		self.backCyan = "\033[46m"
		self.backWhite = "\033[47m"

		self.colors = [ self.PURPLE, self.CYAN, self.DARKCYAN, self.BLUE, self.GREEN, self.YELLOW, self.RED, self.BOLD, self.UNDERL, self.ENDC, self.backBlack, self.backRed, self.backGreen, self.backYellow, self.backBlue, self.backMagenta, self.backCyan, self.backWhite ]
	
	def disable(self):
		self.PURPLE = ""
		self.CYAN = ""
		self.BLUE = ""
		self.GREEN = ""
		self.YELLOW = ""
		self.RED = ""
		self.ENDC = ""
		self.BOLD = ""
		self.UNDERL = ""
		self.backBlack = ""
		self.backRed = ""
		self.backGreen = ""
		self.backYellow = ""
		self.backBlue = ""
		self.backMagenta = ""
		self.backCyan = ""
		self.backWhite = ""
		self.DARKCYAN = ""

	def indent(self):
		self.INDENT += 2
		
	def outdent(self):
		if self.INDENT != 0:
			self.INDENT -= 2

	def open_log(self, logfile):

		try:
			self.logging = True
			self.log = open(logfile, "w")
		except:
			self.logging = False
			self.log = None

	def print_ln(self, text=""):
		print (" " * self.INDENT) + text

		if self.logging:

			# Strip colors chars out of log
			for color in self.colors:
				text = text.replace(color, "")
			self.log.write((" " * self.INDENT) + text + "\n")
		
	def print_caption(self, text):
		title = self.GREEN + text + self.ENDC
		self.print_ln(self.center(title))
	
	def print_error(self, text):
		text = random_pick(self.bad_times) + "! " + text
		text = self.RED + "[-] " + text + self.ENDC
		self.print_ln(text)

	def print_good(self, text):
		text = random_pick(self.good_times) + "! " + text
		
		text = self.GREEN + "[+] " + text + self.ENDC
		self.print_ln(text)

	def print_menu_opt(self, id, text):
		# Temporarily ignore indent
		tmp_indent = self.INDENT
		self.INDENT = 2

		text = "[%d]\t%s" % (id, text)
		self.print_ln(text)

		# Restore indent
		self.INDENT = tmp_indent
		
	def print_status(self, text):
		text = self.BLUE + "[*] " + text + self.ENDC
		self.print_ln(text)

	def print_subtitle(self, label, text):
		text = self.BLUE + label + self.ENDC + \
				self.RED +  text  + self.ENDC
		self.print_ln(self.center(text))

	def print_title(self, text):
		text = self.YELLOW + text + self.ENDC
		self.print_ln(self.center(text))

	def bold(self, text):
		return self.BOLD + text + self.ENDC

	def center(self, text):
		return text.center(self.MAX_WIDTH)
	
	def max_len(self, items):
		size = 0
	
		for item in items:
			if size < len(item):
				size = len(item)
		return size

	def show_menu(self, options, prompt="main"):
		for opt in sorted(options.keys()):
			self.print_menu_opt(opt, options[opt])

		self.print_ln()
		
		choice = -1
		try:
			choice = int(raw_input("%s> " % prompt))
		except:
			pass

		return choice
			

def random_pick(items):
	choice = None
	
	if items:
		items_max = len(items) - 1
		choice = items[random.randint(0, items_max)]
	
	return choice


class Dapper:
	

	def __init__(self, ldapurl=""):
		self.APPLE_PW_PORT = 3659
		self.APPLE_PW_SLOT = 3659
		self.PATH_NMAP = "/usr/local/bin/"

		self.conn = None
		self.ldapurl = ldapurl
		self.limit = 0
		self.discovered = []
		self.rootdse = {}
		self.namingContexts = None
		self.subschema = None
		self.subschema_tried = False
		self.subSchemaSubentry = None
		self.ui = Ui()
		self.verbose = False
		
		if os.name != "posix":
			self.ui.disable()
			
		self.phrase_list = ("I don't always hack protocols, but when I do, I prefer LDAP",
							"Automate to dominate",
							"Check yourself before you riggity wreck yourself",
							)	
	def connect(self):
		try:
			l = ldap.initialize(self.ldapurl)
			l.network_timeout = 4
			l.simple_bind_s("","")
	
			self.ui.print_status("Bind to %s succeeded" % self.ldapurl)
	
		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))				
			l = None
#			sys.exit(1)
		
		self.conn = l

		return self.conn != None

	def disconnect(self):
		if self.conn:
			self.conn.unbind()
			self.ui.print_status("Disconnected from %s" % self.ldapurl)
			self.conn = None	

	def get_rootdse(self):
		if self.conn:
			searchfilter = "objectclass=*"
			base = ""
			scope = ldap.SCOPE_BASE
			retrieve_attrs = None

			timeout = 0

			self.ui.print_status("Fetching RootDSE")
			self.ui.indent()
			try:
				result_id = self.conn.search(base, scope, searchfilter, retrieve_attrs)
		
				result_type, result_data = self.conn.result(result_id, timeout)
				
				if result_type == ldap.RES_SEARCH_ENTRY:
		
					for entry in result_data:
						column = self.ui.max_len(entry[1].keys()) + 3

						# HANDLE OPENLDAP ROOTDSE PROB (TODO: use for fingerprinting later)
						if len(entry[1].keys()) == 1:
							self.get_rootdse_openldap()
							break
		
						for key in entry[1].keys():
							# Grab the namingContext entry (search base) - defaultNamingContext in Windows
							if key.lower() == "namingcontexts":
								self.namingContexts = entry[1][key][0] 
							# Grab the name of the schema entry
							if key.lower() == "subschemasubentry":
								self.subSchemaSubentry = entry[1][key][0] 
							# todo: make key/val print method?
							# drunk dan has no idea what above means						
							
							self.rootdse[key] = ", ".join(entry[1][key])
							
							if self.verbose:
								self.ui.print_ln("%s%s" % ((key + ":").ljust(column), ", ".join(entry[1][key])))
				
			except ldap.LDAPError, e:
				self.ui.print_error(self.str_ldap_error(e))

			self.ui.outdent()
	
	def get_rootdse_openldap(self):
		if self.conn:
			searchfilter = "objectclass=*"
			base = ""
			scope = ldap.SCOPE_BASE

			# Stolen from Nmap scripts...The namingContexts was not there, try to query all attributes instead
			# Attributes extracted from Windows 2003 and complemented from RFC
			retrieve_attrs = ["_","configurationNamingContext","currentTime","defaultNamingContext",
			"dnsHostName","domainFunctionality","dsServiceName","forestFunctionality","highestCommittedUSN",
			"isGlobalCatalogReady","isSynchronized","ldap-get-baseobject","ldapServiceName","namingContexts",
			"rootDomainNamingContext","schemaNamingContext","serverName","subschemaSubentry",
			"supportedCapabilities","supportedControl","supportedLDAPPolicies","supportedLDAPVersion",
			"supportedSASLMechanisms", "altServer", "supportedExtension"]

			timeout = 0

			try:
				result_id = self.conn.search(base, scope, searchfilter, retrieve_attrs)
		
				result_type, result_data = self.conn.result(result_id, timeout)
				
				if result_type == ldap.RES_SEARCH_ENTRY:
		
					for entry in result_data:
						column = self.ui.max_len(entry[1].keys()) + 3
		
						for key in entry[1].keys():

							# Grab the namingContext entry (search base)
							if key.lower() == "namingcontexts":
								self.namingContexts = entry[1][key][0] 
							# Grab the name of the schema entry
							if key.lower() == "subschemasubentry":
								self.subSchemaSubentry = entry[1][key][0] 
							# todo: make key/val print method?
							self.rootdse[key] = ", ".join(entry[1][key])
							self.ui.print_ln("%s%s" % ((key + ":").ljust(column), ", ".join(entry[1][key])))
				
			except ldap.LDAPError, e:
				self.ui.print_error(self.str_ldap_error(e))

	def discover(self, targets):

		self.ui.print_status("Scanning targets {%s}" % targets)
		tmpfile = "/tmp/nmap_out.txt"
#		result = subprocess.Popen("cd %s/;nmap -Pn -n -p389,636 -oG %s %s" % (self.PATH_NMAP, tmpfile, targets), shell=True).wait()
		result = 0

		if result != 0:
			self.ui.print_error("Nmap reported an error (ret code %d). Next time, try harder." % result)
			return
		try:
			output = open(tmpfile)

			for line in output:
				portpos = line.find("Ports:")
				if portpos > 0:
					line = line.replace("Host: ", "")
					spaced = line.split(" ")
					host = spaced[0]
					if line.find(" 389/") > 0:
						self.discovered.append("ldap://%s:389" % host)

					if line.find(" 636/") > 0:
						self.discovered.append("ldaps://%s:636" % host)
		except Exception,e:
			self.ui.print_error(e.message)

		#os.unlink(tmpfile)

		print self.discovered

	def get_schema(self):
		
		self.subschema_tried = True
		if self.conn:
			self.ui.print_status("Fetching Schema")
			self.ui.indent()
			try:
				# Fetch rootDSE for subschema if necessary
				if self.subSchemaSubentry == None:
					self.get_rootdse()
				res = self.conn.search_s(self.subSchemaSubentry, ldap.SCOPE_BASE, "(objectclass=*)", ["*","+"])
				
				if res:
					self.subschema = ldap.schema.SubSchema(res[0][1])
				
			except ldap.LDAPError, e:
				self.ui.print_error(self.str_ldap_error(e))

			self.ui.outdent()
	
	
	def dump_email(self):

		self.ui.print_status("Fetching email addresses")
		self.ui.indent()
		try:
			result_set = self.search("mail=*", retrieve_attrs=["mail"], limit=self.limit)
				
			if len(result_set) == 0:
				self.ui.print_error("No results found.")
				
			else:
				count = 0
				for i in range(len(result_set)):
					for entry in result_set[i]:		
						email = "no email"
						if entry[1].has_key("mail"):
							email = ", ".join(entry[1]["mail"])
						count += 1
	
						self.ui.print_ln("%04d: %s" % (count, email))
	
		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))
		
		self.ui.outdent()
	
	def search_admin(self):

		self.ui.print_status("Searching for admins")
		self.ui.indent()
		try:
			result_set = self.search("cn=*admin*", limit=self.limit)
	
			if len(result_set) == 0:
				self.ui.print_error("No results found")
			else:
				
				count = 0
				for i in range(len(result_set)):
					for entry in result_set[i]:
	
						name = ""
						if entry[1].has_key("cn"):
							name  = entry[1]["cn"][0]
						
						password = ""
						if entry[1].has_key("userPassword"):
							password = ":" + ", ".join(entry[1]["userPassword"])
						
						email = ""
						if entry[1].has_key("mail"):
							email = "(" + ", ".join(entry[1]["mail"]) + ")" 
							
						count += 1
							
						self.ui.print_ln("%04d: %s%s %s" % (count, name, password, email))

		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))
		
		self.ui.outdent()
	
	def search_password(self):

		passwords = []

		self.ui.print_status("Searching for passwords")
		self.ui.indent()
		try:			
			self.ui.print_status("Looking up password-like attributes in schema")

			found_attrs = self.search_schema(ldap.schema.AttributeType, ["userPassword"])

			self.ui.print_status("Found %d password-like attributes in schema" % len(found_attrs))

			if found_attrs == None or len(found_attrs) == 0:
				raise Exception, "No password-like attributes found in schema"

			self.ui.print_status("Fetching objects with password-like attributes")
			
			searchfilter = self.create_filter_or(found_attrs)
			result_set = self.search(searchfilter, limit=self.limit)

			if len(result_set) == 0:

				self.ui.print_status("No results found, trying with empty search base...")
				result_set = self.search(searchfilter, base="*", limit=self.limit)

				if len(result_set) == 0:
					self.ui.print_error("No results found with empty search base...we tried.")
					return result_set
				
			count = 0
			self.ui.print_good("Found some password-like entries!")
			self.ui.indent()
			for i in range(len(result_set)):
				for entry in result_set[i]:
									
					# Pull common name and password-like attributes
					name = ""
					if entry[1].has_key("cn"):
						name  = entry[1]["cn"][0]

					
					for attr in found_attrs:
						if entry[1].has_key(attr):
							count += 1
							passwords.append(entry[1][attr][0])
							self.ui.print_ln("%04d: %s, %s" % (count, name, ":".join(passwords)))
			self.ui.outdent()
		
		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))

		except Exception, e:
			self.ui.print_error(str(e))
		self.ui.outdent()

		return passwords
	
	def crack_passwords(self, hashes, wordlist_name):

		self.ui.print_status("Attempting to crack %d password hash(es)" % len(hashes))
		self.ui.indent()

		# Test if file exists
		try:
			wordlist = open(wordlist_name, "r")
		except:
			self.ui.print_error("Error opening file %s" % wordlist_name)
			return

		while 1:
			test = wordlist.readline()
			if test:
				test = test.rstrip()
				self.ui.print_ln(test)

			else:fixesfixes
				break

		self.ui.outdent()

	def dump_entrust_roaming_uids(self, id_field="uid"):

		roaming_uids = []

		self.ui.print_status("Fetching Entrust Roaming User UID's")
		self.ui.indent()
		try:
			# works on opp #result_set = self.search("(&(%s=*)(entrustRoamingSLA=*))" % id_field, retrieve_attrs=["uid"], limit=self.limit)
			result_set = self.search("entrustRoamingSLA=*", retrieve_attrs=["uid"], limit=self.limit)
			if len(result_set) == 0:
				self.ui.print_error("No results found.")
				
			else:
				count = 0
				for i in range(len(result_set)):
					for entry in result_set[i]:
						uid = ""
						print entry
						if entry[1].has_key(id_field):
							uid = entry[1][id_field][0]
							roaming_uids.append(uid)
						count += 1
	
						self.ui.print_ln("%04d: %s" % (count, uid))
	
		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))
		
		self.ui.outdent()
	
		return roaming_uids

	def search(self, searchfilter, base="", scope=ldap.SCOPE_SUBTREE, retrieve_attrs=None, limit=0):
		
		result_set = []
		
		if self.conn:
			timeout = 0

			if base == "" and self.namingContexts:
				base = self.namingContexts

			elif base == "*": # directed to search from root
				base = ""

			try:
				result_id = self.conn.search_ext(base, scope, searchfilter, retrieve_attrs, sizelimit=limit)
		
				while 1:
					try:
						result_type, result_data = self.conn.result(result_id, timeout)
						if result_data == []:
							break;
						else:
							if result_type == ldap.RES_SEARCH_ENTRY:
								result_set.append(result_data)
					except ldap.SIZELIMIT_EXCEEDED:
						break
	
			except ldap.LDAPError, e:
				self.ui.print_error(self.str_ldap_error(e))
		
		return result_set


	def search_schema(self, element_type, search_terms):
		
		if type(search_terms) == str:
			search_terms = [search_terms]

		found_elements = []

		str_type = ""

		if element_type == ldap.schema.AttributeType:
			str_type = "attribute(s)"
		elif element_type == ldap.schema.ObjectClass:
			str_type = "objectClass(es)"
		else:
			str_type = "schemaThingie(s)"

		self.ui.print_status("Searching schema for %d different %s" % (len(search_terms), str_type))
		self.ui.indent()

		try:
			if self.subschema == None:
				self.get_schema()
				
				if self.subschema == None:
					self.ui.print_error("Cannot search LDAP schema, probably missing credentials")
					return found_elements

			oids = self.subschema.listall(element_type)

			count = 1
			
			for oid in oids:
								
				attr = self.subschema.get_obj(element_type, oid)
				
				attr_names = ",".join(attr.names)

				for search_term in search_terms:

					# Account for basic meta-char searches
					#found = False

					#if search_term.startswith("*") and 

					if attr_names.lower().find(search_term.lower()) != -1:

						for attr_name in attr_names.split(","):
							found_elements.append(attr_name)

						if self.verbose:
							self.ui.print_ln("%04d: %s" % (count, attr_names))
							count += 1

		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))

		self.ui.outdent()

		return found_elements

	def fingerprint(self, enumerate=False):
		ldap_server = "unknown"
		missing_schema = False

		self.ui.print_status("Attempting to fingerprint LDAP server.")
		self.ui.indent()
				
		if len(self.rootdse) == 0:
			self.get_rootdse()

		try:
			# Attempt to fingerprint the easy way
			attribs = ["", "vendorName"]
			vendor_info = ""

			if self.rootdse.has_key("vendorName"):
				vendor_info = self.rootdse["vendorName"]
				ldap_server = vendor_info.split(" ")[0].lower().strip(",")

				if self.rootdse.has_key("vendorVersion"):
					vendor_info += ", version: " + self.rootdse["vendorVersion"]			

			
			if vendor_info == "":
				self.ui.print_error("Vendor information not published (or otherwise accessible) in the LDAP Server.")

				if self.subschema == None:
					if not self.subschema_tried:
						self.get_schema()
										
					if self.subschema == None:
						missing_schema = True

				if not missing_schema:
					self.ui.print_status("Running Entrust CA tests.")
					results = self.search_schema(ldap.schema.AttributeType, ["entrust"])
				
					if len(results) > 3:
						self.ui.print_status("System appears to support an Entrust Certificate Authority")
						ldap_server = "entrust"
					
						if enumerate:
							print "enum_entrust"#self.enum_dirx()

						return ldap_server

					else:
						self.ui.print_status("Entrust CA tests failed.")


					self.ui.print_status("Running Siemens DirX tests.")
					results = self.search_schema(ldap.schema.AttributeType, ["dirxadministrator","siemens"])
				
					if len(results) > 0:
						self.ui.print_status("System appears to be a Siemens DirX directory")
						ldap_server = "dirx"
					
						if enumerate:
							self.enum_dirx()

						return ldap_server

					else:
						self.ui.print_status("Siemens DirX tests failed.")

					self.ui.print_status("Running Apple Xserver tests.")
					results = self.search_schema(ldap.schema.AttributeType, ["apple-"])
				
					if len(results) > 5:
						self.ui.print_status("System appears to be an Apple Xserve Open Directory")
						ldap_server = "apple"
					
						if enumerate:
							self.enum_apple()
						
						return ldap_server

					else:
						self.ui.print_status("Siemens DirX tests failed.")
						

				else:
					self.ui.print_status("Running Microsoft Active Directory tests.")

					if self.rootdse.has_key("isGlobalCatalogReady"):
						"""
						 self.rootdse.has_key("domainControllerFunctionality") and \
						self.rootdse.has_key("domainFunctionality") and \
						self.rootdse.has_key("forestFunctionality") and \
						self.rootdse.has_key("isGlobalCatalogReady"):
						"""
						self.ui.print_status("System appears to be Microsoft Active Directory")
						ldap_server = "ms"
					
						if enumerate:
							self.enum_ms()

			
						return ldap_server				
			else:
				self.ui.print_status("System appears to be %s" % vendor_info)
		
		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))

		self.ui.outdent()

		return ldap_server

	def enum_ms(self):

		self.ui.print_status("Checking out MS Active Directory info")
		self.ui.indent()
		
		ad_func_levels = {    "domainControllerFunctionality" : {"desc":"DC Functionality", 
									"0":"Windows 2000 Mode", 
									"2":"Windows Server 2003 Mode", 
									"3":"Windows Server 2008 Mode",
									"4":"Windows Server 2008 R2 Mode"},
						"domainFunctionality" : { "desc":"Domain Functionality",
									"0":"Windows 2000 Domain Mode", 
									"1":"Windows Server 2003 Interim Domain Mode", 
									"2":"Windows Server 2003 Domain Mode", 
									"3":"Windows Server 2008 Domain Mode", 
									"4":"Windows Server 2008 R2 Domain Mode"},
						"forestFunctionality" : {"desc":"Forest Functionality",
									"0":"Windows 2000 Forest Mode", 
									"1":"Windows Server 2003 Interim Forest Mode", 
									"2":"Windows Server 2003 Forest Mode", 
									"3":"Windows Server 2008 Forest Mode", 
									"4":"Windows Server 2008 R2 Forest Mode"} }
				
		if len(self.rootdse) == 0:
			self.ui.print_error("RootDSE empty")
			return

		try:
			report = {}
			ms_domain = ""
			if self.rootdse.has_key("rootDomainNamingContext"):
				ms_domain = self.rootdse["rootDomainNamingContext"]
				ms_admin = "CN=Administrator,CN=Users," + ms_domain
				
				ms_domain = ms_domain.replace(",DC=", ".")
				ms_domain = ms_domain.replace("DC=", "")
				
				report["Windows Domain Name"] =  ms_domain
				report["Built-in Admin (guess)"] =  ms_admin

			if self.rootdse.has_key("dnsHostName"):
				report["Server Hostname"] = self.rootdse["dnsHostName"]				
				
			for key in self.rootdse:
				if ad_func_levels.has_key(key):
					int_level = self.rootdse[key]
					report[ ad_func_levels[key]['desc'] ] = ad_func_levels[key][int_level]
					
			column = self.ui.max_len(report.keys()) + 3
			
			for key in sorted(report):
				self.ui.print_ln("%s%s" % ((key + ":").ljust(column), report[key]))
				
		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))

		self.ui.outdent()
		
		return

	def enum_dirx(self):

		self.ui.print_status("Checking out Siemens DirX info")
		self.ui.indent()
		
		if len(self.rootdse) == 0:
			self.ui.print_error("RootDSE empty")
			return

		try:
			self.debug_dump_subschema()
				
		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))

		self.ui.outdent()
		
		return

	def enum_apple(self):
		print "apple: not done yet"
		self.fetch_apple_password_policy()

	def debug_dump_subschema(self):
		
		found_elements = []
		if self.subschema != None:
			schema_elements = [ldap.schema.AttributeType, ldap.schema.ObjectClass, ldap.schema.NameForm]
			
			for element_type in schema_elements:
				oids = self.subschema.listall(element_type)
		
				count = 1
				
				for oid in oids:
									
					attr = self.subschema.get_obj(element_type, oid)
					
					attr_names = ",".join(attr.names)
		
					found_elements.append(attr_names)
					self.ui.print_ln("%04d: %s" % (count, attr_names))
					count += 1
		
		return found_elements
	
	def fetch_apple_password_policy(self):

		self.ui.print_status("Attempting to enumerate Apple password policy")
		self.ui.indent()
		try:
			result_set = self.search("authAuthority=;ApplePasswordServer*", limit=1)
	
			if len(result_set) == 0:
				self.ui.print_error("No results found")
			else:
				
				count = 0
				for i in range(len(result_set)):
					for entry in result_set[i]:
						dn = entry[0]
						name = ""
						if entry[1].has_key("sn"):
							name  = entry[1]["sn"][0]

						uid = ""
						if entry[1].has_key("uid"):
							uid  = entry[1]["uid"][0]
						
						authAuthority = ""
						pw_slot = ""
						pw_server = ""
						if entry[1].has_key("authAuthority"):
							authAuthority  = entry[1]["authAuthority"][0]
							pw_slot = authAuthority.replace(";ApplePasswordServer;", "")
							pw_slot = pw_slot.split(",")[0]

							pw_server = authAuthority.split(":")[-1]

						if name != "" and uid != "" and pw_server != "" and pw_slot  != "":
							result = False
							conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

							try:
								conn.connect((pw_server, self.APPLE_PW_PORT))
								data = conn.recv(1024)
								self.ui.print_status("Banner: '%s'" % data.rstrip())

								self.ui.print_status("Looking up user %s (a.k.a %s). Password slot is %s" % (uid, name, pw_slot))

								conn.send("getpolicy %s\r\n" % pw_slot) #self.APPLE_PW_SLOT)
								data = conn.recv(1024)

								if data != None and data != "":
									data = data.rstrip()

									if data.startswith("+OK"):

										policy = data.split(" ")

										tests_ActiveAdmin = 	["isDisabled=0", "isAdminUser=1"]
										tests_WeakPolicy  = 	["requiresAlpha=0", "requiresNumeric=0", "passwordCannotBeName=0",
													"requiresMixedCase=0", "notGuessablePattern=0", "minChars=0", "usingHistory=0"]
										tests_LockoutPolicy = 	["maxFailedLoginAttempts=0"]

										# Is the account and admin and enabled?
										is_admin = True
										for test in tests_ActiveAdmin:
											if not test in policy:
												is_admin = False
										if is_admin:
											self.ui.print_good("Account is an active admin")
										else:
											self.ui.print_error("Account is not an active admin")

										# Check the password policy of the account
										tests_passed = 0.0
										for test in tests_WeakPolicy:
											if test in policy:
												tests_passed += 1.0

										is_policy_weak = False
										weakPolicy_score = tests_passed / len(tests_WeakPolicy) * 100
										if weakPolicy_score >= 50.0:
											self.ui.print_good("Password policy: %.1lf%% of settings are weak" % weakPolicy_score)
											is_policy_weak = True
										else:
											self.ui.print_error("Password policy: %.1lf%% of settings are weak" % weakPolicy_score)

										is_lockout_disabled = False
										for test in tests_LockoutPolicy:
											if test in policy:
												is_lockout_disabled = True

										if is_lockout_disabled:
											self.ui.print_good("Account lockout is disabled")

										else:
											self.ui.print_error("Account lockout is enabled")

										if is_admin and is_policy_weak and is_lockout_disabled:
											self.ui.print_good("Found admin user with weak password policy and no lockout...game on!")

									else:
										self.ui.print_error("Apple Password Server says: %s" % data)

							except:
								pass		 

						#self.ui.print_ln("%04d: %s(%s)-->asking %s:%s for policy %s" % (count, uid, name, pw_server, self.APPLE_PW_PORT, pw_slot))

		except ldap.LDAPError, e:
			self.ui.print_error(self.str_ldap_error(e))
		
		self.ui.outdent()

	def create_filter_or(self, attribs):
		searchfilter = ""
		for attrib in attribs:
			searchfilter += "(" + attrib + "=*)"
			
		return "(|%s)" % searchfilter

	def str_ldap_error(self, e):
		
		err = None
		err_msg = ""
		
		try:
			err = e[0]
		except:
			pass
		
		if type(err) == dict:
			if err.has_key("info"):
				err_msg += err["info"] + " - "
			if err.has_key("desc"):
				err_msg += err["desc"]
		else:
			err_msg = "Error - " + str(e)
			
		return err_msg


	def test(self):	
		#self.discover("10.0.52.0/24")
		
		if not self.connect():
			sys.exit(1)

		self.get_rootdse()
		#self.search_admin()
		#self.search_password()
		"""
		server_type = self.fingerprint(enumerate=True)
		if server_type == "unknown":
			self.debug_dump_subschema()
		"""
		# Novell discovery
		#print self.search("entrustCA=*")
		#print self.search("cn=lrcadmin*)
		#for person in self.search("objectClass=inetOrgPerson", limit=10):
		#for person in self.search("objectClass=ndsContainerLoginProperties", limit=25):
		"""
		for person in self.search("o=*loginGraceLimit", limit=25):

			print "\n"
			print person
		"""
		#print self.search_schema(ldap.schema.AttributeType, ["password","passwd","pwd"])
#		self.get_schema()

		#self.namingContexts = "cn=TSXIMAGE,ou=tpghost,o=imaging"
#		self.dump_email(15)
#		self.search_admin()
		
#		pwhashes = self.search_password()
		#if pwhashes:
		#	self.crack_passwords(pwhashes, "/root/ldap/pwlist.txt")

		self.fetch_apple_password_policy()
		#self.search_schema(ldap.schema.AttributeType, "entrust")
		#self.search_schema(ldap.schema.AttributeType, "uid")

		self.dump_entrust_roaming_uids('dn')
		self.disconnect()
	
	def app_title(self):
		self.ui.print_title("DAPPER")
		self.ui.print_title("An LDAP enumeration/attack tool")
		self.ui.print_ln()
		
		self.ui.print_subtitle("By:   ", "3rd Degree             ")
		self.ui.print_subtitle("Home: ", "http://virusfactory.net")
		self.ui.print_ln()

	def usage(self, appname="dapper.py"):
		self.app_title()

		self.ui.print_caption(random_pick(self.phrase_list))
		self.ui.print_ln()
		self.ui.print_ln("Usage: %s <options>" % appname)
		self.ui.print_ln("Options:")
		self.ui.print_ln("   -h, --help                   Show this help message and exit.")
		self.ui.print_ln("   -w, --wizard                 Use the interactive wizard.")
		self.ui.print_ln("   -u, --url      <url>         LDAP url to target for enumeration/attack.")
		self.ui.print_ln("                                e.g. ldap://[user:pass@]server.example.com[:port]")
		self.ui.print_ln("   -f, --fingerprint            Fingerprint the LDAP server.")
		self.ui.print_ln("   -m, --email                  Dump email addresses.")
		self.ui.print_ln("   -o, --output                 Path to output log file.")
		self.ui.print_ln("   -l, --limit    <n>           Limit the number of results to n.")
		self.ui.print_ln("   -v, --verbose                Show detailed information.")


		#
			
def start_wizard(dapper):
	dapper.app_title()

	options = {	1  : "Discover LDAP servers",
			2  : "Change target LDAP server",
			3  : "Profile",
			4  : "Search",
			5  : "Attack",
			6  : "Logging",
			99 : "Exit"}

	choice = 0
	while choice != 99:
		prompt = "main"

		dapper.ui.print_ln("Choose an option below:")
		choice = dapper.ui.show_menu(options, prompt)


		dapper.ui.print_ln()

		if choice == 1:
			dapper.ui.print_ln("Specify targets (E.g. scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254):")
			targets = raw_input()

			if targets != "" and not (targets.find("&") > 0 or targets.find(";") > 0):
				dapper.discover(targets)


		elif choice == 2:
			url = dapper.ldapurl
			if url == "":
				url = "[blank]"

			dapper.ui.print_ln("The current target is %s" % dapper.ui.bold(url))
			dapper.ui.print_ln("Enter the LDAP url of the new target (blank line = don't change):")
			newurl = raw_input()

			if newurl != "":
				dapper.ldapurl = newurl


		elif choice == 3:
			dapper.ui.print_ln("Profiling LDAP server")
			if dapper.connect():
				dapper.get_rootdse()

				server_type = dapper.fingerprint(enumerate=True)

				if server_type == "unknown":
					dapper.debug_dump_subschema()


		elif choice == 4:
			dapper.ui.print_ln("Searching LDAP server")
			prompt = "search"
			opts_search = {	1  : "Search for admin users",
					2  : "Search for email addresses",
					3  : "Search directory",
					4  : "Search directory schema",
					99 : "Back"}

			choice_search = 0
			while choice_search != 99:
				choice_search = dapper.ui.show_menu(opts_search, prompt)

				dapper.ui.print_ln()
#	self.dump_email(15)
#		
				if choice_search == 1:
					dapper.search_admin()
					dapper.ui.print_ln()

############## WORKING HERE
				elif choice_search == 2:
					dapper.ui.print_ln("Profiling LDAP server")
					if dapper.connect():
						dapper.get_rootdse()

						server_type = self.fingerprint(enumerate=True)

						if server_type == "unknown":
							self.debug_dump_subschema()

			

		elif choice == 4:
			print "profile"
		elif choice == 5:
			print "profile"
		elif choice != 99:
			dapper.ui.print_error("Invalid selection.")

		dapper.ui.print_ln()

	dapper.disconnect()
	dapper.ui.print_caption("Thank you. Please come again.") 
	dapper.ui.print_ln()

# change target
#	enter url
# enumerate
# 	fingerprint
#	password policy
# search
#	emails
#	admins
#	other
# attack
#	offline pw
#	online pw
# logging
#	log level
#	log file
# export ldif
# debug


if __name__ == "__main__":

	dapper = Dapper()
		
	# Check dependencies
	if missing_ldap:
		dapper.usage()
		dapper.ui.print_ln()
		dapper.ui.print_error("Missing python-ldap package.\n    "\
			"Download and install from http://pypi.python.org/pypi/python-ldap/")
		sys.exit(1)


	# Get options
	wizard_mode = False
	verbose = False
	testing_mode = False
	fingerprint_mode = False
	email_mode = False

	try:
		options, args = getopt.getopt(sys.argv[1:], 'htwu:fmo:l:v',
			['help',
			'wizard'
			'test',
			'url=',
			'fingerprint',
			'email',
			'output=',
			'limit=',
			'verbose'
			])
	except getopt.GetoptError:
		dapper.ui.print_error("Wrong Option Provided!")
		dapper.ui.print_ln()
		dapper.usage()
		sys.exit(1)

	except:
		dapper.usage()
		sys.exit(1)


	for opt, arg in options:
		if opt in ('-w','--wizard'):
			wizard_mode = True
		elif opt in ("-t", "test"):
			testing_mode = True
		elif opt in ('-f','--fingerprint'):
			fingerprint_mode = True
		elif opt in ('-v','--verbose'):
			dapper.verbose = True
		elif opt in ('-m','--email'):
			email_mode = True
		elif opt in ('-l','--limit'):
			dapper.limit = int(arg)
		elif opt in ('-u','--url'):
			dapper.ldapurl = arg
		elif opt in ('-o','--output'):
			dapper.ui.open_log(arg)

	# Check for required options and connectivity
	if dapper.ldapurl == "" and not (testing_mode or wizard_mode):
		dapper.ui.print_error("No LDAP url specified!")
		dapper.ui.print_ln()
		dapper.usage()
		sys.exit(1)

	elif not dapper.connect():
		sys.exit(1)

	
	if fingerprint_mode:

		log = open("fingerprints.txt", "a")
		result = dapper.fingerprint()
		log.write("%s\t%s\n" % (dapper.ldapurl, result))

	if email_mode:
		dapper.dump_email()

	elif wizard_mode:
		start_wizard(dapper)
	
	elif testing_mode:
		dapper.test()
