#from common import *
import operator
#from log import *
#import gdb

class I386:

	name = "i386"

	catch_syscalls = ["socketcall"]
	
	handle_syscalls = {}
	
	socketcalls = ["0", "socket", "bind", "connect", "listen", "accept", "getsockname",
				   "getpeername", "socketpair", "send", "sendto", "recv", "recvfrom", "shutdown",
				   "getsockopt", "setsockopt", "sendmsg", "recvmsg"]
	
	lengths = [0, 3, 3, 3, 2, 3, 3, 3, 4, 4, 6, 4, 6, 2, 5, 5, 3, 3]
	
	syscall_map = {}
	
	# not used
	break_addr = "0xc137db60"
	
	
	def __init__(self):
		I386.handle_syscalls = {
			"socket" : self.handle_socket,
			"socketpair": self.handle_socketpair,
			"bind": self.handle_bind,
			"connect": self.handle_connect,
			"listen": self.handle_listen,
			"accept": self.handle_accept
		}
		self.record = {}
	pass
	
	def parse_syscall(self):
		regs = self.get_registers()
		number = int(regs["eax"], 16)
		name = self.syscall_map.get(str(number), "undefined")
		
		if name == "socketcall":
			return name, number, self.parse_socketcall(regs)
		return name, number, regs
	pass
	
	def parse_socketcall(self, regs):
		call = int(regs["ebx"], 16)
		length = I386.lengths[call]
		pargs = regs["ecx"]
		info = gdb.execute("x/" + str(length) + "xw " + pargs, False, True).strip()
		args = reduce(operator.add,	map(lambda s: s.split("\t")[1:], info.split("\n")))
		return [I386.socketcalls[call]] + args
	pass
	
	def handle_syscall(self, name, args):
		if name != "socketcall":
			return

		name = args[0]
		args = args[1:]

		try:
			pid, exe = self.get_pid_and_exe()
			self.record = { "pid": pid, "exe": exe, "syscall": name }

			try:
				handler = I386.handle_syscalls[name]
				handler(args)
				print "  -> " + name.upper() + " [" + exe + "]"
			except gdb.MemoryError, ex:
				pass#print "MEM_ERROR: " + str(ex)
			pass
			
			logbuf.add(self.record)
		
			return True
		except KeyError, ex:
			#print "    " + name.upper() + ": no handler"
			return False
		pass
	pass


	
	def handle_socket(self, args):
		sockdomain = int(args[0], 16)
		socktype = int(args[1], 16)
		sockprotocol = int(args[2], 16)
		
		sdomain = domains.get(sockdomain, str(sockdomain))
		stype = types.get(socktype, str(socktype))
		sprotocol = protocols.get(sockprotocol, str(sockprotocol))
		if stype in ['tcp', 'udp']:
			sprotocol = ''
		
		params = {
			"domain_num" : sockdomain,
			"domain_decoded" : domains.get(sockdomain, None),
			"type_num" : socktype,
			"type_decoded" : types.get(socktype, None),
			"protocol_num" : sockprotocol,
			"protocol_decoded" : protocols.get(sockprotocol, None)
		}
		self.record["params"] = params
		self.record["comment"] = "socket " + " ".join([sdomain, stype, sprotocol])
		print "    socket " + sdomain + " " + stype + " " + sprotocol
	pass

	def handle_connect(self, args):
		domain, port, addr, raw_bytes = self.parse_sockaddr(args[1], args[2])
		
		params = {
			"domain_num" : domain,
			"domain_decoded" : domains.get(domain, None),
			"raw_bytes" : str(raw_bytes)
		}
		
		if domain == SocketDomain.AF_INET:
			params["addr"] = addr
			params["port"] = port
			print "    connect " + addr + ":" + str(port)
			self.record["comment"] = "connect " + addr + ":" + str(port)
		else:
			print "    connect { domain: " + str(domain) + " }"
		pass
	
		self.record["params"] = params
	pass
	
	def handle_socketpair(self, args):
		return self.handle_socket(args)
	pass
	
	def handle_bind(self, args):
		domain, port, addr, raw_bytes = self.parse_sockaddr(args[1], args[2])

		params = {
			"domain_num" : domain,
			"domain_decoded" : domains.get(domain, None),
			"raw_bytes" : str(raw_bytes)
		}

		bind_data = {
			"addr" : addr,
			"port" : port,
			"raw_bytes" : raw_bytes,
			"domain" : domain
		}
		logbuf.bind(int(args[0], 16), bind_data)

		if domain in [SocketDomain.AF_INET, SocketDomain.AF_INET6]:
			bind_data["domain_decoded"] = domains.get(domain, str(domain))
			params["addr"] = addr
			params["port"] = port
			print "    bind " + addr + ":" + str(port)
			self.record["comment"] = "bind " + addr + ":" + str(port)
		else:
			print "    bind { domain: " + str(domain) + " }"
		pass

		self.record["params"] = params
	pass

	def handle_listen(self, args):
		sockfd = int(args[0], 16)
		backlog = int(args[1], 16)
		data = logbuf.binded.get(sockfd, None)

		params = {
			"sockfd" : sockfd,
			"backlog" : backlog
		}

		if not data is None:
			self.record["domain"] = data["domain"]
			if data["domain"] in [SocketDomain.AF_INET, SocketDomain.AF_INET6]:
				self.record["addr"] = data["addr"]
				self.record["port"] = data["port"]
				print "    listen socket ", sockfd, " ",  data["addr"], ":", data["port"]
				self.record["comment"] = "listen socket " + str(sockfd) + " domain " + str(data["domain"]) + " " + data["addr"] + ":" + str(data["port"])
			else:
				print "    listen socket ", sockfd, " domain ", data["domain"]
				self.record["comment"] = "listen socket " + str(sockfd) + " domain " + str(data["domain"])
		else:
			print "    listen socket ", sockfd, " (no bind data)"
			self.record["comment"] = "listen socket " + str(sockfd) + " (no bind data)"

		params["bind_data"] = data
		self.record["params"] = params
	pass

	def handle_accept(self, args):

		#print "  accept ", args
		domain, port, addr, raw_bytes = self.parse_sockaddr(args[1], args[2])

		params = {
			"domain_num" : domain,
			"domain_decoded" : domains.get(domain, None),
			"raw_bytes" : str(raw_bytes)
		}

		if domain in [SocketDomain.AF_INET, SocketDomain.AF_INET6]:
			params["addr"] = addr
			params["port"] = port
			print "    accept " + addr + ":" + str(port)
			self.record["comment"] = "accept " + addr + ":" + str(port)
		else:
			print "    accept { socket: " + str(int(args[0], 16)) + " }"
		pass

		self.record["params"] = params
	pass



	def parse_sockaddr(self, addr, addrlen):
		bytes = self.to_bytes(self.exam_memory(addr, addrlen))
		if int(addr, 16) == 0:
			return 0, 0, "", bytes
		domain = bytes[1] * 256 + bytes[0]  # assuming little endian
		if domain == SocketDomain.AF_INET:
			port = bytes[2] * 256 + bytes[3]    # endian is not important. maybe...
			addr = ".".join(map(lambda i: str(i), bytes[4:8]))
		elif domain == SocketDomain.AF_INET6:
			port = bytes[2] * 256 + bytes[3]    # endian is not important. maybe...
			b = bytes[8:24]

			def byte_to_hex(_2bytes):
				return ("0000" + hex(_2bytes[0] * 256 + _2bytes[1])[2:])[-4:]
			pass

			splited = [
				b[0:2],
				b[2:4],
				b[4:6],
				b[6:8],
				b[8:10],
				b[10:12],
				b[12:14],
				b[14:16]
			]

			addr = "[" + ":".join(map(lambda i: str(byte_to_hex(i)), splited)) + "]"
		else:
			port = ""
			addr = ""
		pass
		return domain, port, addr, bytes
	pass



	def exam_memory(self, addr, length):
		#print "x/" + str(int(length, 16) / 4) + "xw " + str(addr)
		info = gdb.execute("x/" + str(int(length, 16) / 4) + "xw " + str(addr), False, True).strip()
		info = info.split('\n')
		info = reduce(operator.add, map(lambda s: s.split('\t')[1:], info))
		return info
	pass

	#returns array of two-character strings that represent bytes in hex notation without 0x prefix
	def to_bytes(self, wordlist):
		bytes = []
		for word in wordlist:
			try:
				x = word[2:]
				bbytes = [x[:2], x[2:4], x[4:6], x[6:]]

				# little endian crap
				bbytes.reverse()

				bytes += bbytes
			except Exception, ex:
				print "word " +  word + " sucked"
			
		bytes = map(lambda s: int('0x' + s, 16), bytes)
		return bytes
	pass


	def get_thread_info_addr(self):
		esp = self.get_esp()
		bottom = esp & (-1 << 13)
		return self.get_val(hex(bottom))
	pass

	def get_task_struct_addr(self, thread_info_addr):
		if type(thread_info_addr) is str:
			thread_info_addr = int(thread_info_addr, 16)
		return thread_info_addr  # offset is 0, lucky!
	pass

	def get_pid(self, task_struct_addr):
		if type(task_struct_addr) is str:
			task_struct_addr = int(task_struct_addr, 16)
		global pid_offset
		if pid_offset:# = 50 * 4  # for test kernel, but may vary
			try:
				return self.get_val(task_struct_addr + pid_offset)
			except:
				return 0
			pass
		else:
			return 0
	pass

	def get_exe(self, task_struct_addr):
		if type(task_struct_addr) is int:
			task_struct_addr = hex(task_struct_addr)
		try:
			info = self.to_bytes(self.exam_memory(task_struct_addr, "200"))
			info = map(lambda b: chr(b), info)
			global name_offset
			info = info[name_offset:]
			end = info.index('\x00')
			info = info[:end]
			info = "".join(info)
			#print info, "<<<<<<<<<<<<<"
			info = info.encode('utf8')
			return info
		except Exception, ex:
			print "failed getting process name"
			return "<error>"
		pass
	pass

	def get_pid_and_exe(self):
		thread_info_addr = self.get_thread_info_addr()
		task_struct_addr = self.get_task_struct_addr(thread_info_addr)
		
		pid = self.get_pid(task_struct_addr)
		exe = self.get_exe(task_struct_addr)
		
		return pid, exe
	pass


	def get_registers(self):
		info = gdb.execute("info registers", False, True)
		ss = info.split("\n")
		regs = {}
		for s in ss[:-1]:
			parts = s.split(" ", 1)
			reg = parts[0]
			value = parts[1].strip().split("\t")[0]
			regs[reg] = value
		return regs
	pass

	def get_esp(self):	
		return int(gdb.execute("print $esp", to_string = True).strip().split(" ")[-1], 16)
	pass

	def get_val(self, addr):
		return int(self.get_val_str(addr), 16)
	pass

	def get_val_str(self, addr):
		if type(addr) is int:
			addr = hex(addr)
		return gdb.execute("x/ " + addr, to_string = True).strip().split("\t")[-1]
	pass


pass
