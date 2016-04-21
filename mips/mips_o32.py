
#
# ??????
# Although the MIPS processor supports either big endian or
# little endian byte ordering, an ABI-conforming system must support 
# big endian byte ordering.
# http://web.archive.org/web/20040930224745/http://www.caldera.com/developers/devspecs/mipsabi.pdf
#
# @useful sfuff
#   set mips abi
#   set endian little
#


class Mips_o32:

	name = "mips-o32"

	catch_syscalls = ["socket", "socketpair", "bind", "listen", "accept", "connect", "sendto", "send", "recvfrom", "recv", "shutdown", "sendmsg", "recvmsg", "socketcall"]

	handle_syscalls = {}

	reg_names = ["v0", "a0", "a1", "a2", "a3"]
	
	syscall_map = {}
	
	syscall_args = {'getsockopt': 5, 'setsockopt': 5, 'shutdown': 2, 'socket': 3, 'bind': 3, 'send': 4, 'accept': 3, 'recvfrom': 6, 'recvmsg': 3, 'connect': 3, 'getsockname': 3, 'sendto': 6, 'getpeername': 3, 'recv': 6, 'socketpair': 4, 'sendmsg': 3, 'listen': 2}
	
	# not used
	break_addr = "0x80000180"


	def __init__(self):
		Mips_o32.handle_syscalls = {
			"socket" : self.handle_socket,
			"socketpair": self.handle_socketpair,
			"bind": self.handle_bind,
			"connect": self.handle_connect,
			"listen": self.handle_listen,
			"accept": self.handle_accept
		}
		self.record = {}
		print "I AM MIPS"
	pass


	def parse_syscall(self):
	
		regs = self.get_registers()
		number = int(regs["v0"], 16)
		name = self.syscall_map.get(str(number), "undefined " + str(number))

		#ti_addr = self.get_thread_info_addr()
		#ts_addr = self.get_task_struct_addr(ti_addr)
		#print "pid: ", self.get_pid(ts_addr)

		return name, number, regs
	pass



	def handle_syscall(self, name, regs):

		args = map(lambda r: self.parse_int(regs[r]), Mips_o32.reg_names[1:])  # first 3 args
		args += self.get_last4args()           # following 4 args
		args = args[:Mips_o32.syscall_args[name]]

		print "  -> " + name.upper()
		print "      " + str(args)

		try:
			pid, exe = "nopid", "noexe" #self.get_pid_and_exe()
			self.record = { "pid": pid, "exe": exe, "syscall": name }

			handler = Mips_o32.handle_syscalls[name]
			handler(args)

			logbuf.add(self.record)

			return True
		except KeyError, ex:
			#print "    " + name.upper() + ": no handler"
			return False
		pass

	pass





	def handle_socket(self, args):
		sockdomain = self.parse_int(args[0])
		socktype = self.parse_int(args[1])
		sockprotocol = self.parse_int(args[2])

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
		pass
	pass

	def handle_socketpair(self, args):
		return self.handle_socket(args)
	pass

	def handle_bind(self, args):
		domain, port, addr, raw_bytes = self.parse_sockaddr(args[1], args[2])

		print "handle_bind"
		params = {
			"domain_num" : domain,
			"domain_decoded" : domains.get(domain, None),
			"raw_bytes" : str(raw_bytes)
		}

		if domain == SocketDomain.AF_INET:
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
		sockfd = self.parse_int(args[0])
		backlog = self.parse_int(args[1])
		print "    listen ", sockfd
	pass

	def handle_accept(self, args):
		pass
	pass



	def parse_sockaddr(self, addr, addrlen):
		bytes = self.to_bytes(self.exam_memory(addr, addrlen))
		if self.parse_int(addr) == 0:
			return 0, 0, "", bytes
		domain = bytes[1] * 256 + bytes[0]  # assuming little endian
		if domain == SocketDomain.AF_INET:
			port = bytes[2] * 256 + bytes[3]    # endian is not important. maybe...
			addr = ".".join(map(lambda i: str(i), bytes[4:8]))
		elif domain == SocketDomain.AF_INET6:
			port = bytes[2] * 256 + bytes[3]    # endian is not important. maybe...
			addr = ".".join(map(lambda i: str(i), bytes[4:8]))                 # !!! copypaste
		else:
			port = ""
			addr = ""
		pass
		return domain, port, addr, bytes
	pass


	def exam_memory(self, addr, length):
		if type(length) is str:
			length = self.parse_int(length)
		if type(addr) is int:
			addr = hex(addr)
		info = gdb.execute("x/" + str(length / 4) + "xw " + addr, to_string = True).strip()
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
		print "esp: ", hex(esp)
		bottom = esp & (-1 << 13)
		print "btm: ", hex(bottom)

		res = [esp & (-1 << 14), bottom, esp & (-1 << 12), esp & (-1 << 11)]


		print map(lambda i: hex(i), res)
		for guess in res:
			try:
				ti_addr = self.get_val(guess)
				print guess, " -> ", ti_addr
				#gdb.execute("x/2 " + hex(ti_addr))
			except:
				print guess, " -> ", "#error"
				pass
		return self.get_val(hex(bottom))
	pass

	def get_task_struct_addr(self, thread_info_addr):
		print "tia: ", thread_info_addr
		if type(thread_info_addr) is str:
			thread_info_addr = int(thread_info_addr, 16)
		return thread_info_addr  # offset is 0, lucky!
	pass

	def get_pid(self, task_struct_addr):
		print "tsa: ", task_struct_addr
		print self.exam_memory(task_struct_addr, "100")
		if type(task_struct_addr) is str:
			task_struct_addr = int(task_struct_addr, 16)
		pid_offset = 50 * 4  # for test kernel, but may vary
		return self.get_val(task_struct_addr + pid_offset)
	pass

	def get_exe(self, task_struct_addr):
		if type(task_struct_addr) is int:
			task_struct_addr = hex(task_struct_addr)
		info = self.to_bytes(self.exam_memory(task_struct_addr, "200"))
		info = map(lambda b: chr(b), info)
		info = info[416:]
		end = info.index('\x00')
		info = info[:end]
		return "".join(info)
	pass



	def get_esp(self):
		return int(gdb.execute("print $sp", to_string = True).strip().split(" ")[-1], 10)
	pass

	def parse_int(self, val):
		if type(val) is int:
			return val
		try:
			if val.startswith("0x"):
				return int(val, 16)
			else:
				return int(val, 10)
		except ValueError, ex:
			raise ValueError("failed parsing " + str(val))
	pass

	def get_val(self, addr):
		return self.parse_int(self.get_val_str(addr))
	pass

	def get_val_str(self, addr):
		if type(addr) is int:
			addr = hex(addr)
		return gdb.execute("x/ " + addr, to_string = True).strip().split("\t")[-1]
	pass


	
	
	def get_last4args(self):
		t0 = gdb.parse_and_eval("$sp + 29") # user stack pointer
		
		arg = []
		for i in xrange(4):
			arg.append(gdb.execute("x/1xw " + str(t0 + 16 + 4 * i), to_string = True))
		arg = map(lambda s: self.parse_int(s.split(":")[1].strip()), arg)
		return arg
	pass
	
	
	def get_registers(self):
		info = gdb.execute("info registers", False, True)
		keys = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3', 't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7', 's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra', 'sr', 'lo', 'hi', 'bad', 'cause', 'pc', 'fsr', 'fir']
		values = filter(lambda s : len(s) == 8,	info.replace("\n", "").split(" "))
		values = map(lambda s: "0x" + s, values)
		return dict(zip(keys, values))
	pass
	
pass