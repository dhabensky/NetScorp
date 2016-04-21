#from i386 import I386
#from mips_o32 import Mips_o32


class BreakpointHandler(gdb.Breakpoint):

	arch = None

	
	def __init__(self, spec):
		super(BreakpointHandler, self).__init__(spec)
				
		# fetching arch
		info = gdb.execute("show arch", False, True)
		if info.find("i386") != -1:
			self.arch = I386()
		elif info.find("mips") != -1:
			self.arch = Mips_o32()
		pass

		# fetching syscalls
		f = open("/usr/share/gdb/syscalls/" + self.arch.name + "-linux.xml")
		ss = f.read().split("\n")
		f.close()
		ss = ss[ss.index("<syscalls_info>") + 1: -2]
		ss = map(lambda s: [s.split("\"")[3], s.split("\"")[1]], ss)
		self.arch.syscall_map = dict(ss)

		#print self.arch.catch_syscalls
	pass
	
	
	def stop(self):
		name, number, args = self.arch.parse_syscall()

		if verbose:
			print name

		if not name in self.arch.catch_syscalls:
			return False

		return self.arch.handle_syscall(name, args) and not nonstop
	pass
	
pass

