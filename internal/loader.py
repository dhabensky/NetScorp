import gdb

verbose = True
nonstop = False
save_path = "./"
name_offset = 0
#pid_offset = 0

def get_arch():
	info = gdb.execute("show arch", False, True)
	if info.find("i386") != -1:
		return I386()
	elif info.find("mips") != -1:
		return Mips_o32()
	pass
pass


def try_connect(port):
	print
	print "connecting to port " + str(port) + '...'
	try:
		gdb.execute("target remote :" + str(port))
		print "SUCCESS"
		print
	except Exception, ex:
		print "FAIL: " + str(ex)
		print
		exit(1)
		return False
	pass
	return True
pass

def load_all():
	pref = "~/PycharmProjects/cp/"

	gdb.execute("source " + pref + "internal/log.py")
	gdb.execute("source " + pref + "internal/common.py")

	gdb.execute("source " + pref + "i386/i386.py")
	gdb.execute("source " + pref + "mips/mips_o32.py")

	gdb.execute("source " + pref + "internal/breakpoint_handler.py")

	gdb.execute("d")
	#gdb.execute("python BreakpointHandler(\"*" + get_arch().break_addr + "\")")
	gdb.execute("set pagination off")
pass

