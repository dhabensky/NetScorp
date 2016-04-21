#!/usr/bin/python2.7

__author__ = 'admin'

import getopt
import sys
import os


def get_content(filename):
	try:
		f = open(filename, "r")
		c = f.read()
		f.close()
		return c
	except OSError, ex:
		print ex
	pass
pass


def parse_in(filename):
	try:
		data = get_content(filename)
	except Exception, ex:
		print ex
		print "cannot read input file"
		exit(-1)
	pass

	try:
		lines = data.split("\n")
		vars = {}
		i = 0
		for line in lines:
			if line.strip().startswith("#") or line.strip() == "":
				i += 1
				continue
			parts = line.split(":", 1)
			key = parts[0]
			val = parts[1]
			vars[key.strip()] = val.strip()
			i += 1
		pass
		return vars
	except Exception, ex:
		print "cannot parse input file: error on line " + str(i)
		print ex
		exit(-1)
	pass
pass


def start_qemu(cmdqemu):
	temp_file = os.path.expanduser("~/.NetScorp/temp.sh")
	#cmdqemu = "qemu-system-i386 /home/dhabensky/Desktop/openwrt-x86-generic-combined-ext4.img -s"
	os.system("mkdir " + temp_file[:temp_file.rindex("/")] + " 2>/dev/null")
	os.system("echo " + cmdqemu + " >" + temp_file)
	os.system("chmod 777 " + temp_file)
	os.system(temp_file + " &")
	# try:
	# 	#cmdqemu = "exec qemu-system-i386 /home/dhabensky/Desktop/openwrt-x86-generic-combined-ext4.img -s"
	# 	os.system("x-terminal-emulator -e 'bash -c qemu-system-i386 /home/dhabensky/Desktop/openwrt-x86-generic-combined-ext4.img -s'")
	# 	print shlex.split(cmdqemu)
	# 	#subprocess.Popen(shlex.split(cmdqemu))
	# except Exception, ex:
	# 	print ex
	# 	print shlex.split(cmdqemu)
	# pass
pass


def start_gdb(gdbpath, addr, endian, offset, pid_offset):
	toexec = gdbpath
	toexec += " -ex 'source ~/PycharmProjects/cp/internal/loader.py'"
	toexec += " -ex 'python try_connect(" + str(port) + ")'"
	toexec += " -ex 'python load_all()'"
	if endian:
		toexec += " -ex 'set endian " + endian + "'"
	toexec += " -ex 'python name_offset=" + str(offset) + "'"
	if pid_offset:
		toexec += " -ex 'python pid_offset=" + str(pid_offset) + "'"
	if save_path:
		toexec += " -ex 'python save_path=\"" + str(save_path) + "\"'"
	toexec += " -ex 'python BreakpointHandler(\"*" + addr + "\")'"
	toexec += " --silent"
	os.system(toexec)
pass











def usage():
	print
	print "USAGE:"
	print "  -h                           - prints this message"
	print "  [-o output_dir] task_file    - run task from 'task_file' and set output directory to 'output_dir'"
	print
pass





try:
	opts, args = getopt.getopt(sys.argv[1:], "ho:")
except getopt.GetoptError as err:
	print "    " + str(err)
	usage()
	sys.exit(2)
pass



if len(sys.argv) == 1:
	usage()
	sys.exit()

save_path = None

for o, a in opts:

	if o in ("-h", "--help"):
		usage()
		sys.exit()

	elif o == "-o":
		#print "saving to " + a
		save_path = a
pass




try:

	if len(args) >= 1:
		vars = parse_in(args[0])
	else:
		print "no file specified"
		exit(-1)
	pass

	#print vars
	qemu = vars.get("qemu", None)
	gdb_path = vars.get("gdb_path", "gdb")
	port = vars.get("port", 1234)
	addr = vars.get("syscall_handler", None)
	offset = vars.get("name_offset", None)
	pid_offset = vars.get("pid_offset", None)
	endian = vars.get("endian")


	if not gdb_path:
		print "'gdb_path' not specified"
		exit(-1)

	try:
		try:
			port = int(port, 10)
		except:
			port = int(port, 16)
		pass
	except Exception, ex:
		print "incorrect value for 'port':"
		print ex
		exit(-1)

	if not addr:
		print "'syscall_handler' not specified"
		exit(-1)
	try:
		addr = int(addr, 16)
		addr = hex(addr)
	except Exception, ex:
		print "incorrect value for 'syscall_handler':"
		print ex
		exit(-1)

	if not offset:
		print "'name_offset' not specified"
		exit(-1)
	try:
		try:
			offset = int(offset, 10)
		except:
			offset = int(offset, 16)
		pass
	except Exception, ex:
		print "incorrect value for 'name_offset':"
		print ex
		exit(-1)

	if pid_offset:
		try:
			try:
				pid_offset = int(pid_offset, 10)
			except:
				pid_offset = int(pid_offset, 16)
			pass
		except Exception, ex:
			print "incorrect value for 'pid_offset':"
			print ex
			exit(-1)

	if endian:
		endian = endian.lower()
		if endian != "big" and endian != "little":
			print "incorrect value for 'endian': only 'big' and 'little' are valid"
			exit(-1)

	temp_file = os.path.expanduser("~/.NetScorp/temp.sh")


	if qemu:
		#start_qemu(qemu)
		print "'qemu': this feature is not supported yet. Please, launch qemu manually"
		exit(-1)

	start_gdb(gdb_path, addr, endian, offset, pid_offset)


except OSError, ex:
	print ex
pass
