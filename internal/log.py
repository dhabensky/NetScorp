import json
import os
from datetime import datetime

class Log:
	
	instance = None
	
	@staticmethod
	def get_instance():
		if Log.instance is None:
			Log.instance = Log()
		return Log.instance
	pass

	
	def __init__(self):
		if not Log.instance is None:
			raise Exception("log is already open")
		self.file = open("log.txt", "w+")
	pass


	def write(self, data_str):
		self.__check_is_open()
		self.file.write(data_str)
	pass


	def flush(self):
		self.__check_is_open()
		self.file.flush()
	pass


	def __check_is_open(self):
		if Log.instance is None:
			raise Exception("log is not open")
	pass
		
	def close(self):
		self.file.close()
		Log.instance = None
	pass
	
pass

#log = Log.get_instance()


class LogBuffer:

	instance = None
	
	@staticmethod
	def get_instance():
		if LogBuffer.instance is None:
			LogBuffer.instance = LogBuffer()
		return LogBuffer.instance
	pass

	def __init__(self):
		self.data = []
		self.first_time = None
		self.last_time = None
		self.date = str(datetime.now().date())
		self.binded = {}
	pass

	def add(self, obj):
		time = str(datetime.now().time())
		ttime = datetime.now().time().strftime("%H:%M:%S")
		
		if len(self.data) == 0:
			self.first_time = ttime
		self.last_time = ttime
		
		obj = { "record": obj } if type(obj) is not dict else obj		
		obj["time"] = time
		self.data.append(obj)
	pass

	def dump(self):

		fname = save_path

		# if len(self.data) == 0:
		# 	fname = self.date + "_" + datetime.now().time().strftime("%H:%M:%S") + "_empty"
		# else:
		# 	fname = self.date + "_" + self.first_time + "_" + self.last_time

		#fname = "~/SockDetect/" + fname
		fname = os.path.expanduser(fname)
		try:
			os.makedirs(fname, 0777)
		except OSError, ex:
			pass
		pass

		try:
			#if len(self.data) != 0:
			file_all = open(fname + "/" + "all.json", "w+")
			file_all.write(json.dumps(self.data, indent=4))
			file_all.close()

			connects = self.filter_connects(self.data)
			file_con = open(fname + "/" + "connect.json", "w+")
			file_con.write(json.dumps(connects, indent=4))
			file_con.close()

			listens = self.filter_listens(self.data)
			file_lis = open(fname + "/" + "listen.json", "w+")
			file_lis.write(json.dumps(listens, indent=4))
			file_lis.close()
			#pass

			print "save completed. Check files in " + str(os.path.abspath(fname))
		except Exception, ex:
			print "save failed:"
			print ex
		pass
	pass

	def clear(self):
		self.data = []
	pass

	def bind(self, sockfd, sockaddr):#addr, port, raw_bytes):
		self.binded[sockfd] = sockaddr
	pass


	def filter_connects(self, data):
		names = {}
		for d in data:
			if d["syscall"] == "connect":
				try:
					if d["params"]["domain_num"] in [SocketDomain.AF_INET, SocketDomain.AF_INET6]:
						name = d["exe"]
						record = names.get(name, None)
						if record:
							found = False
							for rec in record:
								params = rec[0]["params"]
								if params["domain_num"] in [SocketDomain.AF_INET, SocketDomain.AF_INET6]:
									if params["domain_num"] == d["params"]["domain_num"] and params["port"] == d[
										"params"]["port"] and params["addr"] == d["params"]["addr"]:
										rec[1] += 1
										found = True
										#print "inc"
										break
									pass
								pass
							pass

							if not found:
								record.append([d, 1])
							#print "app"
						else:
							names[name] = [[d, 1]]
							#print "new"
						pass
					pass
				except: # skips connect without params got because of gdb.MemoryError
					pass
				pass
			pass
		pass

		res = []

		for name, record in names.iteritems():
			for rec in record:
				res.append([
					name,
					rec[0]["params"]["addr"] + ":" + str(rec[0]["params"]["port"]),
					rec[1]
				])
			pass
		pass

		return res
	pass


	def filter_listens(self, data):
		names = {}
		for d in data:
			if d["syscall"] == "listen":

				if d["params"]["bind_data"]["domain"] in [SocketDomain.AF_INET, SocketDomain.AF_INET6]:
					name = d["exe"]
					record = names.get(name, None)
					if record:
						found = False
						for rec in record:
							params = rec[0]["params"]["bind_data"]
							if params["domain"] in [SocketDomain.AF_INET, SocketDomain.AF_INET6]:
								if params["domain"] == d["params"]["bind_data"]["domain"] and params["port"] == d["params"]["bind_data"]["port"] and params["addr"] == d["params"]["bind_data"]["addr"]:
									rec[1] += 1
									found = True
									#print "inc"
									break
								pass
							pass
						pass

						if not found:
							record.append([d, 1])
						#print "app"
					else:
						names[name] = [[d, 1]]
						#print "new"
					pass
				pass
			pass
		pass


		res = []

		for name, record in names.iteritems():
			for rec in record:
				res.append([
					name,
					rec[0]["params"]["bind_data"]["addr"] + ":" + str(rec[0]["params"]["bind_data"]["port"]),
					rec[1]
				])
			pass
		pass

		return res
	pass
	
pass


logbuf = LogBuffer.get_instance()


def save():
	logbuf.dump()
	#logbuf.clear()
pass

def clear():
	logbuf.clear()
pass




















