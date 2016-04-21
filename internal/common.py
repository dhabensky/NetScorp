
	

linux_syscalls = {

    # socket creation
	"socket" : 3,
	"socketpair" : 4,
	
	# connection
	"bind" : 3,
	"connect": 3,
	"listen": 2,
	"accept": 3,
	
	# potentially useful
	
	# read & write
	#"read",
	#"write",
	#"send",
	#"sendto",
	#"sendmsg",
	#"recv",
	#"recvfrom",
	#"recvmsg",
	
	# close
	#"shutdown",
	#"close"
}



class SocketDomain:

	AF_UNSPEC      = 0
	AF_UNIX        = 1   #   /* Unix domain sockets          */
	AF_LOCAL       = 1   #   /* POSIX name for AF_UNIX       */
	AF_INET        = 2   #   /* Internet IP Protocol         */
	AF_INET6       = 10  #   /* IP version 6                 */
	
	# and many more domains in that we are not interested

pass

domains = {
	1 : 'Unix',
	2 : 'IPv4',
	10 : 'IPv6'
}

types = {
	1 : 'tcp',
	2 : 'udp',
	3 : 'raw'
}

protocols = {
	17 : 'udp',
	6 : 'tcp',
	0 : 'default'
}