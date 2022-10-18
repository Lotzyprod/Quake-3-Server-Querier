import socket
import re
import asyncio

class PromodeQuerier:

	# check what we get ipv4 or domain
	# input: str (probably ipv4)
	# return: bool (is legit ip or not)
	def is_valid_address(ip: str) -> bool:
		return re.match('^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$',ip)
	
	# return ipv4 from domain name or none if cant get info from dns
	# input: str (probably domain address)
	# return: str (probably ipv4) or None
	def address_from_domain(domain: str) -> str | None:
		try:
			return socket.gethostbyname(domain)
		except:
			return

	# implement abstract class for async queries
	# init with asyncio.Queue <- datagrames will be received in that
	class AsyncProtocol(asyncio.DatagramProtocol):
	    def __init__(self, recvq: asyncio.Queue):
	        self._recvq = recvq

	    def datagram_received(self, data: bytes, addr):
	        self._recvq.put_nowait((data, addr))
	
	# parse players data into tuple of dict like [{name,rawname,ping,score},..]
	# input values: part of packet
	def parseServerPlayerData(packet: bytes) -> tuple[{str,str,int,int}]:
		packet = (packet[:len(packet)-1]).decode("utf-8")
		players = []
		for data in packet.split('\n'):
			score,ping,rawname = data.split(' ',maxsplit=2)
			ping = int(ping)
			score = int(score)
			rawname = str(rawname)
			rawname = rawname[1:len(rawname)-1]
			name = re.sub('\^.','',rawname)
			players.append({'name':name,'rawname':rawname,'ping':ping,'score':score})
		return players
	
	# parse game data into dict like {option:value,...}
	# input values: part of packet
	def parseServerGameData(packet: bytes) -> dict:
		data = re.split(' ?\\\ ?',packet.decode("utf-8"))
		gamedata = {}
		for i in range(int(len(data)/2)):
			key = data[2*i].lower()
			if data[2*i+1].isdigit():
				gamedata[key] = int(data[2*i+1])
			elif re.match(r'^-?\d+(?:\.\d+)$', data[2*i+1]) is not None:
				gamedata[key] = float(data[2*i+1])
			else:
				gamedata[key] = data[2*i+1]
		return gamedata

	def parseServerPacket(packet: bytes) -> dict | None:
		if b'\xff\xff\xff\xffstatusResponse\n\\' != packet[:20]:
			return
		body = packet[20:] 
		if not body.count(b'\\') % 2 == 1:
			return
		data = re.split(b'\n',body, maxsplit=1)
		gameInfo = PromodeQuerier.parseServerGameData(data[0])
		gameInfo['players'] = PromodeQuerier.parseServerPlayerData(data[1]) if data[1] else None
		return gameInfo

	# sync query game server
	# input: 
	# 	str: address (domain or ipv4), 
	# 	int: port (number between 0 and 65535), 
	# 	int: timeout (what amount of secs wait if host not response)
	# output: dict (server's game info)
	@staticmethod
	def queryServer(address: str, port: int, timeout: int=5) -> dict | None:
		if not (0 <= port <= 65535):
			return
		ip = address if PromodeQuerier.is_valid_address(address) else PromodeQuerier.address_from_domain(address)
		if not ip:
			return
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM,0) as sock:
			packet = b'\xff\xff\xff\xffgetstatus\x00'
			sock.settimeout(timeout)
			sock.sendto(packet, (ip, port))
			try:
				data = sock.recvfrom(4096)[0]	
			except:
				return
		return PromodeQuerier.parseServerPacket(data)

	# sync query multiple game servers
	# input:
	#	tuple[[str: address, int: port]] (domain/ipv4 + port)
	# 	int: timeout (what amount of secs wait if host not response)
	# output: tuple of dicts (servers game info)
	@staticmethod
	def queryServers(servers: tuple[[str,int]], timeout: int=5) -> tuple[dict | None]:
		return [PromodeQuerier.queryServer(server[0],server[1],timeout) for server in servers]

	@staticmethod
	async def queryServerAsync(address: str, port: int, timeout: int=5) -> dict | None:	
		if not (0 <= port <= 65535):
			return
		ip = address if PromodeQuerier.is_valid_address(address) else PromodeQuerier.address_from_domain(address)
		if not ip:
			return
		loop = asyncio.get_event_loop()
		recvq = asyncio.Queue()
		transport = (await loop.create_datagram_endpoint(lambda: PromodeQuerier.AsyncProtocol(recvq),family=socket.AF_INET,remote_addr=(address,port)))[0]
		packet = b'\xff\xff\xff\xffgetstatus\x00'
		transport.sendto(packet)
		try:
			data = (await asyncio.wait_for(recvq.get(), timeout=timeout))[0]
		except:
			transport.close()
			return
		transport.close()
		return PromodeQuerier.parseServerPacket(data)

	@staticmethod
	async def queryServersAsync(servers: tuple[[str,int]], timeout: int=5) -> tuple[dict | None]:
		return await asyncio.gather(*[PromodeQuerier.queryServerAsync(server[0],server[1],timeout) for server in servers])

	# generate packet for ♂master♂ server
	# input:
	# 	int: protocol (game protocol)
	#   str: tags (game tags with space delimiter like as: 'empty full bots ...')
	def build_master_packet(protocol: int = 68,tags: str = None) -> bytes:
		tags = (' '+tags).encode() if tags else ''.encode()
		return b'\xff\xff\xff\xffgetservers '+str(protocol).encode()+tags+b'\x00'

	# parse response from ♂master♂ server as tuple like [[ip,port],...]
	def parseMasterData(data: bytes) -> tuple[[str,int]] | None:
		if data[:22] != b'\xff\xff\xff\xffgetserversResponse':
			return
		data = str(data[22:])
		servers = []
		for i in range(len(data) - 10):
			if (data[i] == '\\' and data[i + 7] == '\\'):
				ip   = str(ord(data[i + 1])) + '.' + str(ord(data[i + 2])) + '.' + str(ord(data[i + 3])) + '.' + str(ord(data[i + 4]))
				port = (ord(data[i + 5]) << 8) + ord(data[i + 6])
				servers.append([ip,port])
		return servers

	# sync query ♂master♂ server
	# input: 
	# 	str: address (domain or ipv4), 
	# 	int: port (number between 0 and 65535), 
	# 	int: timeout (what amount of secs wait if host not response)
	#   int: protocol (game protocol number)
	#   str: tags (game tags with space delimiter like as: 'empty full bots ...')  
	# output: tuple[[str,int]] (servers addresses)
	@staticmethod
	def queryMaster(address: str, port: int, timeout: int = 5, protocol: int = 68, tags: str = None) -> tuple[[str,int]] | None:
		if not (0 <= port <= 65535):
			return
		ip = address if PromodeQuerier.is_valid_address(address) else PromodeQuerier.address_from_domain(address)
		if not ip:
			return
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM,0) as sock:
			sock.settimeout(timeout)
			sock.sendto(PromodeQuerier.build_master_packet(protocol,tags), (ip, port))
			try:
				data = sock.recvfrom(65507)[0]	
			except:
				return
		return PromodeQuerier.parseMasterData(data)

	# sync query multiple ♂master♂ servers
	# input:
	#	tuple[[str: address, int: port]] (domain/ipv4 + port)
	# 	int: timeout (what amount of secs wait if host not response)
	# 	int: timeout (what amount of secs wait if host not response)
	#   int: protocol (game protocol number)
	#   str: tags (game tags with space delimiter like as: 'empty full bots ...')  
	# output: tuple of tuples of tuples (servers game info)
	@staticmethod
	def queryMasters(servers: tuple[[str,int]], timeout: int = 5, protocol: int = 68, tags: str = None) -> tuple[tuple[[str,int]] | None]:
		return [PromodeQuerier.queryMaster(server[0],server[1],timeout,protocol,tags) for server in servers]

	@staticmethod
	async def queryMasterAsync(address: str, port: int, timeout: int=5, protocol: int = 68, tags: str = None) -> tuple[[str,int]] | None:	
		if not (0 <= port <= 65535):
			return
		ip = address if PromodeQuerier.is_valid_address(address) else PromodeQuerier.address_from_domain(address)
		if not ip:
			return	
		loop = asyncio.get_event_loop()
		recvq = asyncio.Queue()
		transport = (await loop.create_datagram_endpoint(lambda: PromodeQuerier.AsyncProtocol(recvq),family=socket.AF_INET,remote_addr=(address,port)))[0]
		transport.sendto(PromodeQuerier.build_master_packet(protocol,tags))
		try:
			data = (await asyncio.wait_for(recvq.get(), timeout=timeout))[0]
		except:
			transport.close()
			return 
		transport.close()
		return PromodeQuerier.parseMasterData(data)

	@staticmethod
	async def queryMastersAsync(servers: tuple[[str,int]], timeout: int=5, protocol: int = 68, tags: str = None) -> tuple[tuple[[str,int]] | None]:
		return await asyncio.gather(*[PromodeQuerier.queryMasterAsync(server[0],server[1],timeout,protocol,tags) for server in servers])
