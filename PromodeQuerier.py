import socket
import re
import asyncio

class PromodeQuerier:

	# check what we get ipv4 or domain
	def is_valid_address(ip: str) -> bool:
		return re.match('^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$',ip)
	
	# return ipv4 from domain name or none if cant get info from dns
	def address_from_domain(domain: str) -> str:
		try:
			return socket.gethostbyname(domain)
		except:
			return None
	
	# check if we get valid body of packet
	def is_valid_response_body(body: bytes) -> bool:
		return body.startswith(b'\\') and body.count(b'\\') % 2 == 0

	# generate packet for master server
	def build_query_master_packet(protocol: int = 68,tags: str = None) -> bytes:
		protocol = str(protocol).encode()
		tags = (' '+tags).encode() if tags else ''.encode()
		return b'\xff\xff\xff\xffgetservers '+protocol+tags+b'\x00'

	def is_valid_master_response_header(header: bytes) -> bool:
		return header == b'\xff\xff\xff\xffgetserversResponse'

	def split_master_packet(packet: bytes) -> tuple[bytes, bytes]:
		return packet[:22], packet[22:]

	# generate packet for retrieve server info
	def build_query_packet() -> bytes:
		return b'\xff\xff\xff\xffgetstatus\x00'

	# check if we get valid header packet
	def is_valid_response_header(header: bytes) -> bool:
		return header == b'\xff\xff\xff\xffstatusResponse\n'

	# simply split packet to body and header
	def split_packet(packet: bytes) -> tuple[bytes, bytes]:
	    return packet[:19], packet[19:]
	
	# parse players data into tuple of dict like [{name,rawname,ping,score},..]
	def parsePlayers(packet: bytes) -> tuple[dict]:
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
	def parseGamedata(packet: bytes) -> dict:
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

	def parseInfo(packet: bytes) -> dict:
		packet = packet[1:]
		data = re.split(b'\n',packet, maxsplit=1)
		info = PromodeQuerier.parseGamedata(data[0])
		info['players'] = PromodeQuerier.parsePlayers(data[1]) if data[1] else None
		return info

	# parse response from master server as tuple like [{'address':ip,'port':port},...]
	def parseMasterData(data: bytes) -> tuple[{str,int}]:
		servers = []
		data = str(data)
		for i in range(len(data) - 10):
			if (data[i] == '\\' and data[i + 7] == '\\'):
				ip   = str(ord(data[i + 1])) + '.' + str(ord(data[i + 2])) + '.' + str(ord(data[i + 3])) + '.' + str(ord(data[i + 4]))
				port = (ord(data[i + 5]) << 8) + ord(data[i + 6])
				servers.append({'address':ip,'port':port})
		return servers

	# query servers from master server
	@staticmethod
	def queryMaster(address: str, port: int, timeout: int, protocol: int = 68, tags: str = None) -> tuple[{str,int}]:
		if not (0 <= port <= 65535):
			return {'error':f'Invalid port {address}:{port}'}
		ip = address if PromodeQuerier.is_valid_address(address) else PromodeQuerier.address_from_domain(address)
		if not ip:
			return {'error':f'Can\'t get ipv4 from address {address}'}
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM,0) as sock:
			sock.settimeout(timeout)
			sock.sendto(PromodeQuerier.build_query_master_packet(protocol,tags), (ip, port))
			try:
				data = sock.recvfrom(65507)[0]	
			except:
				return {'error':f'Master server {address}:{port} doesn\'t response'}
		header, body = PromodeQuerier.split_master_packet(data)
		if not (PromodeQuerier.is_valid_master_response_header(header)):
			return {'error':f'Response error from master server {address}:{port}. Maybe this game doesn\'t supports?'}
		return PromodeQuerier.parseMasterData(body)

	@staticmethod
	def queryMasterMult(servers: tuple[{str,int}], timeout: int, protocol: int = 68, tags: str = None) -> tuple[tuple[{str,int}]]:
		result = []
		for server in servers:
			result.append(PromodeQuerier.queryMaster(server['address'],server['port'],timeout,protocol,tags))
		return result

	# sync query 
	@staticmethod
	def query(address: str, port: int, timeout: int) -> tuple:
		if not (0 <= port <= 65535):
			return {'error':f'Invalid port {address}:{port}'}
		ip = address if PromodeQuerier.is_valid_address(address) else PromodeQuerier.address_from_domain(address)
		if not ip:
			return {'error':f'Can\'t get ipv4 from address {address}'}
		with socket.socket(socket.AF_INET, socket.SOCK_DGRAM,0) as sock:
			sock.settimeout(timeout)
			sock.sendto(PromodeQuerier.build_query_packet(), (ip, port))
			try:
				data = sock.recvfrom(4096)[0]	
			except:
				return {'error':f'Server {address}:{port} doesn\'t response'}
		header, body = PromodeQuerier.split_packet(data)
		if not (PromodeQuerier.is_valid_response_header(header) and PromodeQuerier.is_valid_response_body(body)):
			return {'error':f'Response error from server {address}:{port}. Maybe this game doesn\'t supports?'}
		return PromodeQuerier.parseInfo(body)

	# sync query multiple
	@staticmethod
	def queryMult(servers: tuple[{str,int}], timeout: int) -> tuple[dict]:
		result = []
		for server in servers:
			result.append(PromodeQuerier.query(server['address'],server['port'],timeout))
		return result

	class AsyncProtocol(asyncio.DatagramProtocol):
	    def __init__(self, recvq):
	        self._recvq = recvq

	    def datagram_received(self, data, addr):
	        self._recvq.put_nowait((data, addr))

	@staticmethod
	async def queryAsync(address: str, port: int, timeout: int) -> tuple:	
		if not (0 <= port <= 65535):
			return {'error':f'Invalid port {address}:{port}'}
		ip = address if PromodeQuerier.is_valid_address(address) else PromodeQuerier.address_from_domain(address)
		if not ip:
			return {'error':f'Can\'t get ipv4 from address {address}'}
		
		loop = asyncio.get_event_loop()
		recvq = asyncio.Queue()
		transport, protocol = await loop.create_datagram_endpoint(lambda: PromodeQuerier.AsyncProtocol(recvq),family=socket.AF_INET,remote_addr=(address,port))
		transport.sendto(PromodeQuerier.build_query_packet())
		try:
			data, address = await asyncio.wait_for(recvq.get(), timeout=timeout)
		except:
			transport.close()
			return {'error':f'Server {address}:{port} doesn\'t response'}
		transport.close()

		header, body = PromodeQuerier.split_packet(data)
		if not (PromodeQuerier.is_valid_response_header(header) and PromodeQuerier.is_valid_response_body(body)):
			return {'error':f'Response error from server {address}:{port}. Maybe this game doesn\'t supports?'}
		return PromodeQuerier.parseInfo(body)

	@staticmethod
	async def queryMultAsync(servers: tuple[{str,int}], timeout: int) -> tuple[dict]:
		tasks = [PromodeQuerier.queryAsync(server['address'],server['port'],5) for server in servers]
		return await asyncio.gather(*tasks)

	@staticmethod
	async def queryMasterAsync(address: str, port: int, timeout: int, protocol: int = 68, tags: str = None) -> tuple[{str,int}]:	
		if not (0 <= port <= 65535):
			return {'error':f'Invalid port {address}:{port}'}
		ip = address if PromodeQuerier.is_valid_address(address) else PromodeQuerier.address_from_domain(address)
		if not ip:
			return {'error':f'Can\'t get ipv4 from address {address}'}
		
		loop = asyncio.get_event_loop()
		recvq = asyncio.Queue()
		transport, proto = await loop.create_datagram_endpoint(lambda: PromodeQuerier.AsyncProtocol(recvq),family=socket.AF_INET,remote_addr=(address,port))
		transport.sendto(PromodeQuerier.build_query_master_packet(protocol,tags))
		try:
			data, address = await asyncio.wait_for(recvq.get(), timeout=timeout)
		except:
			transport.close()
			return {'error':f'Master server {address}:{port} doesn\'t response'}
		transport.close()

		header, body = PromodeQuerier.split_master_packet(data)
		if not (PromodeQuerier.is_valid_master_response_header(header)):
			return {'error':f'Response error from master server {address}:{port}. Maybe this game doesn\'t supports?'}
		return PromodeQuerier.parseMasterData(body)

	@staticmethod
	async def queryMasterMultAsync(servers: tuple[{str,int}], timeout: int, protocol: int = 68, tags: str = None) -> tuple[tuple[{str,int}]]:
		tasks = [PromodeQuerier.queryMasterAsync(server['address'],server['port'],5,protocol,tags) for server in servers]
		return await asyncio.gather(*tasks)
