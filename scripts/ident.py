import socket

IP = '127.0.0.1'
PORT = 64000
BUFFER_SIZE = 1024
MAX_PACKET_SIZE = 584

SIGNATURE = b'\xc0\xff\xee\xc0\xff\xee\x00\x00'
PACKET_TYPE_IDENT = b'\x00'
PACKET_TYPE_QUERY = b'\x01'
PACKET_TYPE_QUERY_IDENT = b'\x02'
IDENTITY = bytes.fromhex('uUt9Rm6bxd4af8lwqQvtSZbWIF09iMt3'.encode('utf-8').hex())
DATA = b'\x00' * (MAX_PACKET_SIZE - (len(SIGNATURE) + 1 + len(IDENTITY)))
IDENT_PACKET = SIGNATURE + PACKET_TYPE_IDENT + IDENTITY + DATA
QUERY_PACKET = SIGNATURE + PACKET_TYPE_QUERY + IDENTITY + DATA
QUERY_IDENT_PACKET = SIGNATURE + PACKET_TYPE_QUERY_IDENT + IDENTITY + DATA

print('[i] sending packet: %s' % IDENT_PACKET)

socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket_obj.connect((IP, PORT))

print('[i] on port: %d' % int(socket.getnameinfo(socket_obj.getsockname(), 3)[1]))

socket_obj.send(IDENT_PACKET)
socket_obj.recv(BUFFER_SIZE)

socket_obj.send(QUERY_PACKET)
data = socket_obj.recv(BUFFER_SIZE)

socket_obj.send(QUERY_IDENT_PACKET)
data = socket_obj.recv(BUFFER_SIZE)

print('[+] received: %s' % data)
socket_obj.close()
