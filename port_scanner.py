import socket

IP = '192.168.0.14'

for port in range (1, 1025):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((IP, port))
    if result == 0:
        print("Port {} is open.".format(port))
    sock.close

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex((IP, 8000))

if result == 0:
    print("Port 8000 is open (my python server)")
    sock.sendall(b'ping!')
    data = sock.recv(1024)
sock.close
print(data)