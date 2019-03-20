import socketserver
import json
import logging
import socket
import threading
import time
import argparse


logging.basicConfig(level=logging.DEBUG,
                    format='%(name)s: %(message)s',
                    )


class MyRequestHandler(socketserver.BaseRequestHandler):

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        #(self.ip, self.port) = self.server.server_address

    def handle(self):
        # Echo the back to the client
        (ip, port) = self.server.server_address
        client = self.client_address
        self.data = self.request.recv(1024)
        if "GET /getpeers" in str(self.data):
            servers = bytes(get_string_from_conf(port), 'ascii')
            print(servers)
            self.request.sendall(servers)
        return


def get_string_from_conf(port: int) -> str:
    with open('servers-' + str(port) + '.json', 'r') as f:
        output = f.read()
    return output


def get_servers_from_conf(port: int) -> str:
    return json.loads(get_string_from_conf(port))


def add_servers_to_conf(servers: list, ip: str, port: int) -> None:
    conf_servers = get_servers_from_conf(port)
    all_servers = set(conf_servers)
    all_servers.union(set(servers))

    try:
        all_servers.remove(ip + ":" + str(port))
    except KeyError:
        pass

    with open("servers-" + str(port) + ".json", 'w') as outfile:
        json.dump(list(all_servers), outfile)


"""
def client(ip, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
        sock.sendall(bytes(message, 'ascii'))
        response = str(sock.recv(1024), 'ascii')
        print("Received: {}".format(response))
"""


def poll_peers_from_server(ip, port) -> list:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print("beforeconnect")
        sock.connect((ip, port))
        print("afterconnect")
        message = "GET /getpeers HTTP/1.1\r\nHost: " + ip + "\r\n\r\n"
        sock.sendall(bytes(message, 'ascii'))

        response = str(sock.recv(1024), 'ascii')
    print("Received: {}".format(response))
    peers = json.loads(response)
    return peers


def get_request(ip, port, message, parameters):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))
    sock.sendall(bytes(message, 'ascii'))
    response = str(sock.recv(1024), 'ascii')
    print("Received: {}".format(response))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', required=True, help='the TCP port to listen on')
    args = parser.parse_args()
    HOST, PORT = "localhost", int(args.port)

    # Create the server, binding to localhost on port 9999
    server = socketserver.TCPServer((HOST, PORT), MyRequestHandler)

    print("Server started on port:", PORT)
    s = threading.Thread(target=server.serve_forever)

    s.start()

    while True:
        time.sleep(2)
        for server in get_servers_from_conf(PORT):
            try:
                print(server)
                s_ip, s_port = server.split(":")
                s_port = int(s_port)
                print("oh")
                polled_peers = poll_peers_from_server(s_ip, s_port)
                print("ih")
                print(polled_peers)
                add_servers_to_conf(polled_peers, HOST, PORT)

                #client(HOST, PORT, "GET / HTTP/1.1\r\nHost: www.cnn.com\r\n\r\n")
            except ConnectionRefusedError:

                pass

