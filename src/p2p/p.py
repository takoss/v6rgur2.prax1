import hashlib
import os
import random
import string
import requests
import argparse
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class MyRequestHandler(BaseHTTPRequestHandler):

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        print("GET received", self.server.server_address[1])

        ip, server_port = self.server.server_address
        self._set_headers()
        if self.path == "/getpeers/":
            servers = get_string_from_conf(server_port)
            self.wfile.write(bytes(servers, "utf-8"))

        elif self.path == "/block/gethashes/":
            hashes = get_hash_list(server_port, "blocks_peer")
            self.wfile.write(bytes(json.dumps(hashes), "utf-8"))

        elif self.path == "/transact/gethashes/":
            hashes = get_hash_list(server_port, "transacts_peer")
            self.wfile.write(bytes(json.dumps(hashes), "utf-8"))

        elif self.path.startswith("/getblock/"):
            block_hash = self.path[len("/getblock/"):]
            self.wfile.write(bytes(read_file(server_port, block_hash, "blocks_peer"), "utf-8"))

        elif self.path.startswith("/gettransact/"):
            transact_hash = self.path[len("/gettransact/"):]
            self.wfile.write(bytes(read_file(server_port, transact_hash, "transacts_peer"), "utf-8"))

        else:
            raise Exception("Invalid get request: ", self.path)

    def do_POST(self):
        print("POST received", self.server.server_address[1])

        ip, server_port = self.server.server_address
        self._set_headers()
        if self.path == "/addpeer/":
            content_len = int(self.headers.get('Content-Length'))
            post_body = json.loads(self.rfile.read(content_len).decode("utf-8"))
            if "port" in post_body:
                c_ip, c_tcp_port = self.client_address
                add_peer_to_list(server_port, c_ip + ":" + str(post_body["port"]))

        elif self.path == "/addtransact/":
            content_len = int(self.headers.get('Content-Length'))
            transact = self.rfile.read(content_len).decode("utf-8")
            saved = save(server_port, transact, folder_prefix="transacts_peer")
            if saved:
                broadcast(server_port, get_peers_from_conf(server_port), data=transact, is_transact=True)

        elif self.path == "/addblock/":
            content_len = int(self.headers.get('Content-Length'))
            block = self.rfile.read(content_len).decode("utf-8")
            saved = save(server_port, block, folder_prefix="blocks_peer")
            if saved:
                broadcast(server_port, get_peers_from_conf(server_port), data=block, is_block=True)


def read_file(curr_port, block_hash, folder_prefix):
    path = os.path.abspath('.')
    sep = get_separator(path)
    block_path = path + sep + folder_prefix + str(curr_port) + sep + block_hash

    block = None
    if os.path.exists(block_path):
        with open(block_path, "r") as text_file:
            block = text_file.read()

    return block


def get_separator(path: str) -> str:
    for char in path[::-1]:
        if char == '\\':
            _separator = '\\'
            return _separator
        if char == '/':
            return '/'


def random_word(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for _ in range(length))


def get_string_from_conf(port: int) -> str:
    with open('servers-' + str(port) + '.json', 'r') as f:
        output = f.read()
    return output


def get_peers_from_conf(port: int) -> list:
    return json.loads(get_string_from_conf(port))


def get_hash_list(port: int, folder_prefix: str) -> list:
    path = os.path.abspath('.')
    sep = get_separator(path)

    folder_path = path + sep + folder_prefix + str(port)

    hashes = list()

    if os.path.exists(folder_path):
        for filename in os.listdir(folder_path):
            hashes.append(filename)

    return hashes


def add_self_to_another_peer(curr_port, peer):
    data = dict()
    data['port'] = curr_port

    requests.post("http://" + peer + "/addpeer/", json=data)


def get_peers_from_peer(peer: str) -> list:
    r = requests.get("http://" + peer + "/getpeers/")

    return json.loads(r.content.decode("utf-8"))


def add_peer_to_list(curr_port: int, new_peer: str):
    conf_servers = get_peers_from_conf(curr_port)

    if new_peer not in conf_servers:
        conf_servers.append(new_peer)
        print("adding ", new_peer)

        with open("servers-" + str(curr_port) + ".json", 'w') as outfile:
            json.dump(list(conf_servers), outfile)
    else:
        print(PEER, " already in server list.")


def remove_peer_from_list(curr_port: int, old_peer: str):
    conf_servers = get_peers_from_conf(curr_port)

    try:
        conf_servers.remove(old_peer)
    except KeyError:
        print(PEER, "not in server list")
        pass

    with open("servers-" + str(curr_port) + ".json", 'w') as outfile:
        json.dump(list(conf_servers), outfile)


def add_peers_to_list(curr_ip, curr_port, new_peers: list):
    conf_servers = get_peers_from_conf(curr_port)
    all_servers = set(conf_servers)
    all_servers = all_servers.union(set(new_peers))

    try:
        all_servers.remove(curr_ip + ":" + str(curr_port))
    except KeyError:
        pass

    with open("servers-" + str(curr_port) + ".json", 'w') as outfile:
        json.dump(list(all_servers), outfile)


def make_transact(curr_port, data):
    path = os.path.abspath('.')
    sep = get_separator(path)
    folder_path = path + sep + "transacts_peer" + str(curr_port)

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    data_hash = hashlib.sha256(data.encode("utf-8")).hexdigest()

    full_path = folder_path + sep + data_hash

    with open(full_path, "w") as text_file:
        text_file.write(data)

    return data_hash


def make_block(curr_port):
    path = os.path.abspath('.')
    sep = get_separator(path)
    folder_path = path + sep + "blocks_peer" + str(curr_port)

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    data = random_word(100)

    data_hash = hashlib.sha256(data.encode("utf-8")).hexdigest()

    full_path = folder_path + sep + data_hash

    with open(full_path, "w") as text_file:
        text_file.write(data)

    return data_hash


def send_block(curr_port, block, peer):
    try:
        requests.post("http://" + peer + "/addblock/", data=block)
    except requests.exceptions.ConnectionError:
        remove_peer_from_list(curr_port, peer)
        print("ConnectionError:", peer, "removed from peer list.")


def send_transact(curr_port, text, peer):
    try:
        requests.post("http://" + peer + "/addtransact/", data=text)
    except requests.exceptions.ConnectionError:
        remove_peer_from_list(curr_port, peer)
        print("ConnectionError:", peer, "removed from peer list.")


def broadcast(curr_port, peers, data_hash=None, data=None, fail_if_exists=True, is_transact=False, is_block=False):
    if is_transact:
        folder_prefix = "transacts_peer"
    elif is_block:
        folder_prefix = "blocks_peer"
    else:
        raise RuntimeError

    if data is None:
        data = read_file(curr_port, data_hash, folder_prefix)

    if data_hash is None:
        data_hash = hashlib.sha256(data.encode("utf-8")).hexdigest()

    if fail_if_exists and data_hash in get_hash_list(curr_port, folder_prefix):
        return

    for peer in peers:
        if is_block:
            send_block(curr_port, data, peer)
        elif is_transact:
            send_transact(curr_port, data, peer)


def save(curr_port: int, text: str, folder_prefix: str, text_hash: str=None):
    name = "Block" if folder_prefix.startswith("blocks") else "Transaction"

    test_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if text_hash and test_hash != text_hash:
        print(name + " not saved due to hash discrepancy: ", text_hash)
        return False

    if text_hash is None:
        text_hash = test_hash

    if text_hash in get_hash_list(curr_port, folder_prefix):
        return False

    path = os.path.abspath('.')
    sep = get_separator(path)
    folder_path = path + sep + folder_prefix + str(curr_port)

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    full_path = folder_path + sep + text_hash

    with open(full_path, "w") as text_file:
        text_file.write(text)

    print(name + " with hash", text_hash, "saved")
    return True


def peer_discovery(server_ip, server_port):
    for peer in get_peers_from_conf(server_port):
        try:
            add_self_to_another_peer(curr_port=server_port, peer=peer)
            add_peers_to_list(curr_ip=server_ip, curr_port=server_port, new_peers=get_peers_from_peer(peer))
        except requests.exceptions.ConnectionError:
            print("removed peer", peer)
            remove_peer_from_list(curr_port=server_port, old_peer=peer)


def update_ledger(curr_port, peers):
    curr_blocks = set(get_hash_list(curr_port, "blocks_peer"))
    curr_transacts = set(get_hash_list(curr_port, "transacts_peer"))

    added_blocks = added_transactions = 0
    for peer in peers:
        r = requests.get("http://" + peer + "/block/gethashes/")
        peer_block_hashes = json.loads(r.content.decode("utf-8"))

        for peer_block_hash in peer_block_hashes:
            if peer_block_hash not in curr_blocks:
                block_r = requests.get("http://" + peer + "/getblock/" + peer_block_hash)
                saved = save(curr_port=curr_port, text=block_r.content.decode("utf-8"), text_hash=peer_block_hash,
                             folder_prefix="blocks_peer")
                if saved:
                    added_blocks += 1

        r = requests.get("http://" + peer + "/transact/gethashes/")
        peer_transact_hashes = json.loads(r.content.decode("utf-8"))

        for peer_transact_hash in peer_transact_hashes:
            if peer_transact_hash not in curr_transacts:
                transact_r = requests.get("http://" + peer + "/gettransact/" + peer_transact_hash)
                saved = save(curr_port=curr_port, text=transact_r.content.decode("utf-8"),
                             folder_prefix="transacts_peer", text_hash=peer_transact_hash)
                if saved:
                    added_transactions += 1

    print(str(added_blocks) + " blocks added.")
    print(str(added_transactions) + " transactions added.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', required=True, help='the TCP port to listen on')

    args = parser.parse_args()
    HOST, PORT = "127.0.0.1", int(args.port)

    # Create the server
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, MyRequestHandler)

    s = threading.Thread(target=httpd.serve_forever)

    s.start()
    print("Server started on port:", PORT)

    # Start client
    peer_discovery(server_ip=HOST, server_port=PORT)
    update_ledger(PORT, get_peers_from_conf(PORT))

    print("Client setup finished.")

    while True:
        try:
            i = input()

            if i == "block":
                HASH = make_block(PORT)
                print("New block with hash: ", HASH)
                broadcast(PORT, get_peers_from_conf(PORT), data_hash=HASH, fail_if_exists=False, is_block=True)

            elif i.startswith("c "):
                PEER = i[2:]
                p_ip, p_port = PEER.split(":")
                p_port = int(p_port)
                add_self_to_another_peer(curr_port=PORT, peer=PEER)
                add_peer_to_list(curr_port=PORT, new_peer=PEER)

            elif i.startswith("t "):
                TEXT = i[2:]
                HASH = make_transact(PORT, TEXT)
                print("New transaction with hash: ", HASH)
                broadcast(PORT, get_peers_from_conf(PORT), data_hash=HASH, fail_if_exists=False, is_transact=True)

            elif i == "l":
                update_ledger(PORT, get_peers_from_conf(PORT))

            elif i == "p":
                peer_discovery(HOST, PORT)

            elif i == "exit":
                break

            print("Query finished.")
        except KeyboardInterrupt:
            break
