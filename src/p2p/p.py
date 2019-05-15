import base64
import datetime
import hashlib
import os
import random
import string

from ecdsa import SigningKey, NIST384p, VerifyingKey, BadSignatureError
import json_stable_stringify_python
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
            block_hash_ = self.path[len("/getblock/"):]
            self.wfile.write(bytes(read_file(server_port, block_hash_, "blocks_peer"), "utf-8"))

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
            print("Transaction received")
            verified = verify_transaction(transact)
            if not verified:
                print("Verification failed, not saving")
                return
            print("Verification succeeded")
            saved = save(server_port, transact, folder_prefix="transacts_peer")
            if saved:
                broadcast(server_port, get_peers_from_conf(server_port), data=transact, is_transact=True)
                # create_block_if_necessary(server_port)

        elif self.path == "/addblock/":
            content_len = int(self.headers.get('Content-Length'))
            block = self.rfile.read(content_len).decode("utf-8")

            block_hash = json.loads(block)["hash"]

            saved = save(server_port, block, folder_prefix="blocks_peer", text_hash=block_hash,
                         ignore_hash_similarity_check=True)
            if saved:
                print("Block received")

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


def random_alphanumericword(length):
    letters = string.ascii_uppercase + string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for _ in range(length))


def get_string_from_conf(port: int) -> str:
    try:
        with open('servers-' + str(port) + '.json', 'r') as f:
            output = f.read()
    except FileNotFoundError:
        output = "[]"
        with open('servers-' + str(port) + '.json', 'w') as f:
            f.write('[]')

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
        print("adding peer", new_peer)

        with open("servers-" + str(curr_port) + ".json", 'w') as outfile:
            json.dump(list(conf_servers), outfile)
    else:
        print(new_peer, " already in server list.")


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

    print("New serverlist: ", all_servers)

    with open("servers-" + str(curr_port) + ".json", 'w') as outfile:
        json.dump(list(all_servers), outfile)


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
        requests.post("http://" + peer + "/addblock/", data=block, timeout=2)
    except requests.exceptions.ConnectionError:
        pass
        #remove_peer_from_list(curr_port, peer)
        #print("ConnectionError:", peer, "removed from peer list.")
    except requests.Timeout:
        pass


def send_transact(curr_port, text, peer):
    try:
        requests.post("http://" + peer + "/addtransact/", data=text, timeout=2)
    except requests.exceptions.ConnectionError:
        pass
        #remove_peer_from_list(curr_port, peer)
        #print("ConnectionError:", peer, "removed from peer list.")
    except requests.Timeout:
        pass


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



def save(curr_port: int, text: str, folder_prefix: str, text_hash: str=None, ignore_hash_similarity_check=False):
    name = "Block" if folder_prefix.startswith("blocks") else "Transaction"

    test_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if not ignore_hash_similarity_check and text_hash and test_hash != text_hash:
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
    return text_hash


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
        try:
            r = requests.get("http://" + peer + "/block/gethashes/")
            peer_block_hashes = json.loads(r.content.decode("utf-8"))

            for peer_block_hash in peer_block_hashes:
                if peer_block_hash not in curr_blocks:
                    block_r = requests.get("http://" + peer + "/getblock/" + peer_block_hash)
                    saved = save(curr_port=curr_port, text=block_r.content.decode("utf-8"), text_hash=peer_block_hash,
                                 folder_prefix="blocks_peer", ignore_hash_similarity_check=True)
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
        except requests.exceptions.ConnectionError:
            remove_peer_from_list(curr_port, peer)
            print("ConnectionError:", peer, "removed from peer list.")

    print(str(added_blocks) + " blocks added.")
    print(str(added_transactions) + " transactions added.")


def make_transact(curr_port: int, data: str, signing_key, verifying_key):
    try:
        t_json = json.loads(data)
    except Exception:
        print("Error occurred during json processing")
        return

    if type(t_json) != dict or "from" not in t_json or "to" not in t_json or "sum" not in t_json:
        print("Invalid json!")
        return False

    # To avoid unnecessary timezone complications let's use UTC time
    t_json["timestamp"] = datetime.datetime.utcnow().isoformat()

    outgoing_transaction_json = dict()

    outgoing_transaction_json["signature"] = \
        base64.b64encode(signing_key.sign(json_stable_stringify_python.stringify(t_json).encode())).decode()

    outgoing_transaction_json["transaction"] = t_json

    out_str = json.dumps(outgoing_transaction_json)

    if not verify_transaction(outgoing_transaction_json) and t_json["from"] != "0":
        print("Transaction does not verify")
        return False

    path = os.path.abspath('.')
    sep = get_separator(path)
    folder_path = path + sep + "transacts_peer" + str(curr_port)

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    data_hash = hashlib.sha256(out_str.encode()).hexdigest()

    full_path = folder_path + sep + data_hash

    with open(full_path, "w") as text_file:
        text_file.write(out_str)

    return data_hash


def get_all_transaction_hashes_in_blocks(curr_port, latest_block):
    if latest_block is None:
        return []

    blocks = [latest_block]

    curr_hash = latest_block["prev_hash"]
    while curr_hash is not False:
        curr_block = json.loads(read_file(curr_port, curr_hash, "blocks_peer"))
        blocks.append(curr_block)
        curr_hash = curr_block["prev_hash"]

    transactions_in_blocks = []
    transaction_hashes_in_blocks = []
    for block in blocks:
        for transaction in block["transactions"]:
            transaction_hashes_in_blocks.append(hashlib.sha256(json.dumps(transaction).encode()).hexdigest())
            transactions_in_blocks.append(transaction)

    return transaction_hashes_in_blocks


def get_all_transactions_not_in_blocks(curr_port, latest_block):
    transact_hashes_in_blocks = get_all_transaction_hashes_in_blocks(curr_port, latest_block)

    if transact_hashes_in_blocks is None:
        transact_hashes_in_blocks = []

    transact_hashes = get_hash_list(curr_port, "transacts_peer")

    transact_hashes_not_in_blocks = []

    for transact_hash in transact_hashes:
        if transact_hash not in transact_hashes_in_blocks:
            transact_hashes_not_in_blocks.append(transact_hash)

    transacts_not_in_blocks = []

    for transact_hash in transact_hashes_not_in_blocks:
        txt = read_file(curr_port, transact_hash, "transacts_peer")
        if txt is not None:
            update_ledger(curr_port, get_peers_from_conf(curr_port))
            txt = read_file(curr_port, transact_hash, "transacts_peer")
        transacts_not_in_blocks.append(json.loads(txt))

    return transacts_not_in_blocks


def calc_merkle_root(correct_transactions):
    if len(correct_transactions) == 0:
        return "0"

    # Populate lower level with hashes
    prev_level = [hashlib.sha256(json.dumps(transact).encode()).hexdigest() for transact in correct_transactions]

    curr_level = []

    while len(prev_level) > 1:
        i = 0
        while i < len(prev_level):
            if i + 1 < len(prev_level):
                this_hash = hashlib.sha256((prev_level[i] + prev_level[i + 1]).encode()).hexdigest()
            elif i + 1 == len(prev_level):
                this_hash = hashlib.sha256((prev_level[i] + prev_level[i]).encode()).hexdigest()

            curr_level.append(this_hash)
            i += 2

        prev_level = curr_level
        curr_level = []

    return prev_level[0]


def create_block(curr_port, correct_transactions, verifying_key):
    block_json = dict()
    block_hashes = get_hash_list(curr_port, "blocks_peer")
    if len(block_hashes) == 0:
        nr = 0
        prev_hash = False
    else:
        prev_nr = -1
        prev_hash = False
        for block_hash in block_hashes:
            block = json.loads(read_file(curr_port, block_hash, "blocks_peer"))
            if prev_nr < block["nr"]:
                prev_nr = block["nr"]
                prev_hash = block["hash"]

        nr = prev_nr + 1

    block_json["prev_hash"] = prev_hash
    block_json["nr"] = nr

    block_json["timestamp"] = datetime.datetime.utcnow().isoformat()
    block_json["creator"] = base64.b64encode(verifying_key.to_string()).decode()
    block_json["merkle_root"] = calc_merkle_root(correct_transactions)

    block_json["count"] = len(correct_transactions)
    block_json["transactions"] = correct_transactions

    block_str = json.dumps(block_json)

    while True:
        nonce = random_alphanumericword(32)
        block_str_w_nonce = block_str + nonce
        block_hash = hashlib.sha256(block_str_w_nonce.encode()).hexdigest()
        if block_hash.startswith("0000"):
            block_json["nonce"] = nonce
            block_json["hash"] = block_hash
            return json.dumps(block_json), block_hash


def get_all_transactions_in_blocks(curr_port, latest_block):
    transact_hashes_in_blocks = get_all_transaction_hashes_in_blocks(curr_port, latest_block)
    transacts_in_blocks = []

    for transact_hash in transact_hashes_in_blocks:
        txt = read_file(curr_port, transact_hash, "transacts_peer")
        if txt is None:
            update_ledger(curr_port, get_peers_from_conf(curr_port))
            txt = read_file(curr_port, transact_hash, "transacts_peer")
        transacts_in_blocks.append(json.loads(txt))

    return transacts_in_blocks


def get_account_balance(account, done_transactions) -> float:
    sum = 0
    for transaction in done_transactions:
        if transaction["transaction"]["from"] == account:
            sum -= transaction["transaction"]["sum"]
        elif transaction["transaction"]["to"] == account:
            sum += transaction["transaction"]["sum"]
    return sum


def get_transaction_amount_in_block_chain(last_block, all_blocks):
    transaction_amount = last_block["count"]
    prev_hash = last_block["prev_hash"]
    while prev_hash is not False:
        for block in all_blocks:
            if block["hash"] == prev_hash:
                transaction_amount += block["count"]
                prev_hash = block["prev_hash"]
                break

    return transaction_amount


def get_latest_block(curr_port):
    block_hashes = get_hash_list(curr_port, "blocks_peer")

    if len(block_hashes) == 0:
        return None

    blocks = []
    for block_hash in block_hashes:
        blocks.append(json.loads(read_file(curr_port, block_hash, "blocks_peer")))

    best_block = blocks[0]
    best_transaction_amount = get_transaction_amount_in_block_chain(best_block, blocks)
    for block in blocks[1:]:
        if block["nr"] > best_block["nr"]:
            best_block = block
            best_transaction_amount = get_transaction_amount_in_block_chain(block, blocks)
            continue

        elif block["nr"] == best_block["nr"]:
            transaction_amount = get_transaction_amount_in_block_chain(block, blocks)
            if transaction_amount > best_transaction_amount:
                best_block = block
                best_transaction_amount = transaction_amount
                continue

            elif transaction_amount == best_transaction_amount:
                if block["timestamp"] > best_block["timestamp"]:
                    best_block = block
                    best_transaction_amount = transaction_amount

                elif block["timestamp"] == best_block["timestamp"]:
                    if block["hash"] < best_block["hash"]:
                        best_block = block
                        best_transaction_amount = transaction_amount

    return best_block


def create_block_from_transactions(curr_port, verifying_key, only_create_if_at_least: int=False):
    latest_block = get_latest_block(curr_port)

    transactions_not_in_blocks = get_all_transactions_not_in_blocks(curr_port, latest_block)
    validated_transactions = get_all_transactions_in_blocks(curr_port, latest_block)

    new_blocks_in_loop = True
    new_block_transactions = []
    while new_blocks_in_loop:
        new_blocks_in_loop = False
        for transaction in transactions_not_in_blocks:

            if transaction in new_block_transactions:
                continue

            # Workaround for inserting money into the system
            if transaction["transaction"]["from"] == "0":
                new_block_transactions.append(transaction)
                continue

            if not verify_transaction(transaction):
                print("Transaction verification failed.")
                continue

            if float(transaction["transaction"]["sum"]) <= 0:
                continue

            if get_account_balance(transaction["transaction"]["from"], validated_transactions) - \
                        float(transaction["transaction"]["sum"]) < 0:
                print("Not enough balance")
                continue

            new_block_transactions.append(transaction)
            validated_transactions.append(transaction)
            new_blocks_in_loop = True

    if len(new_block_transactions) == 0:
        print("No correct transactions, halting block creation.")
        return False

    elif only_create_if_at_least is not False and len(new_block_transactions) < only_create_if_at_least:
        print("Not creating block because it has less than", only_create_if_at_least, "transactions.")
        return False

    print("Creating block with", len(new_block_transactions), "transactions")

    block_str, block_hash = create_block(curr_port, new_block_transactions, verifying_key)

    save(curr_port, block_str, folder_prefix="blocks_peer", text_hash=block_hash, ignore_hash_similarity_check=True)

    return block_hash


def verify_transaction(transaction_data):
    if type(transaction_data) == str:
        json_main = json.loads(transaction_data)
    else:
        json_main = transaction_data
    signature = json_main["signature"]
    transaction_json = json_main["transaction"]
    transaction_str = json_stable_stringify_python.stringify(json_main["transaction"]).encode()

    public_key_data = transaction_json["from"]

    if transaction_json["from"] == "0":
        return True

    signature = base64.b64decode(signature.encode())

    vk = VerifyingKey.from_string(base64.b64decode(public_key_data), curve=NIST384p)

    try:
        vk.verify(signature, transaction_str)
        return True
    except BadSignatureError:
        return False


def get_sk(port):
    path = os.path.abspath('.')
    sep = get_separator(path)
    folder_path = path + sep + "keys_peer" + str(port)

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    sk_path = folder_path + sep + "signing"
    vk_path = folder_path + sep + "verifying"

    if os.path.isfile(sk_path):
        with open(sk_path, "rb") as file:
            sk = SigningKey.from_string(base64.b64decode(file.read()), curve=NIST384p)

        with open(vk_path, "rb") as file:
            vk = VerifyingKey.from_string(base64.b64decode(file.read()), curve=NIST384p)

    else:
        sk = SigningKey.generate(curve=NIST384p)
        vk = sk.get_verifying_key()

        with open(sk_path, "wb") as file:
            file.write(base64.b64encode(sk.to_string()))

        with open(vk_path, "wb") as file:
            file.write(base64.b64encode(vk.to_string()))

    return sk, vk


def create_block_if_necessary(curr_port):
    _, vk = get_sk(curr_port)

    block_hash = create_block_from_transactions(curr_port, vk, only_create_if_at_least=5)
    if block_hash:
        print("New block with hash: ", block_hash, "created")
        broadcast(PORT, get_peers_from_conf(PORT), data_hash=block_hash, fail_if_exists=False, is_block=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', required=True, help='the TCP port to listen on')

    args = parser.parse_args()
    HOST, PORT = "127.0.0.1", int(args.port)

    # Create the server
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, MyRequestHandler)

    sk, vk = get_sk(PORT)

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
                block_hash = create_block_from_transactions(PORT, vk)
                if block_hash:
                    print("New block with hash: ", block_hash, "created")
                    broadcast(PORT, get_peers_from_conf(PORT), data_hash=block_hash, fail_if_exists=False, is_block=True)

            elif i.startswith("c "):
                PEER = i[2:]
                p_ip, p_port = PEER.split(":")
                p_port = int(p_port)
                add_self_to_another_peer(curr_port=PORT, peer=PEER)
                add_peer_to_list(curr_port=PORT, new_peer=PEER)

            elif i.startswith("t "):
                TEXT = i[2:]
                hash = make_transact(PORT, TEXT, sk, vk)
                if hash:
                    print("New transaction with hash: ", hash)
                    broadcast(PORT, get_peers_from_conf(PORT), data_hash=hash, fail_if_exists=False, is_transact=True)

                    create_block_if_necessary(PORT)

            elif i.startswith("v "):
                TEXT = i[2:]
                print(verify_transaction(read_file(PORT, TEXT, "transacts_peer")))

            elif i == "l":
                update_ledger(PORT, get_peers_from_conf(PORT))

            elif i == "p":
                peer_discovery(HOST, PORT)

            elif i == "exit":
                break

            elif i == "s":
                transactions_in_blocks = get_all_transactions_in_blocks(PORT, get_latest_block(PORT))
                accounts = set()
                for transact in transactions_in_blocks:
                    accounts.add(transact["transaction"]["from"])
                    accounts.add(transact["transaction"]["to"])

                print("\nBalances:")
                for account in accounts:
                    print(account, get_account_balance(account, transactions_in_blocks))
                print()

            print("Query finished.\n")
        except KeyboardInterrupt:
            break
