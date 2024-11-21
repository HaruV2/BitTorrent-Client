import select
import socket
import sys
import bencoding as benc
import argparse
import random
import time
import threading
import hashlib
import queue

#debian1.torrent
#debian-12.5.0-arm64-netinst.iso.torrent

# For debugging purposes
downloaded = set()
all_pices = set()
peer_list = {}

def check_hash(received_piece, index):
    # don't run the code if the received piece was empty. Issue is in the calling function
    pieces = decoded_torrent[b'info'][b'pieces']  
    expected_hash = pieces[20*index:20*index+20]
    received_hash = hashlib.sha1(received_piece).digest()
    return received_hash == expected_hash

# BITFIELD functionality
def get_piece_bit(bitfield: bytearray, i):
    byte = bitfield[i // 8]
    #find the bit within the byte
    return byte.__and__(2**(7 - (i % 8)))

# BITFIELD functionality
def set_piece_bit(bitfield: bytearray, i):
    byte = bitfield[i//8]
    byte = byte.__or__(2**(7 - (i % 8)))
    bitfield[i//8] = byte
    return

def create_handshake(peer_id):
    protocol_length = (19).to_bytes(1, "big")
    protocol_string = b'BitTorrent protocol'
    reserved_bytes = b'\x00' * 8
    info_hash = benc.get_info_hash_raw(decoded_torrent)
    handshake_info = protocol_length + protocol_string + reserved_bytes + info_hash + peer_id.encode('utf-8')
    return handshake_info
    
# initialize connection to peer, and start requesting pieces
def connect_to_peer(ip, port, peer_id):
    try:
        # Create a unique socket for each peer
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        try:
            s.connect((ip, port))
            #print(f"Successfully connected to {ip}:{port}")

            # Send handshake
            handshake_info = create_handshake(peer_id)

            s.sendall(handshake_info)
            response = s.recv(68)
            # ignore response
            while len(response) < 68:
                chunk = s.recv(68 - len(response))
                if not chunk:
                    return
                response += chunk


            if len(response) < 68:
                #print("Handshake failed: Incomplete response")
                s.close()
                return
        except socket.error as e:
            #print(f"Socket error during handshake: {e}")
            s.close()
            return

        # with peer_lock:
        #     peer_list[s.fileno()] = s
        # Receive and handle the bitfield
        bitfield = receive_bitfield(s)
        if wait_for_unchoke(s) != 1: # error unchoking, we'll never work successfully
            return
        send_interested_message(s)
        piece_length = benc.get_piece_length(decoded_torrent)

        run_client(s, piece_length, bitfield)
        return
    except socket.timeout:
        #print(f"Connection timed out for {ip}:{port}")
        return
    except socket.error as e:
        #print(f"Failed to connect to {ip}:{port}, error: {e}")
        return

def send_interested_message(sock):
    # Interested message format: length: 4 bytes + message ID: 1 byte
    msg_length = (1).to_bytes(4, "big")  
    msg_id = (2).to_bytes(1, "big")  # Message ID for "interested"
    interested_msg = msg_length + msg_id

    try:
        sock.sendall(interested_msg)
        #print("Sent interested message")
        return
    except socket.error as e:
        #print(f"Socket error while sending interested message: {e}")
        return

def wait_for_unchoke(sock):
    while True:
        sock.settimeout(None)
            # Read the message length and ID
        length_bytes = sock.recv(4)
        if not length_bytes:
            return -1 # couldn't receive anything
        msg_length = int.from_bytes(length_bytes, "big")
        msg_id = int.from_bytes(sock.recv(1), "big")

        if msg_id == 1:  # Message ID for "unchoke"
                #print("Received unchoke message")

            return 1
        elif(msg_id == 6):
            # print("got a REQUEST message")
            index = int.from_bytes(sock.recv(4), "big")
            begin = int.from_bytes(sock.recv(4), "big")
            length = int.from_bytes(sock.recv(4), "big")
            
            if index in downloaded:
                response_block = b''
                with file_lock:
                    with open(file_path, "r+b") as file:
                        file.seek((index) * piece_length + begin)  # Adjust offsets as needed
                        response_block = file.read(length)
                response_len = (9 + length).to_bytes(4, "big")
                response_index = index.to_bytes(4, "big")
                response_begin = begin.to_bytes(4, "big")
                
                packet = response_len + (7).to_bytes(1, "big") + response_index + response_begin + response_block
                sock.sendall(packet)     
        if msg_length == 0:
            continue
            # Skip over any other message payload
        sock.recv(msg_length - 1)


def receive_bitfield(sock):
    try:
        # Read the length and message ID
        length_bytes = sock.recv(4)
        if not length_bytes:
            #print("No data received.")
            return b""
        #pop off any keep-alive messages
        if length_bytes == 0:
            receive_bitfield(sock) 
        msg_length = int.from_bytes(length_bytes, "big")
        msg_id = int.from_bytes(sock.recv(1), "big")

        # Check if it's a "bitfield" message (ID 5)
        if msg_id == 5:
            bitfield_data = sock.recv(msg_length - 1)
            #print(f"Received bitfield of length {len(bitfield_data)}")
            return bitfield_data            
        else:
            #print(f"Received unexpected message ID: {msg_id}")
            sock.recv(msg_length - 1)  # Skip the remaining message payload
            return b""
    except socket.error as e:
        #print(f"Socket error while receiving bitfield: {e}")
        return b""

def download_piece(sock, index):
    sock.settimeout(5)
    #send out requests totaling to the entire piece
    # without exceeding the limit of bytes that we can request in each individual request message
    if index == num_pieces - 1:
        if (benc.get_length(decoded_torrent) % benc.get_piece_length(decoded_torrent)) % 16384 == 0:
             num_blocks = piece_length // 16384
        else:
            num_blocks = ((benc.get_length(decoded_torrent) % benc.get_piece_length(decoded_torrent)) // 16384) + 1 
            #print(num_blocks)
        #print(num_blocks)
    else:
        num_blocks = piece_length // 16384

    chunk_arr = [b""] * num_blocks
    bytes_left = (benc.get_length(decoded_torrent) % piece_length)
    for i in range(0,num_blocks):
        
        request_msg_length = (13).to_bytes(4, "big")  # 13 bytes total excluding this length field
        request_msg_id = (6).to_bytes(1, "big")  # ID for "request" message
        length_bytes = 16384
        index_bytes = index.to_bytes(4, "big")
        begin_bytes = (block_length*i).to_bytes(4, "big")
        if index == benc.get_number_pieces(decoded_torrent) - 1 and not (num_blocks == piece_length // 16384):
            if bytes_left > 16384:
                bytes_left -= 16384
                length_bytes = block_length.to_bytes(4, "big")
            else:
                length_bytes = bytes_left.to_bytes(4, "big")
        else:
            length_bytes = block_length.to_bytes(4, "big")
        request_msg = request_msg_length + request_msg_id + index_bytes + begin_bytes + length_bytes
            
        try:
            sock.sendall(request_msg)
            #print(f"{sock} Requested piece {index}, offset {offset}, length {block_length}")
        except socket.error as e:
            return b""
    received = 0

    # keep receiving until we've gotten the entire piece back
    while received != num_blocks:
        
        try:
            msg_len = sock.recv(4)
            msg_length = int.from_bytes(msg_len, "big")

            if(msg_length != 0): # wouldn't want to process a keep alive message
                msg_id = int.from_bytes(sock.recv(1), "big")

                # unpack the msg_id             
                if(msg_id == 7):
                    #take payload out of buffer and put it into the array
                    
                    block_data = b""
                    received_index = int.from_bytes(sock.recv(4), "big")
                    received_offset = int.from_bytes(sock.recv(4), "big")
                    # receive data
                    block_data = sock.recv(msg_length - 9)  # Remaining bytes after headers
                    # data may not pull out of buffer all at once, keep recving until we have desired length
                   
                    while len(block_data) < (msg_length - 9):
                        chunk = sock.recv((msg_length - 9) - len(block_data))
                        block_data += chunk

                    # "chunks" are the partitioning of pieces into the max allowable request size
                    # determine where to put the chunk received with respect to the piece
                    # chunk_arr represents the entire piece
                    chunk_index = int(received_offset / block_length)
                    if chunk_index < num_blocks and chunk_index >= 0 and received_index == index:
                        if chunk_arr[chunk_index] == b"":
                            chunk_arr[int(received_offset/block_length)] = block_data
                            received += 1
                        # else:
                            # print("repeat chunk")
                    else:
                        # print(f"wrong index I got {received_index} I wanted {index}")
                        return b""
                elif(msg_id == 4):
                    # print("got a HAVE message")
                    sock.recv(msg_length - 1)
                elif(msg_id == 6):
                    # print("got a REQUEST message")
                    index = int.from_bytes(sock.recv(4), "big")
                    begin = int.from_bytes(sock.recv(4), "big")
                    length = int.from_bytes(sock.recv(4), "big")
                    
                    if index in downloaded:
                        response_block = b''
                        with file_lock:
                            with open(file_path, "r+b") as file:
                                file.seek((index) * piece_length + begin)  # Adjust offsets as needed
                                response_block = file.read(length)
                        response_len = (9 + length).to_bytes(4, "big")
                        response_index = index.to_bytes(4, "big")
                        response_begin = begin.to_bytes(4, "big")
                        
                        packet = response_len + (7).to_bytes(1, "big") + response_index + response_begin + response_block
                        sock.sendall(packet)                    
                    
                elif(msg_id == 0): # we got choked :(
                    try:
                        wait_for_unchoke(sock)
                        send_interested_message(sock)
                    except socket.error as e:
                        raise e
                else:
                    sock.recv(msg_length - 1) # pop off any other message
            else:
                # would not expect a keep alive, would timeout before then
                raise ValueError
        except socket.error as e:
            raise e
        except ValueError as v:
            raise v
    return chunk_arr


def is_piece_available(index, bitfield):
    byte_index = index // 8 
    bit_index = index % 8   
    return (bitfield[byte_index] & (1 << (7 - bit_index))) != 0

def dedicated_seeding(peer_id, port, file_path, piece_length):
    print("Starting Dedicated Seeding")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:  
        s.bind(('', port))
    except OSError as err:
        print(f"Binding Failure : {err}")
        sys.exit(1)
    
    s.listen(socket.SOMAXCONN)
    
    while True:
        peersock, client_addr = s.accept()
        plen = int.from_bytes(peersock.recv(1), "big")
        pstr = peersock.recv(plen)
        peersock.recv(8)
        info = peersock.recv(20) # Hash of Metainfo file
        peersock.recv(20) # peer_id
        if pstr !=  b'BitTorrent protocol' and info != benc.get_info_hash_raw(decoded_torrent):
            peersock.close()
        else:
            handshake_info = create_handshake(peer_id)
            peersock.sendall(handshake_info)
            
            # send the bitfield
            bitfield_msg = (bitfield_len + 1).to_bytes(4, "big") + (5).to_bytes(1, "big") + local_bitfield
            peersock.sendall(bitfield_msg)

            # unchoke the peer
            unchoke_msg = (5).to_bytes(4, "big") + (1).to_bytes(1, "big")
            peersock.sendall(unchoke_msg)
            
            thread = threading.Thread(target = handle_seeding, args = (peersock, file_path, piece_length), daemon = True)
            thread.start()

def create_bitfield():
    return bytearray(num_pieces//8 + (0 if num_pieces % 8 == 0 else 1))

def handle_seeding(sock, file_path, piece_length):
    try:
        while True:
            msg_length = int.from_bytes(sock.recv(4), "big")
            
            if(msg_length != 0): 
                msg_id = int.from_bytes(sock.recv(1), "big")
                
                if msg_id == 6:
                    index = int.from_bytes(sock.recv(4), "big")
                    begin = int.from_bytes(sock.recv(4), "big")
                    length = int.from_bytes(sock.recv(4), "big")
                    
                    if index in downloaded:
                        response_block = b''
                        with file_lock:
                            with open(file_path, "r+b") as file:
                                file.seek((index) * piece_length + begin)  # Adjust offsets as needed
                                response_block = file.read(length)
                                file.close()
                        response_len = (9 + length).to_bytes(4, "big")
                        response_index = index.to_bytes(4, "big")
                        response_begin = begin.to_bytes(4, "big")
                        
                        packet = response_len + (7).to_bytes(1, "big") + response_index + response_begin + response_block
                        sock.sendall(packet)
                    #     print("REQUESTED: Piece Sent")
                    # else:
                    #     print("Do not have requested piece")
                else:
                    sock.recv(msg_length - 1) # Do we care about any other message type
    except socket.error:
        sock.close()
        return
                
# repeatedly process pieces
def run_client(sock, piece_length, bitfield):
    if bitfield == b"":
            return
    # process pieces
    while True:
        available_pices = all_pices - downloaded
        if available_pices:  
            index = random.choice(list(available_pices))

            # check if the piece we've popped off is in the client's possession
            byte_index = index // 8 
            bit_index = index % 8   
            if (bitfield[byte_index] & (1 << (7 - bit_index))) == 0:
                # print("not in bitfield")
                continue
            else: 
                arr = b""
                try:
                    chunk = download_piece(sock, index)
                except Exception:
                    return
                            
                if chunk == b"" or None:
                    continue
                for c in chunk:
                    arr += c
                isHashCorrect = check_hash(arr, index)
                if isHashCorrect:
                    # write to our output file if hashes check out
                    with file_lock:
                        with open(file_path, "r+b") as file:
                            file.seek((index) * piece_length)  # Adjust offsets as needed
                            file.write(arr)
                            file.close()
                    with lock:
                        downloaded.add(index)
                    with bitfield_lock:
                        set_piece_bit(local_bitfield, index)      
                    # send have message

                    # with peer_lock:
                    #     for socket in peer_list.values():
                    #         msg_len = (5).to_bytes(4, "big")
                    #         msg_id = (4).to_bytes(1, "big")
                    #         msg_index = index.to_bytes(4, "big")
                    #         packet = msg_len + msg_id + msg_index
                    #         socket.send(packet)
                # for debugging  
                # else:
                #     # (check_hash didn't work, this could tie back to the return of download_piece)
                #     print("Hashing Failed")
                #     print(len(chunk))
        else:
            return # if everything is processed
        # end processing of piece
    # end while loop
        

def arg_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, required=True, help='The port to be used for the BitTorrent')
    parser.add_argument('-f', '--file', type=str, required=True, help='File to be downloaded')
    parser.add_argument('-c', '--compact', type=int, required=False, help='Compact Message', default = 1)
    parser.add_argument('-s', "--seed_only", type=int, required=False, help='when nonzero, skip peer connections and go straight to seeding', default=0)
    parser.add_argument('-jp', "--join_port", type=int, required=False, help='port to join to (via manual connection)',default=0)
    args = parser.parse_args()
    
    if args.port < 6881 or args.port > 6889:
        parser.error("Invalid Port Value. Port must be between 6881 or 6889")
        exit(1)
        
    file = benc.decode_torrent(args.file)
    return args.port, file, args.compact, args
    
def hash_downloaded(file_path, piece_length, file_lock):
    hash = hashlib.sha512()
    with file_lock:
        with open(file_path, 'rb', buffering=0) as file:
            while True:
                chunk = file.read(piece_length)
                if not chunk:
                    break
                hash.update(chunk)
            file.close()
            
    hash = hash.hexdigest()
    print(f"File: {file_path}")
    if file_path.startswith("debian-12.5.0-arm64"):
        print(f"Original SHA512 Hash:\n14c2ca243ee7f6e447cc4466296d974ee36645c06d72043236c3fbea78f1948d3af88d65139105a475288f270e4b636e6885143d01bdf69462620d1825e470ae")
    else: # Debian-1
        print(f"Original SHA512 Hash:\n0262488ce2cec6d95a6c9002cfba8b81ac0d1c29fe7993aa5af30f81cecad3eb66558b9d8689a86b57bf12b8cbeab1e11d128a53356b288d48e339bb003dace5")
    print(f"Our SHA512 Hash:\n{hash}")
    
if __name__ == "__main__":
    port, decoded_torrent, compact, args = arg_parse()
    
    start = time.time()
    
    #Using Transmission peer id format I dont think it matters much
    lock = threading.Lock()
    file_lock = threading.Lock()
    threads: list[threading.Thread] = []
    bitfield_lock = threading.Lock()
    # peer_lock = threading.Lock()

    piece_length = benc.get_piece_length(decoded_torrent)
    block_length =  16384 # =2^14 = 16kb
    num_blocks = piece_length // block_length #  Note that both arguments will be a power of 2
    file_path = benc.get_file_name(decoded_torrent)
    if args.join_port != 0:
        file_path += f"_{args.port}"
    num_pieces = benc.get_number_pieces(decoded_torrent)
    indices = list(range(benc.get_number_pieces(decoded_torrent)))
    local_bitfield= create_bitfield()
    bitfield_len = num_pieces//8 + (0 if num_pieces % 8 == 0 else 1)

    random.shuffle(indices)

    for index in indices:
        all_pices.add(index)
    
    prefix = '-TR417-'
    random_HEX = ''.join(random.choices('0123456789ABCDEF', k=13))
    my_id = prefix + random_HEX

    if args.seed_only == 0:
        with open(file_path, "wb") as f:
            f.truncate(benc.get_length(decoded_torrent))
            f.close()
        #print(benc.get_length(decoded_torrent))
        peer_ip_port_tuple = [("127.0.0.1", args.join_port)]
        if args.join_port == 0:
            peer_ip_port_tuple = benc.get_ip_port_tupple_from_tracker(decoded_torrent, my_id, port, compact)
        for ip, port in peer_ip_port_tuple:
            thread = threading.Thread(target=connect_to_peer, args=(ip, port, my_id), daemon=False)
            threads.append(thread)
            thread.start()
        
        while len(downloaded) < num_pieces:
            time.sleep(2)
            print(f"Downloaded {len(downloaded)} out of {benc.get_number_pieces(decoded_torrent)} pieces. Time Lapsed: {time.time() - start} seconds.")
            # get more peers if necessary
            # first, purge dead threads
            # DO NOT CONNECT TO MORE PEERS IF WE WANT TO DO MANUAL CONNECTION
            if args.join_port == 0:
                for thread in threads:
                    if not thread.is_alive():
                        threads.remove(thread)

                if len(threads) < 15:
                    peer_ip_port_tuple = benc.get_ip_port_tupple_from_tracker(decoded_torrent, my_id, port, compact)
                    for ip, port in peer_ip_port_tuple:
                        thread = threading.Thread(target=connect_to_peer, args=(ip, port, my_id), daemon=True)
                        threads.append(thread)
                        thread.start()
            continue
            # uncomment to see what peice gets stuck
            #if len(all_pices - downloaded) < 10:
                #print(all_pices - downloaded)
        print(f"{file_path} finished downloading all {num_pieces} pieces!")
        # print(f"Your file is in {file_path}")
        # print(f"You downloaded {num_pieces} pieces!")
        print(f"And there are {len(list(set(downloaded)))} unique pieces")
        print(f"Time Total Taken: {time.time() - start} seconds")
        hash_downloaded(file_path, piece_length, file_lock)
    else:
        for i in range(0, bitfield_len):
            local_bitfield[i] = 255
        downloaded = set(indices)

    dedicated_seeding(my_id, args.port, file_path, piece_length)
