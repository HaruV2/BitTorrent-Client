import hashlib
import bencodepy
import socket
import urllib.parse
import random
import string

def decode_torrent(file_path):
    f = open(file_path, "rb")
    try:
        torrent_data = f.read()
        decoded = bencodepy.decode(torrent_data)
        return decoded
    except:
        print("Parsing Failed. Invalid File")
        exit(1)
    finally:
        f.close()
        
#just for testing
def print_torrent_info(decoded_torrent):    
    #Print announce url and file info
    print("Announce URL:", decoded_torrent.get(b'announce').decode('utf-8'))
    info = decoded_torrent.get(b'info')
    print("File:", info[b'name'].decode('utf-8'))
    print(info[b'length'], "bytes")

def get_tracker_url(decoded_torrent):
    return decoded_torrent.get(b'announce').decode('utf-8')

def get_file_name(decoded_torrent):
    info = decoded_torrent.get(b'info')
    return info[b'name'].decode('utf-8')

def get_info_hash(decoded_torrent):
    info = decoded_torrent.get(b'info')
    info_bc = bencodepy.encode(info)
    return hashlib.sha1(info_bc).hexdigest()

def get_piece_length(decoded_torrent):
    info = decoded_torrent[b'info']
    return info[b'piece length']

def get_number_pieces(decoded_torrent):
    info = decoded_torrent.get(b'info')
    pieces = info.get(b'pieces')
    number_of_pieces = len(pieces) // 20
    
    return number_of_pieces

def get_info_hash_raw(decoded_torrent):
    info = decoded_torrent.get(b'info')
    info_bc = bencodepy.encode(info)
    return hashlib.sha1(info_bc).digest()

def get_length(decoded_torrent):
    info = decoded_torrent.get(b'info')
    return info[b'length']

def get_piece_hashes(decoded_torrent):
    info = decoded_torrent.get(b'info')
    return info.get(b"pieces").hex()

def map_pieces_to_hashes(decoded_torrent):
    info = decoded_torrent.get(b'info')
    pieces = info.get(b"pieces")
   
    piece_length = 20  # Each SHA-1 hash is 20 bytes long
    num_pieces = len(pieces) // piece_length
    piece_hash_mapping = {}

    for i in range(num_pieces):
        # Extract the hash for the current index
        piece_hash = pieces[i * piece_length: (i + 1) * piece_length]
        # Map the 1-based index to the corresponding hash
        piece_hash_mapping[i + 1] = piece_hash.hex()  # Optionally, use `.hex()` to convert to string

    return piece_hash_mapping


def get_ip_port_tupple_from_tracker(decoded_torrent, peer_id, port, compact):

    query_params = {
        'info_hash': get_info_hash_raw(decoded_torrent),
        'peer_id': peer_id,
        'port': port,
        'uploaded': 0,
        'downloaded': 0,
        'left': get_length(decoded_torrent),
        'compact': compact
    }
    
    # URL encode the parameters
    query_string = urllib.parse.urlencode(query_params)
    
    # Parse the announce URL
    announce_url = get_tracker_url(decoded_torrent)
    parsed_url = urllib.parse.urlparse(announce_url)
    hostname = parsed_url.hostname
    port = parsed_url.port 
    path = parsed_url.path
    
    request_path = urllib.parse.urljoin(path, '?' + query_string)
    
    # Create the HTTP request string
    request = "GET " + request_path + " HTTP/1.0\r\nHost: " + hostname + "\r\n\r\n"

    
    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    sock.connect((hostname, port))
    
    sock.sendall(request.encode('utf-8'))
        
    response = b""
    while True:
        part = sock.recv(1024)
        if not part:
            break
        response += part
    
    sock.close()
        
    # chop off the headers
    headers_end = response.find(b'\r\n\r\n') + 4
    body = response[headers_end:]
    #decode the response
    decoded_response = bencodepy.decode(body)
    peers = decoded_response[b'peers']
    
    # Extract IP addresses
    ip_port_list = []

    # get the peers in 6 byte chunks
    for i in range(0, len(peers), 6):
        ip_bytes = peers[i:i+4]
        port_bytes = peers[i+4:i+6]
        
        ip_byte_arr = []
        for byte in ip_bytes:
            ip_byte_arr.append(str(byte))
        ip = ".".join(ip_byte_arr)

        port = int.from_bytes(port_bytes, byteorder='big')

        ip_port_list.append((ip, port))
    #print(ip_port_list)
    return ip_port_list


