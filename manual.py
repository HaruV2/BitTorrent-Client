import socket             
import main as m
import random
import bencoding as benc
import threading
import time

downloaded = set()
block_length = 16384

start = time.time()
prefix = '-TR2940-'
random_HEX = ''.join(random.choices('0123456789ABCDEF', k=12))
my_id = prefix + random_HEX

ip = '127.0.0.1'
port = 6882
decoded_torrent = m.decoded_torrent
num_pieces = benc.get_number_pieces(decoded_torrent)
file_path = benc.get_file_name(decoded_torrent)


thread = threading.Thread(target=m.connect_to_peer, args=(ip, port, my_id), daemon=True)

while len(downloaded) < num_pieces:
    time.sleep(2)
    print(f"Downloaded {len(downloaded)} out of {benc.get_number_pieces(decoded_torrent)} pieces. Time Lapsed: {time.time() - start}")
    continue
print(f"{file_path} finished downloading!")
print(f"Your file is in {file_path}")
print(f"You downloaded {num_pieces} pieces!")
print(f"And there are {len(list(set(downloaded)))} unique pieces")
m.hash_downloaded(file_path)