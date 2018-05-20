import socket
import struct
import hashlib
import os


def get_socket_to_listen(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(1024)
    return s


def get_sha1(arg):
    arg_sha1 = hashlib.sha1()
    arg_sha1.update(arg)
    arg_sha1 = arg_sha1.digest()
    return arg_sha1


def get_handshake_data(dict_sha1, peer_id):
    handshake_data = b""
    handshake_data += struct.pack("!B", 19)
    bittorrent_protocol = "BitTorrent protocol"
    for aso in list(bittorrent_protocol):
        handshake_data += struct.pack("c", aso.encode())
    handshake_data += struct.pack("!I", 0)
    handshake_data += struct.pack("!I", 0)
    handshake_data += dict_sha1
    handshake_data += peer_id
    return handshake_data


def byte_into_array_of_bits(byte):
    tmp_array = []
    for i in range(8):
        tmp_array.append(get_bit(byte, i))
    return tmp_array


def get_bit(byte, ind):
    tmp = 1
    tmp <<= (7-ind)
    tmp &= byte
    tmp >>= (7-ind)
    if tmp % 2 == 1:
        return 1
    return 0


def write_file(data, file_url, offset):
    try:
        f = open(file_url, "r+b")
    except IOError:
        f = open(file_url, "wb")
    f.seek(offset)
    f.write(data)
    f.close()
