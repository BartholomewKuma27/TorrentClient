import ArgumentParser
from bencodepy import decode_from_file
import os
import requests
import hashlib
from bencodepy import encode
from bencodepy import decode
import helper
import socket
import struct
import binascii
import os
from threading import Thread
import threading

pieces_bitfield = None
chunk_size = 16384
chunk_number = 0
currently_used = None


def main():
    arg = ArgumentParser.ArgumentParser()
    arg.do_parsing()
    torrent_dict = decode_from_file(os.getcwd() + "\\" + arg.torrent_file_url)
    info_dict = torrent_dict[b"info"]
    piece_length = info_dict[b"piece length"]
    piece_count = int(len(info_dict[b"pieces"])/20)
    file_name = info_dict[b"name"]
    file_name = file_name.decode("utf-8")
    if b"files" in info_dict:
       print(info_dict[b"files"])
    global chunk_number
    chunk_number = int(piece_length/chunk_size)
    if piece_length % chunk_size != 0:
        chunk_number += 1
    global pieces_bitfield
    pieces_bitfield = [None] * piece_count
    global currently_used
    currently_used = [False] * piece_count
    dictionary_sha1 = helper.get_sha1(encode(info_dict))
    bencoded_info_dict = encode(info_dict)
    info_hash = helper.get_sha1(bencoded_info_dict)
    peer_id = os.urandom(20)
    listen_port = 2710
    file_length = info_dict[b"length"]
    payload = {"info_hash": info_hash, "peer_id": peer_id,
               "port": listen_port, "uploaded": 0, "downloaded": 0, "left": file_length}
    r = requests.get(torrent_dict[b"announce"], params=payload)
    response = decode(r.content)
    if b"failure reason" in response:
        return
    interval = response[b"interval"]
    peers = response[b"peers"]
    peers_list = []
    peer_num = len(peers)/6
    for elem in range(int(peer_num)):
        start_ind = 6 * elem
        peer_ip = socket.inet_ntoa(peers[start_ind:start_ind+4])
        peer_port = struct.unpack("!H", peers[start_ind+4:start_ind+6])[0]
        peers_list.append((peer_ip, peer_port))
    print(peers_list)
    for elem in peers_list:
        test_ip = elem[0]
        test_port = elem[1]
        cur_thread = Thread(target=do_for_each_peer,
                            args=(dictionary_sha1, test_ip, test_port, piece_length, info_dict, peer_id, file_length,
                                  file_name))
        # do_for_each_peer(dictionary_sha1, test_ip, test_port, piece_length, info_dict,peer_id)
        # print(cur_thread.name)
        cur_thread.start()


def do_for_each_peer(dictionary_sha1, test_ip, test_port, piece_length, info_dict, peer_id, file_length, file_name):
    temp_handshake = helper.get_handshake_data(dictionary_sha1, peer_id)
    tmp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp_sock.settimeout(5)
    try:
        tmp_sock.connect((test_ip, test_port))
        tmp_sock.send(temp_handshake)
        tmp_resp = tmp_sock.recv(1024)
        response_sha1 = tmp_resp[28:48]
        if response_sha1 != dictionary_sha1:
            return
        else:
            connect_to_peers(piece_length, tmp_resp, tmp_sock, info_dict[b"pieces"], file_length, file_name)
    except:
        return


def connect_to_peers(piece_length, tmp_resp, sock, concatenated_sha1_of_pieces, file_length, file_name):
    #print("gavida")
    bitfield_start = tmp_resp[68:]
    next_resp = sock.recv(1024)
    next_resp = bitfield_start + next_resp
    our_bitfield = get_bitfield(next_resp)
    peer_bitfield = []
    for elem in range(int(len(our_bitfield))):
        cur = helper.byte_into_array_of_bits(our_bitfield[elem])
        peer_bitfield += cur
    peer_bitfield = peer_bitfield[0:len(pieces_bitfield)]
    we_interested = False
    we_choking = True
    interested_data = b""
    interested_data += struct.pack("!I", 1)
    interested_data += struct.pack("!B", 2)
    sock.send(interested_data)
    we_interested = True
    recvd = sock.recv(512)
    if recvd[4] == 1:
        we_choking = False
    # print("we interested? - {}".format(we_interested))
    # print("we choking ? - {}".format(we_choking))
    # print(currently_used)
    while True:
        is_last_one = False
        piece_ind = get_next_piece_ind(peer_bitfield)
        if piece_ind is None:
            break
        print("avirchiet piece index n :{}".format(piece_ind))
        cur_piece_request = generate_piece_request(piece_ind, file_length, piece_length)
        sock.send(cur_piece_request)
        recv_data = b""
        while True:
            try:
                temp_data = sock.recv(4096)
                recv_data += temp_data
            except:
                break
        if piece_ind == len(pieces_bitfield) - 1:
            is_last_one = True
        cur_piece_data = get_full_piece_data(recv_data, is_last_one, file_length, piece_length)
        cur_piece_sha1 = helper.get_sha1(cur_piece_data)
        if cur_piece_sha1 == concatenated_sha1_of_pieces[piece_ind*20:piece_ind*20+20]:
            #print("gj dzma.pieceindexia {}".format(piece_ind))
            pieces_bitfield[piece_ind] = 1
            helper.write_file(cur_piece_data, os.getcwd() + "\\" + file_name, piece_ind*piece_length)
        else:
            currently_used[piece_ind] = False


def get_full_piece_data(recv_data, is_last_one, file_length, piece_length):
    offset = 0
    cur_chunk_number = chunk_number
    if is_last_one:
        last_piece_len = file_length % piece_length
        cur_chunk_number = int(last_piece_len / chunk_size)
        if last_piece_len % chunk_size != 0:
            cur_chunk_number += 1
    main_piece_data = [None]*cur_chunk_number
    for i in range(cur_chunk_number):
        msg_len = struct.unpack_from("!I", recv_data, offset)[0]
        offset += 4
        msg_type = struct.unpack_from("!B", recv_data, offset)[0]
        offset += 1
        piece_ind = struct.unpack_from("!I", recv_data, offset)[0]
        offset += 4
        begin_offset = struct.unpack_from("!I", recv_data, offset)[0]
        index_to_save = int(begin_offset / chunk_size)
        offset += 4
        data_len = msg_len - 9
        main_piece_data[index_to_save] = recv_data[offset:offset+data_len]
        offset += data_len
    data_to_return = b""
    for elem in main_piece_data:
        data_to_return += elem
    return data_to_return


def get_next_piece_ind(peer_bitfield):
    lock = threading.Lock()
    lock.acquire()
    for ind in range(len(peer_bitfield)):
        if (peer_bitfield[ind] == 1) and (pieces_bitfield[ind] is None and currently_used[ind] == False):
            #print("shemovida")
            currently_used[ind] = True
            lock.release()
            return ind
    return None


def generate_piece_request(piece_ind, file_length, piece_length):
    offset = 0
    cur_data = b""
    cur_chunk_number = chunk_number
    if piece_ind == len(pieces_bitfield)-1:
        last_piece_len = file_length % piece_length
        cur_chunk_number = int(last_piece_len / chunk_size)
        if last_piece_len % chunk_size != 0:
            cur_chunk_number += 1
        last_chunk_len = last_piece_len - (cur_chunk_number-1) * chunk_size
    for i in range(cur_chunk_number):
        cur_data += struct.pack("!I", 13)
        cur_data += struct.pack("!B", 6)
        cur_data += struct.pack("!I", piece_ind)
        cur_data += struct.pack("!I", offset)
        if piece_ind == len(pieces_bitfield)-1 and i == cur_chunk_number - 1:
            cur_data += struct.pack("!I", last_chunk_len)
            offset += last_chunk_len
        else:
            cur_data += struct.pack("!I", chunk_size)
            offset += chunk_size
    return cur_data


def get_bitfield(next_resp):
    our_bitfield = b""
    offset = 0
    while True:
        if offset == len(next_resp):
            break
        full_len = struct.unpack_from("!I", next_resp, offset)[0]
        offset += 4
        msg_type = struct.unpack_from("!B", next_resp, offset)[0]
        offset += 1
        msg_len = full_len - 1
        cur_msg_as_bytes = next_resp[offset:offset + msg_len]
        offset += msg_len
        # bitfield
        if msg_type == 5:
            our_bitfield += cur_msg_as_bytes
        # have
        elif msg_type == 4:
            offset += 9
            cur_msg_as_int = struct.unpack_from("!I", cur_msg_as_bytes, 0)[0]
            byte_num = int(cur_msg_as_int / 8)
            tmp_byte = 1
            off_index = 7 - (cur_msg_as_int-byte_num*8)
            new_byte = (tmp_byte << off_index) | our_bitfield[byte_num]
            new_byte_for_save = struct.pack("!B", new_byte)
            our_bitfield = our_bitfield[0:byte_num] + new_byte_for_save + our_bitfield[byte_num+1:]
    return our_bitfield

if __name__ == "__main__":
    main()
