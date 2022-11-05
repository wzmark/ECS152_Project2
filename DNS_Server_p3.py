import ipaddress
from socket import *
import time
import bitstring
from datetime import datetime


class hostname_record:
    name = ""
    type = ""
    answer_class = ""
    ttl = 0
    data_length = ""
    ip_address = ""
    time_stored = ""

    def __init__(self, name, type, answer_class, ttl, data_length, ip_address):
        self.name = name
        self.type = type
        self.ttl = ttl
        self.data_length = data_length
        self.ip_address = ip_address
        self.answer_class = answer_class
        self.time_stored = datetime.now()

    def is_expired(self):
        if int((datetime.now() - self.time_stored).seconds) < int(self.ttl, 16):
            return False
        else:
            return True

    def get_combined_record(self):
        return self.name + self.type + self.answer_class+ self.ttl + self.data_length + self.ip_address


class ip_cache:
    #hostname_dict = {"tmz.com": [hostname_record("c00c", "0001", "0001", "000002ee", "0004", "0de2e465"), hostname_record("c00c", "0001", "0001", "000002ee", "0004", "0de2e465")]}
    hostname_dict = {}
    def add_record(self, hostname, name, type, answer_class, ttl, data_length, ip_address):
        # header not include id
        if hostname not in self.hostname_dict.keys():
            self.hostname_dict[hostname] = []

        self.hostname_dict[hostname].append(hostname_record(name, type, answer_class, ttl, data_length, ip_address))

    def get_record(self, hostname):
        response = ""
        len_answer = 0
        for key, value in self.hostname_dict.items():
            if hostname == key:
                index = 0
                remove_list = []
                len_answer = 0
                for record in value:
                    if not record.is_expired():
                        response += record.get_combined_record()
                        len_answer += 1
                    else:
                        remove_list.append(index)
                    index += 1
                remove_list.reverse()
                for index in remove_list:
                    del self.hostname_dict[key][index]
        return response, len_answer
    
    
        


cache = ip_cache()


def create_flag():
    flags = {
        "QR": "0",
        "OPCODE": "0000",
        "Authoritative_Answer": "0",
        "TrunCation": "0",
        "Recursion_Desired": "1",
        "Recursion_Available": "0",
        "Z": "000",
        "RCODE": "0000"

    }
    result = "0b"
    for value in flags.values():
        result += value
    return result


def build_DNS_query(hostname, transaction_ip):
    data = None
    transaction_ID = transaction_ip
    flag = create_flag()
    QDCOUNT = 1
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0

    qname = ""
    lenOfString = 0  # count the string length to the .
    hostname_split = hostname.split('.')
    temp_hostname = ""
    for string in hostname_split:
        lenOfString = len(string)
        temp_hostname += "0" + str(hex(lenOfString))[2:]
        for character in string:
            temp_hostname += str(hex(ord(character)))[2:]
        qname += temp_hostname
        temp_hostname = ""
        # qname += str(hex(ord(character)))[2:]
    qname += str("00")
    qtype = "01"
    qclass = "0x0001"
    data = bitstring.pack("hex", transaction_ID)
    data += bitstring.pack("bin", flag)
    data += bitstring.pack("uintbe:16", QDCOUNT)
    data += bitstring.pack("uintbe:16", ANCOUNT)
    data += bitstring.pack("uintbe:16", NSCOUNT)
    data += bitstring.pack("uintbe:16", ARCOUNT)
    queries = ""
    queries += bitstring.pack("hex", qname)
    queries += bitstring.pack("uintbe:16", qtype)
    queries += bitstring.pack("hex", qclass)

    data += bitstring.pack("hex", qname)
    data += bitstring.pack("uintbe:16", qtype)
    data += bitstring.pack("hex", qclass)
    # print(data)
    return data, queries


def send_DNS_packet(root_ip, data):
    port = 53
    serverIP = root_ip
    client_socket = socket(AF_INET, SOCK_DGRAM)

    temp = data.tobytes()
    client_socket.sendto(data.tobytes(), (serverIP, port))
    modifiedMessage, serverAddress = client_socket.recvfrom(1024)
    client_socket.close()
    return modifiedMessage


def prase_response_message(message, queries, hostname):
    isFind_ip = False
    message = bitstring.BitArray(bytes=message)
    message = message.hex
    queries = queries.hex
    length_queries = len(queries)
    location_queries = message.find(queries)
    answer = message[length_queries + location_queries: len(message)]
    num_authority_rr = message[location_queries - 8: location_queries - 4]
    num_authority_rr = int(num_authority_rr, 16)
    num_additional_rr = message[location_queries - 4: location_queries]
    num_additional_rr = int(num_additional_rr, 16)
    num_rr = num_additional_rr + num_authority_rr
    num_answer = message[location_queries - 12: location_queries - 8]
    num_answer = int(num_answer, 16)
    if num_answer != 0:
        isFind_ip = True
    answer_list = []
    ip_list = []
    start_location = 0
    
    for index in range(num_rr + num_answer):
        name = answer[start_location: start_location + 4]
        start_location += 4
        type = answer[start_location: start_location + 4]
        start_location += 4
        class_ip = answer[start_location: start_location + 4]
        start_location += 4
        time_live = answer[start_location: start_location + 8]
        start_location += 8
        data_length = answer[start_location: start_location + 4]
        data_length_hex = answer[start_location: start_location + 4]
        data_length = int(data_length, 16)
        start_location += 4
        ip_hex = answer[start_location: start_location + 2 * data_length]
        start_location += 2 * data_length

        ip_dec = ""
        for j in range(0, 8, 2):
            ip_dec = ip_dec + str(int(ip_hex[j: j + 2], 16))
            if (j + 2 != 8):
                ip_dec = ip_dec + "."
        if type == "0001":
            ip_list.append(ip_dec)
            if isFind_ip:
                cache.add_record(hostname, name, type, class_ip, time_live, data_length_hex, ip_hex)
                print("hostname: " + str(hostname) + "with ttl: " + str(int(time_live, 16)) + "seconds")

    response = message
    return isFind_ip, ip_list, response


def find_DNS_IP(hostname, transaction_ip, root_dns):
    root_ip = root_dns
    
    isFind_ip = False
    response = ""
    message = ""
    isSuccess_find = True
    while not isFind_ip:
        data, queries = build_DNS_query(hostname, transaction_ip)
        message = send_DNS_packet(root_ip, data)
        isFind_ip, ip_list, response = prase_response_message(message, queries, hostname)
        if len(ip_list) > 0:
            
            root_ip = ip_list[0]
        else:
            if not isFind_ip:
                isSuccess_find = False
                print("do not return")
                break
                
        
    return message, isSuccess_find


def unpack_client_package(message):
    transaction_ip = ""
    hostname = ""
    message = bitstring.BitArray(bytes=message)
    message = message.hex

    transaction_ip = message[0: 4]
    # 24
    queries = message[24: len(message)]
    location_end_hostname = queries.find("00")

    hostname_hex = queries[0: location_end_hostname + 2]
    location_index = 2
    num_character = int(hostname_hex[0: 2], 16)
    substring_hostname = hostname_hex[2: location_index + num_character * 2]
    location_index += num_character * 2
    while num_character != 0:

        hostname += str(bytes.fromhex(substring_hostname).decode())
        num_character = int(hostname_hex[location_index: location_index + 2], 16)
        if num_character != 0:
            hostname += "."
        location_index += 2
        substring_hostname = hostname_hex[location_index: location_index + num_character * 2]
        location_index += num_character * 2

    return transaction_ip, hostname, message

def find_IP_Cache(hostname):
    response = cache.get_record(hostname)
    return response

def form_cache_response(header, len_answer, response):
    header = header[0 : 12] + str(bitstring.pack("uintbe:16", len_answer).hex) + header[16 : len(header)]
    response = header + response
    return response

    


if __name__ == '__main__':

    response = ""
    client_ip = ""
    serverPort = 65432
    serverSocket = socket(AF_INET, SOCK_DGRAM)
    serverSocket.bind(('', serverPort))
    while True:
        message, clientAddress = serverSocket.recvfrom(2048)
        print("message received")
        transaction_ip, hostname, header = unpack_client_package(message)
        response, len_answer = find_IP_Cache(hostname)
        if response == "":
            root_dns = {
                "a.root-servers.net": "198.41.0.4",
                "b.root-servers.net": "199.9.14.201", 
                "c.root-servers.net": "192.33.4.12", 
                "d.root-servers.net": "199.7.91.13",
                "e.root-servers.net": "192.203.230.10", 
                "f.root-servers.net": "192.5.5.241", 
                "g.root-servers.net": "192.112.36.4",
                "h.root-servers.net": "198.97.190.53", 
                "i.root-servers.net": "192.36.148.17", 
                "j.root-servers.net": "192.58.128.30", 
                "k.root-servers.net": "193.0.14.129", 
                "l.root-servers.net": "199.7.83.42",
                "m.root-servers.net": "202.12.27.33"
            }
            isSuccess = False
            for key, value in root_dns.items():
                start_time = datetime.now()
                response, isSuccess = find_DNS_IP(hostname, transaction_ip, value)
                end_time = datetime.now()
                print("hostname: " + hostname + " use microseconds of finding in dns " + str(key) +": " + str(int((end_time - start_time).microseconds)))
                if isSuccess:
                    break
            
            serverSocket.sendto(response, clientAddress)
                
        else:
            print("hostname: " + hostname + " from cache")
            response = form_cache_response(header, len_answer, response)
            response = bitstring.pack("hex", response)
            #print("hostname:" + hostname + " from cache")
            serverSocket.sendto(response.tobytes(), clientAddress)
            
