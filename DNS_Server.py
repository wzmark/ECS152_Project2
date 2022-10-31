
from socket import *
import bitstring





def create_flag():
    flags = {
        "QR":"0",
        "OPCODE":"0000",
        "Authoritative_Answer":"0",
        "TrunCation":"0",
        "Recursion_Desired":"1",
        "Recursion_Available": "0",
        "Z":"000",
        "RCODE":"0000"
        
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
    lenOfString = 0 #count the string length to the .
    hostname_split = hostname.split('.')
    temp_hostname = ""
    for string in hostname_split:
        lenOfString = len(string)
        temp_hostname += "0" + str(hex(lenOfString))[2:]
        for character in string:
            temp_hostname += str(hex(ord(character)))[2:]
        qname += temp_hostname
        temp_hostname = ""
        #qname += str(hex(ord(character)))[2:]
    qname += str("00")
    print(qname + "\n")
    qtype = "01"
    qclass  = "0x0001"
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
    #print(data)
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

def prase_response_message(message, queries):
    isFind_ip = False
    message = bitstring.BitArray(bytes = message)
    message = message.hex
    queries = queries.hex
    length_queries = len(queries)
    location_queries = message.find(queries)
    answer = message[length_queries + location_queries : len(message)]
    num_authority_rr = message[location_queries - 8 : location_queries - 4]
    num_authority_rr = int(num_authority_rr, 16)
    num_additional_rr = message[location_queries - 4 : location_queries]
    num_additional_rr = int(num_additional_rr, 16)
    num_rr = num_additional_rr + num_authority_rr
    num_answer = message[location_queries - 12 : location_queries - 8]
    num_answer = int(num_answer, 16)
    if num_answer != 0:
        isFind_ip = True
    answer_list = []
    ip_list = []
    start_location = 0
    for index in range(num_rr):
        name = answer[start_location : start_location + 4]
        start_location += 4
        type = answer[start_location : start_location + 4]
        start_location += 4
        class_ip = answer[start_location : start_location + 4]
        start_location += 4
        time_live = answer[start_location : start_location + 8]
        start_location += 8
        data_length = answer[start_location : start_location + 4]
        data_length = int(data_length, 16)
        start_location += 4
        ip_hex = answer[start_location : start_location + 2 * data_length]
        start_location += 2 * data_length
		
        ip_dec = ""
        for j in range(0, 8, 2):
            ip_dec = ip_dec + str(int(ip_hex[j : j + 2], 16))
            if(j + 2 != 8):
                ip_dec = ip_dec + "."
        if type == "0001":
            ip_list.append(ip_dec)
    response = message[location_queries : len(message)]
    return isFind_ip, ip_list, response

def find_DNS_IP(hostname, transaction_ip):
	root_ip = "198.41.0.4"
	print(root_ip)
	isFind_ip = False
	response = ""
	while not isFind_ip:
		data, queries = build_DNS_query(hostname, transaction_ip)
		message = send_DNS_packet(root_ip, data)
		ip_list, isFind_ip, response = prase_response_message(message, queries)
		
		root_ip = ip_list[0]
		print(root_ip)
	return response

def unpack_client_package(message):
    transaction_ip = ""
    hostname = ""
    message = bitstring.BitArray(bytes = message)
    message = message.hex
    
    transaction_ip = message[0 : 4]
    #24
    queries = message[24 : len(message)]
    location_end_hostname = queries.find("00")
    hostname = queries[0 : location_end_hostname]
    
    return transaction_ip, hostname

if __name__ == '__main__':
	
	response = ""
	client_ip = ""
	serverPort = 12000
	serverSocket = socket(AF_INET, SOCK_DGRAM)
	serverSocket.bind(('', serverPort))
	while True:
		message, clientAddress = serverSocket.recvfrom(2048)
		transaction_ip, hostname = unpack_client_package(message)
		response = find_DNS_IP(hostname, transaction_ip)
		serverSocket.sendto(response.encode(),clientAddress)
        
		