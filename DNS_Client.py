from pkgutil import ModuleInfo
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
    


def build_DNS_query(hostname):
    data = None
    transaction_ID = "0x1a2b"
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
        
    
    

def send_DNS_packet(data):
    port = 53
    serverIP = "169.237.229.88"
    client_socket = socket(AF_INET, SOCK_DGRAM)

    temp = data.tobytes()
    client_socket.sendto(data.tobytes(), (serverIP, port))
    modifiedMessage, serverAddress = client_socket.recvfrom(1024)
    client_socket.close()
    return modifiedMessage

def prase_response_message(message, queries):
    message = bitstring.BitArray(bytes = message)
    message = message.hex
    queries = queries.hex
    length_queries = len(queries)
    location_queries = message.find(queries)
    answer = message[length_queries + location_queries : len(message)]
    num_answer = message[location_queries - 12 : location_queries - 8]
    num_answer = int(num_answer)
    answer_list = []
    ip_list = []
    for index in range(num_answer):     
        answer_list.append(answer[int(len(answer) / num_answer * index) : int(len(answer) / num_answer * (index + 1))])
        ip_hex = answer_list[index][len(answer_list[index]) - 8:len(answer_list[index])]
        ip_dec = ""
        for j in range(0, 8, 2):
            ip_dec = ip_dec + str(int(ip_hex[j : j + 2], 16))
            if(j + 2 != 8):
                ip_dec = ip_dec + "."
        ip_list.append(ip_dec)
    return ip_list

def send_HTTP_request(ip_list):
    ip = ip_list[0]
    port = 80
    client = socket(AF_INET, SOCK_STREAM)  
    client.connect((ip,port))  
    request = ""
    request = "GET / HTTP/1.1\r\nHost:%s\r\nConnection: close\r\nUser-agent: Mozilla/5.0\r\n\r\n" % ip
    client.send(request.encode())  
    
    # receive some data 
    response = client.recv(4096)  
    http_response = repr(response)
    http_response_len = len(http_response)




if __name__ == '__main__':
    hostname = "tmz.com"
    port = 53
    #socket = socket.socket()
    data, queries = build_DNS_query(hostname)
    message = send_DNS_packet(data)
    ip_list = prase_response_message(message, queries)
    send_HTTP_request(ip_list)
    
    
    