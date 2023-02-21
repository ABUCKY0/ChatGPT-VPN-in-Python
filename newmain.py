import os
import select
import socket
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def start_vpn_server(listen_address, port, subnet_address, subnet_mask, key):
    subnet_address = "10.0.0.1".encode(); server_vpn_address = subnet_address + struct.pack(">I", 1)
    clients = {}

    # Create the VPN socket and start listening for client connections
    vpn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    vpn_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    vpn_socket.bind((listen_address, port))
    vpn_socket.listen(5)

    inputs = [vpn_socket]
    outputs = []

    while inputs:
        # Wait for a socket to become ready for I/O
        readable, writable, exceptional = select.select(inputs, outputs, inputs)

        for sock in readable:
            if sock is vpn_socket:
                # Handle a new client connection
                client_socket, client_address = sock.accept()
                print("New client connected: {}".format(client_address))

                # Assign the next available VPN address to the client
                client_vpn_address = subnet_address + struct.pack(">I", len(clients) + 2)
                clients[client_socket] = {"address": client_address, "vpn_address": client_vpn_address}

                # Add the client socket to the input list
                inputs.append(client_socket)
            else:
                # Handle data received from a client
                data = sock.recv(1024)
                if data:
                    print("Received data from client: {}".format(clients[sock]["address"]))

                    # Encrypt the data and send it over the VPN socket
                    iv = os.urandom(16)
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                    encryptor = cipher.encryptor()
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(data) + padder.finalize()
                    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

                    vpn_packet = clients[sock]["vpn_address"] + server_vpn_address + iv + encrypted_data
                    vpn_socket.send(vpn_packet)
                else:
                    # Remove the client socket from the input and output lists
                    print("Client disconnected: {}".format(clients[sock]["address"]))
                    inputs.remove(sock)
                    if sock in outputs:
                        outputs.remove(sock)
                    sock.close()
                    del clients[sock]

        for sock in exceptional:
            # Handle exceptional condition
            print("Handling exceptional condition for socket: {}".format(sock.getpeername()))
            inputs.remove(sock)
            if sock in outputs:
                outputs.remove(sock)
            sock.close()
            del clients[sock]

        # Handle data received on the VPN socket
        if vpn_socket in readable:
            if sock is vpn_socket:
				    # Handle a new client connection
				    client_socket, client_address = sock.accept()
				    print("New client connected: {}".format(client_address))
				
				    # Assign the next available VPN address to the client
				    client_vpn_address = subnet_address + struct.pack(">I", len(clients) + 2)
				    clients[client_socket] = {"address": client_address, "vpn_address": client_vpn_address}
				
				    # Add the client socket to the input list
				    inputs.append(client_socket)
				else:
				    # Handle data received from a client
				    data = sock.recv(1024)
				    if data:
				        print("Received data from client: {}".format(clients[sock]["address"]))
				
				        # Encrypt the data and send it over the VPN socket
				        iv = os.urandom(16)
				        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
				        encryptor = cipher.encryptor()
				        padder = padding.PKCS7(128).padder()
				        padded_data = padder.update(data) + padder.finalize()
				        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
				
				        vpn_packet = clients[sock]["vpn_address"] + server_vpn_address + iv + encrypted_data
				        for output in outputs:
				            output.send(vpn_packet)
				    else:
				        # Remove the client socket from the input and output lists
				        print("Client disconnected: {}".format(clients[sock]["address"]))
				        inputs.remove(sock)
				        if sock in outputs:
				            outputs.remove(sock)
				        sock.close()
				        del clients[sock]
				
				            if vpn_packet:
				                print("Received data from VPN socket")
				
				                # Decrypt the data and send it to the appropriate client socket
				                client_vpn_address = vpn_packet[:4]
				                iv = vpn_packet[8:24]
				                encrypted_data = vpn_packet[24:]
				
				                for client_sock in clients:
				                    if clients[client_sock]["vpn_address"] == client_vpn_address:
				                        print("Sending data to client: {}".format(clients[client_sock]["address"]))
				
				                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
				                        decryptor = cipher.decryptor()
				                        unpadder = padding.PKCS7(128).unpadder()
				                        decrypted_data = decryptor.update(encrypted_data) + decryptor
				
				                    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
				
				                    client_sock.send(unpadded_data)
				                    break
				        else:
				            # VPN socket has been closed, exit the loop
				            break

start_vpn_server("0.0.0.0", 80, "10.0.0.1","255.255.255.255", "hellow")