import socket
import select

def start_vpn_server(host, port, net_addr, net_mask, key):
    # Create a TCP socket and bind it to the specified host and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"VPN server listening on {host}:{port}")

    # Create a dictionary to store the connected clients
    clients = {}

    # Create a UDP socket to send and receive VPN traffic
    vpn_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Create a dictionary to store the VPN address for each client
    vpn_addresses = {}

    # Main loop to accept new client connections and process VPN traffic
    while True:
        # Use select to wait for data to be received on any of the sockets
        read_sockets, write_sockets, error_sockets = select.select([server_socket, vpn_socket] + list(clients.keys()), [], [])

        # Process data received on each socket
        for sock in read_sockets:
            # Handle new client connections
            if sock == server_socket:
                client_socket, client_address = server_socket.accept()
                print(f"New client connected: {client_address}")
                clients[client_socket] = client_address
            # Handle data received from a client
            elif sock in clients:
                data = sock.recv(1024)
                if data:
                    # Encrypt the data and send it over the VPN socket
                    client_address = clients[sock]
                    vpn_address = vpn_addresses.get(client_address)
                    if vpn_address:
                        encrypted_data = encrypt(key, data)
                        vpn_socket.sendto(encrypted_data, (vpn_address, 0))
                    else:
                        print(f"Client {client_address} has no assigned VPN address")
                else:
                    # If no data is received, remove the client from the list of connected clients
                    print(f"Client disconnected: {clients[sock]}")
                    vpn_address = vpn_addresses.pop(clients[sock], None)
                    clients.pop(sock)
                    sock.close()
            # Handle data received on the VPN socket
            elif sock == vpn_socket:
                encrypted_data, address = sock.recvfrom(1024)
                # Decrypt the data and send it to the correct client socket
                decrypted_data = decrypt(key, encrypted_data)
                client_socket = None
                for sock, address in clients.items():
                    if vpn_addresses.get(address) == address[0]:
                        client_socket = sock
                        break
                if client_socket:
                    client_socket.send(decrypted_data)
                else:
                    print(f"No client found for VPN address {address}")
            # Handle unexpected socket errors
            else:
                print(f"Error on socket: {sock.getpeername()} {error}")
                clients.pop(sock)
                sock.close()

        # Assign a VPN address to any connected client that doesn't have one yet
        for sock, address in clients.items():
            if not vpn_addresses.get(address):
                vpn_address = assign_vpn_address(net_addr, net_mask, vpn_addresses)
                vpn_addresses[address] = vpn_address
                print(f"Assigned VPN address {vpn_address} to client {address}")

start_vpn_server("0.0.0.0", 80, "1.1.1.1", "255.255.255.0", "hellomommy")