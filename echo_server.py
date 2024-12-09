# Developed on Python 3.12.1

import socket

def main():
    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind the server socket to a specific address and port
    server_address = 'localhost'
    server_port = 12345
    server_socket.bind((server_address, server_port))
    server_socket.settimeout(1)
    
    # Listen for incoming connections
    server_socket.listen(5)
    print(f"Server is listening on {server_address}...")
    
    try:
        while True:
            # Accept a connection from a client
            try:
                client_socket, client_address = server_socket.accept()
                print(f"Accepted connection from {client_address}.")
                
                # Receive message from the client and send it back
                message = client_socket.recv(1024)
                while message:
                    print(f"Received message: {message.decode()}. Echoing back to client.")
                    client_socket.send(message)
                    message = client_socket.recv(1024)
                    # Close the client socket
                    client_socket.close()
            except socket.timeout:
                pass
    except KeyboardInterrupt:
        print("Server shutting down.")
        
    finally:
        server_socket.close()
        print("Server socket closed.")

if __name__ == '__main__':
    main()
