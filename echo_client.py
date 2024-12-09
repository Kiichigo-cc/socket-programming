# Developed on Python 3.12.1

import socket

def main():
    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    server_address = 'localhost'
    server_port = 12345
    
    # Send echo to the server and receive the same response
    try:
        sock.connect((server_address, server_port))
        
        # User inputted message
        msg = False
        while msg == False:
            message = input("Enter message to echo ('exit' to close client): ")
            if message == 'exit':
                sock.close()
                exit("closed.")
            elif not message.strip():
                print("Please send a non-empty message.")
                continue
            else:
                msg = True
        
        # Send the whole message
        sock.sendall(message.encode())
        response = sock.recv(1024)
        print(f"Received from server: {response.decode('utf-8')}")

    finally:
        # Close the client socket
        sock.close()

if __name__ == '__main__':
    main()
