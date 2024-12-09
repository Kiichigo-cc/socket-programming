# Developed on Python 3.12.1
# Please check requirements.txt for package requirements.

import os
import socket
import struct
import threading
import time
import zlib
import random
import string
import requests
import ntplib
import dns.resolver
import dns.exception
from prompt_toolkit import PromptSession    # Threads
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.patch_stdout import patch_stdout
from socket import gaierror
from time import ctime
from typing import Tuple, Optional, Any

# Service check functions

# Check custom TCP echo server status
def check_custom_tcp_echo_server(server_address: str, port: int, echo_message: str = "Hello World!") -> Tuple[bool, str]:
    """
    Checks if the custom TCP echo server is up.

    Args:
    server_address (str): The address of the server.
    port (int): The port number that the server is listening on.
    echo_message (str): A message to send to the server for echo testing.

    Returns:
    Tuple[bool, str]: A tuple of the server status and the message returned.
    """
    try:
        # Create a socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            
            # Connect to the server
            client_socket.connect((server_address, port))

            # Send server the message
            client_socket.sendall(echo_message.encode())

            # Receive the response from the server
            received_message = client_socket.recv(1024).decode()

            # Check if the reply is the same message
            if received_message == echo_message:
                return True, "Server is up! Echo reply: " + received_message
            else:
                return False, "Server responded, but the echo was incorrect."
    
    # Failed to connect to the server, this means the server is down
    except ConnectionRefusedError:
        return False, "Server is down! (or listening on wrong port)."
    
    except socket.timeout:
        return False, "Request timed out."

    except Exception as e:
        return False, f"An error occurred: {e}"
    
# Server checks from examples:

# Check ICMP checksum for creating ICMP packet
def calculate_icmp_checksum(data: bytes) -> int:
    """
    Calculate the checksum for the ICMP packet.

    The checksum is calculated by summing the 16-bit words of the entire packet,
    carrying any overflow bits around, and then complementing the result.

    Args:
    data (bytes): The data for which the checksum is to be calculated.

    Returns:
    int: The calculated checksum.
    """

    s: int = 0  # Initialize the sum to 0.

    # Iterate over the data in 16-bit (2-byte) chunks.
    for i in range(0, len(data), 2):
        # Combine two adjacent bytes (8-bits each) into one 16-bit word.
        # data[i] is the high byte, shifted left by 8 bits.
        # data[i + 1] is the low byte, added to the high byte.
        # This forms one 16-bit word for each pair of bytes.
        w: int = (data[i] << 8) + (data[i + 1])
        s += w  # Add the 16-bit word to the sum.

    # Add the overflow back into the sum.
    # If the sum is larger than 16 bits, the overflow will be in the higher bits.
    # (s >> 16) extracts the overflow by shifting right by 16 bits.
    # (s & 0xffff) keeps only the lower 16 bits of the sum.
    # The two parts are then added together.
    s = (s >> 16) + (s & 0xffff)

    # Complement the result.
    # ~s performs a bitwise complement (inverting all the bits).
    # & 0xffff ensures the result is a 16-bit value by masking the higher bits.
    s = ~s & 0xffff

    return s  # Return the calculated checksum.

# Create ICMP packet for ping
def create_icmp_packet(icmp_type: int = 8, icmp_code: int = 0, sequence_number: int = 1, data_size: int = 192) -> bytes:
    """
    Creates an ICMP (Internet Control Message Protocol) packet with specified parameters.

    Args:
    icmp_type (int): The type of the ICMP packet. Default is 8 (Echo Request).
    icmp_code (int): The code of the ICMP packet. Default is 0.
    sequence_number (int): The sequence number of the ICMP packet. Default is 1.
    data_size (int): The size of the data payload in the ICMP packet. Default is 192 bytes.

    Returns:
    bytes: A bytes object representing the complete ICMP packet.

    Description:
    The function generates a unique ICMP packet by combining the specified ICMP type, code, and sequence number
    with a data payload of a specified size. It calculates a checksum for the packet and ensures that the packet
    is in the correct format for network transmission.
    """

    # Get the current thread identifier and process identifier.
    # These are used to create a unique ICMP identifier.
    thread_id = threading.get_ident()
    process_id = os.getpid()

    # Generate a unique ICMP identifier using CRC32 over the concatenation of thread_id and process_id.
    # The & 0xffff ensures the result is within the range of an unsigned 16-bit integer (0-65535).
    icmp_id = zlib.crc32(f"{thread_id}{process_id}".encode()) & 0xffff

    # Pack the ICMP header fields into a bytes object.
    # 'bbHHh' is the format string for struct.pack, which means:
    # b - signed char (1 byte) for ICMP type
    # b - signed char (1 byte) for ICMP code
    # H - unsigned short (2 bytes) for checksum, initially set to 0
    # H - unsigned short (2 bytes) for ICMP identifier
    # h - short (2 bytes) for sequence number
    header: bytes = struct.pack('bbHHh', icmp_type, icmp_code, 0, icmp_id, sequence_number)

    # Create the data payload for the ICMP packet.
    # It's a sequence of a single randomly chosen alphanumeric character (uppercase or lowercase),
    # repeated to match the total length specified by data_size.
    random_char: str = random.choice(string.ascii_letters + string.digits)
    data: bytes = (random_char * data_size).encode()

    # Calculate the checksum of the header and data.
    chksum: int = calculate_icmp_checksum(header + data)

    # Repack the header with the correct checksum.
    # socket.htons ensures the checksum is in network byte order.
    header = struct.pack('bbHHh', icmp_type, icmp_code, socket.htons(chksum), icmp_id, sequence_number)

    # Return the complete ICMP packet by concatenating the header and data.
    return header + data

# Ping for ICMP checks
def ping(host: str, ttl: int = 64, timeout: int = 1, sequence_number: int = 1) -> Tuple[Any, float] | Tuple[Any, None]:
    """
    Send an ICMP Echo Request to a specified host and measure the round-trip time.

    This function creates a raw socket to send an ICMP Echo Request packet to the given host.
    It then waits for an Echo Reply, measuring the time taken for the round trip. If the
    specified timeout is exceeded before receiving a reply, the function returns None for the ping time.

    Args:
    host (str): The IP address or hostname of the target host.
    ttl (int): Time-To-Live for the ICMP packet. Determines how many hops (routers) the packet can pass through.
    timeout (int): The time in seconds that the function will wait for a reply before giving up.
    sequence_number (int): The sequence number for the ICMP packet. Useful for matching requests with replies.

    Returns:
    Tuple[Any, float] | Tuple[Any, None]: A tuple containing the address of the replier and the total ping time in milliseconds.
    If the request times out, the function returns None for the ping time. The address part of the tuple is also None if no reply is received.
    """

    # Create a raw socket with the Internet Protocol (IPv4) and ICMP.
    # socket.AF_INET specifies the IPv4 address family.
    # socket.SOCK_RAW allows sending raw packets (including ICMP).
    # socket.IPPROTO_ICMP specifies the ICMP protocol.
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        # Set the Time-To-Live (TTL) for the ICMP packet.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # Set the timeout for the socket's blocking operations (e.g., recvfrom).
        sock.settimeout(timeout)

        # Create an ICMP Echo Request packet.
        # icmp_type=8 and icmp_code=0 are standard for Echo Request.
        # sequence_number is used to match Echo Requests with Replies.
        packet: bytes = create_icmp_packet(icmp_type=8, icmp_code=0, sequence_number=sequence_number)

        # Send the ICMP packet to the target host.
        # The second argument of sendto is a tuple (host, port).
        # For raw sockets, the port number is irrelevant, hence set to 1.
        try:
            sock.sendto(packet, (host, 1))
        except socket.gaierror:
            # Handle the getaddrinfo failed error specifically
            return None, None
        
        # Record the current time to measure the round-trip time later.
        start: float = time.time()

        try:
            # Wait to receive data from the socket (up to 1024 bytes).
            # This will be the ICMP Echo Reply if the target host is reachable.
            data, addr = sock.recvfrom(1024)

            # Record the time when the reply is received.
            end: float = time.time()

            # Calculate the round-trip time in milliseconds.
            total_ping_time = (end - start) * 1000

            # Return the address of the replier and the total ping time.
            return addr, total_ping_time
        except socket.timeout:
            # If no reply is received within the timeout period, return None for the ping time.
            return None, None

# Traceroute tool which can be used instead of ping
def traceroute(host: str, max_hops: int = 30, pings_per_hop: int = 1, verbose: bool = False) -> str:
    """
    Perform a traceroute to the specified host, with multiple pings per hop.

    Args:
    host (str): The IP address or hostname of the target host.
    max_hops (int): Maximum number of hops to try before stopping.
    pings_per_hop (int): Number of pings to perform at each hop.
    verbose (bool): If True, print additional details during execution.

    Returns:
    str: The results of the traceroute, including statistics for each hop.
    """
    # Header row for the results. Each column is formatted for alignment and width.
    results = [f"{'Hop':>3} {'Address':<15} {'Min (ms)':>8}   {'Avg (ms)':>8}   {'Max (ms)':>8}   {'Count':>5}"]

    # Loop through each TTL (Time-To-Live) value from 1 to max_hops.
    for ttl in range(1, max_hops + 1):
        # Print verbose output if enabled.
        if verbose:
            print(f"pinging {host} with ttl: {ttl}")

        # List to store ping response times for the current TTL.
        ping_times = []

        # Perform pings_per_hop number of pings for the current TTL.
        for _ in range(pings_per_hop):
            # Ping the host with the current TTL and sequence number.
            # The sequence number is incremented with TTL for each ping.
            addr, response = ping(host, ttl=ttl, sequence_number=ttl)

            # If a response is received (not None), append it to ping_times.
            if response is not None:
                ping_times.append(response)

        # If there are valid ping responses, calculate and format the statistics.
        if ping_times:
            min_time = min(ping_times)  # Minimum ping time.
            avg_time = sum(ping_times) / len(ping_times)  # Average ping time.
            max_time = max(ping_times)  # Maximum ping time.
            count = len(ping_times)  # Count of successful pings.

            # Append the formatted results for this TTL to the results list.
            results.append(f"{ttl:>3} {addr[0] if addr else '*':<15} {min_time:>8.2f}ms {avg_time:>8.2f}ms {max_time:>8.2f}ms {count:>5}")
        else:
            # If no valid responses, append a row of asterisks and zero count.
            results.append(f"{ttl:>3} {'*':<15} {'*':>8}   {'*':>8}   {'*':>8}   {0:>5}")

        # Print the last entry in the results if verbose mode is enabled.
        if verbose and results:
            print(f"\tResult: {results[-1]}")

        # If the address of the response matches the target host, stop the traceroute.
        if addr and addr[0] == host:
            break

    # Join all results into a single string with newline separators and return.
    return '\n'.join(results)

# Check HTTP server status
def check_server_http(url: str) -> Tuple[bool, Optional[int]]:
    """
    Check if an HTTP server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL.
    It returns a tuple containing a boolean indicating whether the server is up,
    and the HTTP status code returned by the server.

    :param url: URL of the server (including http://)
    :return: Tuple (True/False, status code)
             True if server is up (status code < 400), False otherwise
    """
    try:
        # Making a GET request to the server
        response: requests.Response = requests.get(url)

        # The HTTP status code is a number that indicates the outcome of the request.
        # Here, we consider status codes less than 400 as successful,
        # meaning the server is up and reachable.
        # Common successful status codes are 200 (OK), 301 (Moved Permanently), etc.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (True/False, status code)
        # True if the server is up, False if an exception occurs (see except block)
        return is_up, response.status_code

    except requests.RequestException:
        # This block catches any exception that might occur during the request.
        # This includes network problems, invalid URL, etc.
        # If an exception occurs, we assume the server is down.
        # Returning False for the status, and None for the status code,
        # as we couldn't successfully connect to the server to get a status code.
        return False, None

# Check HTTPS server status
def check_server_https(url: str, timeout: int = 5) -> Tuple[bool, Optional[int], str]:
    """
    Check if an HTTPS server is up by making a request to the provided URL.

    This function attempts to connect to a web server using the specified URL with HTTPS.
    It returns a tuple containing a boolean indicating whether the server is up,
    the HTTP status code returned by the server, and a descriptive message.

    :param url: URL of the server (including https://)
    :param timeout: Timeout for the request in seconds. Default is 5 seconds.
    :return: Tuple (True/False for server status, status code, description)
    """
    try:
        # Setting custom headers for the request. Here, 'User-Agent' is set to mimic a web browser.
        headers: dict = {'User-Agent': 'Mozilla/5.0'}

        # Making a GET request to the server with the specified URL and timeout.
        # The timeout ensures that the request does not hang indefinitely.
        response: requests.Response = requests.get(url, headers=headers, timeout=timeout)

        # Checking if the status code is less than 400. Status codes in the 200-399 range generally indicate success.
        is_up: bool = response.status_code < 400

        # Returning a tuple: (server status, status code, descriptive message)
        return is_up, response.status_code, "Server is up"

    except requests.ConnectionError:
        # This exception is raised for network-related errors, like DNS failure or refused connection.
        return False, None, "Connection error"

    except requests.Timeout:
        # This exception is raised if the server does not send any data in the allotted time (specified by timeout).
        return False, None, "Timeout occurred"

    except requests.RequestException as e:
        # A catch-all exception for any error not covered by the specific exceptions above.
        # 'e' contains the details of the exception.
        return False, None, f"Error during request: {e}"

# Check DNS server status
def check_dns_server_status(server, query, record_type) -> (bool, str):
    """
    Check if a DNS server is up and return the DNS query results for a specified domain and record type.

    :param server: DNS server name or IP address
    :param query: Domain name to query
    :param record_type: Type of DNS record (e.g., 'A', 'AAAA', 'MX', 'CNAME')
    :return: Tuple (status, query_results)
    """
    try:
        # Set the DNS resolver to use the specified server
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(server)]

        # Perform a DNS query for the specified domain and record type
        query_results = resolver.resolve(query, record_type)
        results = [str(rdata) for rdata in query_results]

        return True, results

    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer, socket.gaierror) as e:
        # Return False if there's an exception (server down, query failed, or record type not found)
        return False, str(e)

# Check NTP server status
def check_ntp_server(server: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if an NTP server is up and returns its status and time.

    Args:
    server (str): The hostname or IP address of the NTP server to check.

    Returns:
    Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the server status
                                 (True if up, False if down) and the current time as a string
                                 if the server is up, or None if it's down.
    """
    # Create an NTP client instance
    client = ntplib.NTPClient()

    try:
        # Request time from the NTP server
        # 'version=3' specifies the NTP version to use for the request
        response = client.request(server, version=3)

        # If request is successful, return True and the server time
        # 'ctime' converts the time in seconds since the epoch to a readable format
        return True, ctime(response.tx_time)
    except (ntplib.NTPException, gaierror):
        # If an exception occurs (server is down or unreachable), return False and None
        return False, None

# Check TCP port status
def check_tcp_port(ip_address: str, port: int) -> (bool, str):
    """
    Checks the status of a specific TCP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The TCP port number to check.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open, False otherwise.
           The string provides a description of the port status.

    Description:
    This function attempts to establish a TCP connection to the specified port on the given IP address.
    If the connection is successful, it means the port is open; otherwise, the port is considered closed or unreachable.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_STREAM socket type (TCP).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely. Here, 3 seconds is used as a reasonable timeout duration.
            s.settimeout(3)

            # Attempt to connect to the specified IP address and port.
            # If the connection is successful, the port is open.
            s.connect((ip_address, port))
            return True, f"Port {port} on {ip_address} is open."

    except socket.timeout:
        # If a timeout occurs, it means the connection attempt took too long, implying the port might be filtered or the server is slow to respond.
        return False, f"Port {port} on {ip_address} timed out."

    except socket.error:
        # If a socket error occurs, it generally means the port is closed or not reachable.
        return False, f"Port {port} on {ip_address} is closed or not reachable."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check port {port} on {ip_address} due to an error: {e}"

# Check UDP port status
def check_udp_port(ip_address: str, port: int, timeout: int = 3) -> (bool, str):
    """
    Checks the status of a specific UDP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The UDP port number to check.
    timeout (int): The timeout duration in seconds for the socket operation. default = 3 seconds.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open (or if the status is uncertain), False if the port is definitely closed.
           The string provides a description of the port status.

    Description:
    This function attempts to send a UDP packet to the specified port on the given IP address.
    Since UDP is a connectionless protocol, the function can't definitively determine if the port is open.
    It can only confirm if the port is closed, typically indicated by an ICMP 'Destination Unreachable' response.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_DGRAM socket type (UDP).
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely.
            s.settimeout(timeout)

            # Send a dummy packet to the specified IP address and port.
            # As UDP is connectionless, this does not establish a connection but merely sends the packet.
            s.sendto(b'', (ip_address, port))

            try:
                # Try to receive data from the socket.
                # If an ICMP 'Destination Unreachable' message is received, the port is considered closed.
                s.recvfrom(1024)
                return False, f"Port {port} on {ip_address} is closed."

            except socket.timeout:
                # If a timeout occurs, it's uncertain whether the port is open or closed, as no response is received.
                return True, f"Port {port} on {ip_address} is open or no response received."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check UDP port {port} on {ip_address} due to an error: {e}"

# Main functionality and majority assignment code.

# Adds a service to the list of services to monitor
def add_service(services):
    """
    This function adds a service to the list of services to monitor. It also prompts the user for inputs, and uses them as parameters.
    Args:
        services (list): The list of services to modify

    Returns:
        service (dict): contains all information to be added for the added service
    """
    # Beginning information prompt
    print("Enter any options in 'single quotes' to begin adding a service to monitor.")
    print("-------------  Standard  services  -------------")
    print("  'HTTP','HTTPS','ICMP','DNS','NTP','TCP','UDP'")
    print("-------------  Additional options  -------------")
    print("'echo' - Test the custom TCP echo server.")
    print("Return/enter - to start monitoring.")
    print("'start' - also start monitoring.")
    print("'view - View all currently added services.")
    print("'restart' - Clear added services and start over.")
    print("'exit' - Exit the program.")
    print("------------------------------------------------")
    
    # Prompt user input
    while True:
        service_input = input(
            "Enter option: ").strip().upper()

        # Continue to prompt parameters
        if service_input in ["", "START"]:
            if not services:
                print("Please include at least one service to monitor.")
            else:
                print("------------------------------------------------")
                print("Starting monitor!")
                break

        # Exit program
        elif service_input == "EXIT":
            exit("Exiting...")
            
        # Start services list over
        elif service_input == "RESTART":
            services.clear()
            print("Starting over.")
            continue
        
        # View added services
        elif service_input == "VIEW":
            if services:
                print("Currently added services:")
                for service in services:
                    print(service)
            else:
                print("No services in the list.")
            continue  # Return to the start of the prompt
            
        # HTTP and HTTPS (parameters: URL)
        elif service_input in ["HTTP", "HTTPS"]:
            url = input(f"Enter full URL (with {service_input.lower()}://) for {service_input} service: ").strip()
            interval = input(f"Enter time the interval for checks: (default = 10): ").strip()
            interval = int(interval) if interval else 10
            print("Service added.\n------------------------------------------------")
            return {"type": service_input, "url": url, "interval": interval}

        # ICMP (parameters: server address, tool)
        elif service_input == "ICMP":
            server_address = input("Enter server address for ICMP: ").strip()
            tool = input("Enter ICMP option ('ping' or 'traceroute') (default = ping): ").strip().lower()
            if tool == "":
                tool = "ping"
            interval = input(f"Enter time the interval for checks: (default = 10): ").strip()
            interval = int(interval) if interval else 10
            print("Service added.\n------------------------------------------------")
            return {"type": service_input, "server": server_address, "tool": tool, "interval": interval}

        # NTP (parameters: server address)
        elif service_input in ["ICMP", "NTP"]:
            server_address = input(f"Enter server address for {service_input}: ").strip()
            interval = input(f"Enter time the interval for checks: (default = 10): ").strip()
            interval = int(interval) if interval else 10
            print("Service added.\n------------------------------------------------")
            return {"type": service_input, "server": server_address, "interval": interval}

        # TCP (parameters: server address, port)
        elif service_input == "TCP":
            server_address = input(f"Enter server address for TCP: ").strip()
            port = input(f"Enter port for TCP service (default = http/80): ").strip()
            port = int(port) if port else 80
            interval = input(f"Enter the time interval for checks: (default = 10): ").strip()
            interval = int(interval) if interval else 10
            print("Service added.\n------------------------------------------------")
            return {"type": "TCP", "server": server_address, "port": port, "interval": interval}

        # UDP (parameters: server address, port, timeout)
        elif service_input == "UDP":
            server_address = input(f"Enter server address for UDP: ").strip()
            port = input(f"Enter port for UDP service (default = dns/53): ").strip()
            port = int(port) if port else 53
            timeout = int(input(
                f"Enter timeout duration for UDP (in seconds, default = 3 seconds): ").strip() or 3)
            interval = input(f"Enter the time interval for checks: (default = 10): ").strip()
            interval = int(interval) if interval else 10
            print("Service added.\n------------------------------------------------")
            return {"type": "UDP", "server": server_address, "port": port, "timeout": timeout, "interval": interval}

        # DNS (parameters: server address, query address, record type)
        elif service_input == "DNS":
            server_address = input("Enter the DNS server address: ").strip()
            query_address = input("Enter the DNS query lookup address: ").strip()
            record_type = input("Enter the DNS record type (A, MX, AAAA, CNAME, or manual) (default = A): ").strip().upper()
            if not record_type:
                record_type = "A"
            interval = input(f"Enter the time interval for checks: (default = 10): ").strip()
            interval = int(interval) if interval else 10
            print("Service added.\n------------------------------------------------")
            return {"type": service_input, "server": server_address, "query": query_address, "record_type": record_type, "interval": interval}

        # echo - TCP echo server (parameters: server address, port, message)
        elif service_input == "ECHO":
            server_address = input("Enter the echo server address (recommendation: localhost/127.0.0.1): ").strip()
            port = input(f"Enter port for echo service (default = 12345): ").strip()
            port = int(port) if port else 12345
            message = input(f"Enter message to echo (default = Hello!): ").strip()
            if message == "":
                message = "Hello!"
            interval = input(f"Enter the time interval for checks: (default = 10): ").strip()
            interval = int(interval) if interval else 10
            print("Service added.\n------------------------------------------------")
            return {"type": service_input.lower(), "server": server_address, "port": port, "message": message, "interval": interval}
        
        # Invalid input entered
        else:
            print("Invalid service/command entered. Please enter a valid service type or command to continue.")

# Timestamped print
def timestamped_print(*args, **kwargs):
    """
    Custom print function that adds a timestamp to the beginning of the message.
    Args:
    *args: Variable length argument list.
    **kwargs: Arbitrary keyword arguments. These are passed to the built-in
    print function.
    """
    # Get the current time and format it
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    # Print the timestamp followed by the original message
    print(f"{timestamp} -",*args,**kwargs)

# Network monitoring function run by a thread
def network_monitor(stop_event, service):
    """
    Network monitor function is run by a thread that tracks one of the services periodically according to the set interval.
    The configuration of the service determines much of the information here as they are put into the check functions.
    Args:
        stop_event (threading.Event): A thread object to signal the termination of the thread
        service (dict): A dictionary containing the information from the service to monitor
    """
    last_checked = 0
    thread_interval = service["interval"] # Thread interval for this service

    # Run until stop event terminates thread
    while not stop_event.is_set():
        current_time = time.time()
        if current_time - last_checked >= service["interval"]:
            last_checked = current_time
            
            # Check HTTP status
            if service["type"] == "HTTP":
                http_server_status, http_server_response_code = check_server_http(service["url"])
                if http_server_status == True:
                    http_server_status = "Server is up!"
                else:
                    http_server_status = "Server is down!"
                timestamped_print(f"HTTP URL: {service["url"]}. Server status: {http_server_status} Status Code: {http_server_response_code if http_server_response_code is not None else 'N/A'}")
            
            # Check HTTPS status
            elif service["type"] == "HTTPS":
                https_server_status, https_server_response_code, description = check_server_https(service["url"])
                if https_server_status == True:
                    https_server_status = "Server is up!"
                else:
                    https_server_status = "Server is down!"
                timestamped_print(f"HTTPS URL: {service["url"]}. Server status: {https_server_status} Status Code: {https_server_response_code if https_server_response_code is not None else 'N/A'}, Description: {description}")
            
            # ICMP
            elif service["type"] == "ICMP":
                # Use traceroute tool
                if service["tool"] == "traceroute":
                    timestamped_print(f"traceroute began.")
                    print(traceroute(service["server"]))
                # Check ping status
                else:
                    ping_addr, ping_time = ping(service["server"])
                    timestamped_print(f"{ping_addr[0]} status: Server is up! - ping: {ping_time:.2f} ms" if (ping_addr and ping_time is not None) else f"{timestamp} - Request to {service["server"]} status: Server is down! DNS either did not resolve, timed out, or no reply received")
            
            # Check DNS status
            elif service["type"] == "DNS":
                dns_server_status, dns_query_results = check_dns_server_status(service["server"], service["query"], service["record_type"])
                if dns_server_status == True:
                    dns_server_status = "Server is up!"
                else:
                    dns_server_status = "Server is down!"
                timestamped_print(f"DNS Server: {service["server"]}, Status: {dns_server_status} {service["record_type"]} Records Results: {dns_query_results}")
            
            # Check NTP status
            elif service["type"] == "NTP":
                ntp_server_status, ntp_server_time  = check_ntp_server(service["server"])
                timestamped_print(f"NTP Server {service["server"]} status: Server is up! Time: {ntp_server_time}" if ntp_server_status else f"{timestamp} - NTP Server {service["server"]} status: Server is down!")
            
            # Check TCP status
            elif service["type"] == "TCP":
                tcp_port_status, tcp_port_description = check_tcp_port(service["server"], service["port"])
                if tcp_port_status == True:
                    tcp_port_status = "Server is up!"
                else:
                    tcp_port_status = "Server is down!"
                timestamped_print(f"Server: {service["server"]}, TCP Port: {service["port"]}, TCP Status: {tcp_port_status} Description: {tcp_port_description}")
            
            # Check UDP status
            elif service["type"] == "UDP":
                udp_port_status, udp_port_description = check_udp_port(service["server"], service["port"])
                if udp_port_status == True:
                    udp_port_status = "Server is up!"
                else:
                    udp_port_status = "Server is down!"
                timestamped_print(f"Server: {service["server"]}, UDP Port: {service["port"]}, UDP Status: {udp_port_status} Description: {udp_port_description}")
            
            # Check echo server
            elif service["type"] == "echo":
                server_status, message = check_custom_tcp_echo_server(service["server"], service["port"], service["message"])
                timestamped_print(f"TCP Echo server status: {message}")

        # Wait for the service interval before checking again
        time.sleep(thread_interval)


# Main function
def main():
    # Introduce the user on program start
    print("Welcome to the network monitor!\n")
    
    # List of all services to monitor
    services = []

    # Add services with parameters and intervals
    while True:
        service = add_service(services)
        if service:
            services.append(service)
        else:
            break

    # Create a stop event for each service
    stop_events = [threading.Event() for _ in services]

    # Start a thread for each service
    threads = []
    for i, service in enumerate(services):
        thread = threading.Thread(target=network_monitor, args=(stop_events[i], service))
        threads.append(thread)
        thread.start()

    # Command completer for auto-completion
    command_completer = WordCompleter(['exit'], ignore_case=True)

    # Create a prompt session
    session = PromptSession(completer=command_completer)

    # Command line for user exit input
    try:
        with patch_stdout():
            while True:
                user_input = session.prompt("Type 'exit' to end monitoring: ")
                if user_input == "exit":
                    print("Please allow all threads to finish. Exiting...")
                    break

    # End threads
    finally:
        # Signal threads to stop
        for event in stop_events:
            event.set()

        # Wait for threads to finish
        for thread in threads:
            thread.join()
    
        # Threads have now ended
        print("Exiting.")

if __name__ == "__main__":
    main()