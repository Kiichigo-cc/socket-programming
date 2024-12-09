# --- README Recommended application instructions for Network Monitor, echo server, and client ---

# --- Executing the network monitor program ---:
This program was coded in a virtual python environment (venv) on Python 3.12.1 in Windows 10.
It is optional, but you may run this program in a similar environment with the same Python interpreter.

To install necessary packages to run this program, run this code to install requirements from requirements.txt:

$ pip install -r requirements.txt

To execute the program, enter the following command:

$ python network_monitor.py

# --- Using the program ---:
The program will first prompt you with many options in the terminal, including standard services to monitor and controls.
Type any of the options prompted in the terminal to add that service/execute that command.
If you are adding a service, additional prompts will appear in the terminal, asking you to choose parameters.
Parameters with "(default = __)" in them will allow you to press enter to inherit the default parameter.
Once a service is added to the monitor list, you will return to the starting prompt.

# --- Available services ---:
This is a description of all services that can be monitored.
HTTP: Hypertext Transfer Protocol (Parameters: url)
HTTPS: Hypertext Transfer Protocol Secure (Parameters: url)
ICMP: Internet Control Message Protocol (Parameters: server address, tool)
DNS: Domain Name System (Parameters: server address, query address, record type)
NTP: Network Time Protocol (Parameters: server address)
TCP: Transmission Control Protocol (Parameters: server address, port)
UDP: User Datagram Protocol (Parameters: server address, port, timeout)
echo: Test the provided echo server. (Parameters: server address, port, message)

# --- Additional controls ---:
'start' or return: Start monitoring all services added to the list
'view': View all services added to the list, with details/parameters in dictionaries.
'restart': Clear the service monitor list and start over.
'exit': Terminate the program.

# --- Monitoring services ---:
When you have finished adding services to monitor, type 'start' or return to begin monitoring.
The console will continuously display updates of all your services at approximate intervals according to what was set for each service.
The outputs are timestamped when the check begins, and will contain a status message telling whether the server is up or down, and related information from each service.
At any time, you may follow instructions in the command line and enter 'exit' to terminate the monitoring service.
The program will close after this.

# --- Echo server usage ---
Run the echo server using the following command:

$ python echo_server.py

This server will now accept connections from client sockets and echo back the same message before closing the connection.
The terminal will let you know when connections and messages have been established.

# --- Echo client usage ---
Run the echo server using the following command:

$ python echo_client.py

The terminal will prompt you to enter a message. Enter the message to echo to the server, or type 'exit' to close the client.
The program will terminate after closing the socket, so launch again to echo again.

# --- END ---
