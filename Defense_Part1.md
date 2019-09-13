# SimulationProject

## Firewall Simulation
In this simulation, your defense program will attempt to implement the rules of the firewall protecting a server so that it only responds to allowed incoming traffic. Your attack program will try to get unallowed traffic through the firewall and get a response from the server.  

There will be a set of TRUSTED source IP addresses and a separate set of SEMI-TRUSTED source IP addresses. Any source IP that is not TRUSTED or SEMI-TRUSTED is UNTRUSTED.  But just because a source is TRUSTED or SEMI-TRUSTED does not mean all traffic from it is allowed. Traffic will only be allowed from certain ports and for certain application protocols. 

## Defense
Various sources will try to communicate with your network server. Your firewall simulation program should inspect the source IP, port and application protocol to ensure that only some traffic is responded to. Log the IP address from the communication socket, as well as the message received. The application protocol and port will be contained in the message.  
* Send back an “Accept” message to communication attempts from a TRUSTED source IP and TRUSTED source port if the application protocol type is TRUSTED.  
* Send back a “Reject” message to communication attempts from a TRUSTED source IP and TRUSTED source port if the application protocol type is SEMI-TRUSTED.
* Send back a “Reject” message to communication attempts from a TRUSTED source IP and TRUSTED source port if the application protocol type is UNTRUSTED.
* Send back a “Reject” message to communication attempts from a SEMI-TRUSTED IP and TRUSTED source port if the application protocol is TRUSTED.
* Send back a “Reject” message to communication attempts from a TRUSTED source IP and SEMI-TRUSTED source port if the application protocol type is TRUSTED.
* Otherwise, do not send back a response, “drop” the communication.
* In all cases, write the IP address and message sent along with the action taken for a communication attempt to a file, to simulate passing the information to an IDS, whether “Accept”, “Reject”, or “Drop”.


## Assignment Instructions

### Installing and using Repy v2 (Restricted Python)
Defense and Attack Programs will be written in repy v2 (Restricted Python). Installation and usage instructions for RepyV2 are here:  

https://github.com/SeattleTestbed/docs/blob/master/Programming/RepyV2Tutorial.md

If you’re familiar with Python, RepyV2 is similar, but has a few differences that are explained here:

https://github.com/SeattleTestbed/docs/blob/master/Programming/PythonVsRepyV2.md

### Message format for communication attempt
The attack programs will include the simulated application protocol in the first 2 characters of the message and a source port number in the following 5 characters. Any further characters in the message are optional. 

An example message with an application protocol of HT and port of 87654 is below. 

HT87654HELLO0000

The defense programs will get the source IP from the connection request, and parse the protocol and port in the message to determine the appropriate (if any) response.

A sample, though insufficient, program for your defense is provided. You will need to modify the code to implemenent all the firewall rules.

A sample attack program is also provided to test against your defense code prior to submission.

## Trust Definitions
In this simulation, the following values represent trusted sources.

### TRUSTED

|     | Values |  
| --- | --- |  
| IP	|  127.0.0.1 through 127.0.0.12  |  
| Port |	20001, 28724, 39845  |  
| AP	|  HT, GL  |  

In this simulation, the following values represent semi-trusted sources.

### SEMI-TRUSTED

|    | Values |  
| --- | --- | 
| IP | 127.0.0.13 through 127.1.1.255 |
| Port | 49034 |
| AP | SR |

### UNTRUSTED
Anything not specifically enumerated above.  

Note that this program will be running locally, so **all IP addresses used must be in the 127 network.**

## Submission
### Defense 

Submit one defense program, named firewalldefend_###.r2py, where ### is your assigned 3-digit code.

## Sample Defense Code

``` python
'''
define inspect function that will parse message
from source and decide whether to send response

this starting definition is not sufficient for the firewall rules
and needs to be improved as part of the simulation assignment
'''
def inspect(ip, unused, sock, actionlog):

  # save received message
  message = sock.recv(512)
  
  # default action
  action = "DROP"

  #############  UPDATE THIS PART #################
  
  # define trusted application protocols
  trustedaps = ['HT', 'GL']

  # parse application protocol out of message  
  senderap = message[0:2]

  # if the application is trusted, send back 'Accept' message
  if senderap in trustedaps:
    action = 'ACCEPT'
    sock.send('Accept')

  #################################################

  # write report to file
  report = ip + ' ' + message + ' ' + action + '\n'
  actionlog.writeat(report, mycontext['offset'])
  mycontext['offset'] += len(report)
  
  # close communication socket
  sock.close()

######## END OF INSPECT FUNCTION ###################

# "global" variable for offset in file writing
mycontext['offset'] = 0

# listen for connection requests coming in
server = listenforconnection('127.0.0.1', 12777)

########## USE UNIQUE STUDENT CODE ASSIGNED #########
studentcode = "###"    # replace ### with your code

filename = "firewalllog_" + studentcode;
actionlog = openfile(filename, True)

# keep checking for connection request
# if none received, wait and try again
while True:
  try:
    src_ip, unused, src_socket = server.getconnection()
    inspect(src_ip, unused, src_socket, actionlog)
  except SocketWouldBlockError:
    sleep(0.1)

actionlog.close()
```


### Run code in separate terminal windows

``` python
python repy.py restrictions.test defend.r2py

python repy.py restrictions.test attack.r2py
```
The restrictions.test file provided sets values of parameters of resources and functionality allowed. 
