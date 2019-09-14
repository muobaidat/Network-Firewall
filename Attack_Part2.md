# Cybersecurity Project

## Network Firewall 
In this project, your attack program will attempt to bypass the network firewall protecting a server, to get unallowed traffic through the firewall and get a response from the server.  

* Each attack program will make one communication attempt to the server. 

A sample attack program is provided and needs to be modified to perform different tests.

## Attack
A network server is protected by a firewall that attempts to only respond to certain traffic. You will test this firewall defense with your attack program. The goal of the attack is to get a response from the server that is not in accordance with the rules described below in the Defense rules section. 

There will be a set of TRUSTED source IP addresses and a separate set of SEMI-TRUSTED source IP addresses. Any source IP that is not TRUSTED or SEMI-TRUSTED is UNTRUSTED.  But just because a source is TRUSTED or SEMI-TRUSTED does not mean all traffic from it is allowed. Traffic will only be allowed from certain ports and for certain application protocols. 

## Defense rules
The firewall simulation program defense should be implementing these rules.
* Send back an “Accept” message to communication attempts from a TRUSTED source IP and TRUSTED source port if the application protocol type is TRUSTED.  
* Send back a “Reject” message to communication attempts from a TRUSTED source IP and TRUSTED source port if the application protocol type is SEMI-TRUSTED.
* Send back a “Reject” message to communication attempts from a TRUSTED source IP and TRUSTED source port if the application protocol type is UNTRUSTED.
* Send back a “Reject” message to communication attempts from a SEMI-TRUSTED IP and TRUSTED source port if the application protocol is TRUSTED.
* Send back a “Reject” message to communication attempts from a TRUSTED source IP and SEMI-TRUSTED source port if the application protocol type is TRUSTED.
* Otherwise, do not send back a response, “drop” the communication.

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

### Attack

You may select up to 5 defense programs to attack. Submit one attack program for a defense.

Name your submitted attack programs "Firewall_DDD_Attack_###.r2py", where DDD is the 3-digit student code in the defense program being attacked, and ### is your unique 3-digit student code.


## Sample Attack Code

``` python
# openconnection(destination, source, timeout)

##########################################################
#### modify the sourceIP address to test the firewall ####
sourceIP = '127.0.0.8'
##########################################################

socket = openconnection('127.0.0.1', 12777, sourceIP, 12345, 10)

# sample message to send to firewall where
# application protocol is DD and port is 20001
# the remainder of the message is optional

##########################################################
#### modify message to test firewall ####
message = 'DD20001helloworld'
##########################################################

socket.send(message)

# wait for response through communication socket, log if received
# otherwise log error message
try:
  sleep(0.1)
  response = socket.recv(512)
  log(response)
  log('\n')
except SocketWouldBlockError:
  pass
except SocketClosedRemote:
  log('exception: message not received')
  log('\n')
  
# close communication socket
socket.close()
```

### Run code in separate terminal windows

``` python
python repy.py restrictions.test defend.r2py

python repy.py restrictions.test attack.r2py
```
The restrictions.test file provided sets values of parameters of resources and functionality allowed. 
