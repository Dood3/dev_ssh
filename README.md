# dev_ssh
- 0_4.py\
  Needs python3-scp, python3-paramiko, python3-netifaces to be installed on target(s).\
  Executes a ping sweep of the current subnet to determine alive hosts, and then goes on to brute force the ssh creds to spread further. After gaining access to a new host, it deletes itself. Still some debugging stuff in the script.
- 0_5.py\
  Reads user and password list from a URI in memory.
- 0.7.1.py\
  Uses the response from dns requests to load user & password list into memory for brute-forcing.
  It runs from Linux as well as Windows and is able to authenticate to both systems via ssh, as long it is
  available and/or enabled on the target.
