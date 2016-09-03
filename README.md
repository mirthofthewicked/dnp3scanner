# dnp3scanner


Initial concept by Chris Sistrunk. Just trying to make his dreams come true:

User input: IP address
                  : TCP port
Then it creates the 10 byte message starting at address 0
Sends the message
Waits for response
Parses response
  > Stores DNP3 response info in a db
Keeps looping until address 65535
