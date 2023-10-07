# Introduction
This lab conducts a DNS attack, kamisky attack

# Task 1: Testing the DNS Setup
We will first need to use `dockps` to list out all the docker containers that is running and locate the `user-10.9.0.5` container's id.

Use `docker sh <containter-id>` to get into the shell of the container

## Observations

### Query the attacker's dns server
Run `dig ns.attacker32.com` to access the attacker's dns server

#### Result

![Alt text](attachments/attacker-dns-query.png)
As we can see from the output, the answer section of `ns.attacker32.com` is coming from `10.9.0.153` which is what we defined in the `attacker32.com.zone` file. Which means the dns server is working

### querying example.com
Run `dig example.com` to check for the ip address that match the domain of `example.com`

#### Result

![Alt text](attachments/example-dns-query.png)
From the screenshot, we can tell that the original ip address of `example.com` is coming from `93.184.216.34` which is what we are expecting

### query example.com using attacker dns
Run `dig@ns.attacker32.com www.example.com` to direct the dns query of `www.example.com` to the attacker's dns server

#### Result
![Alt text](attachments/example-attacker-dns-query.png)

From the screenshot, we can tell that the ip address is different from what we saw previously in [normal example.com query](#result-1), this is because we are querying from the attacker's dns server, and the attacker's dns server has a zone file for `www.example.com` stating that its address should be `1.2.3.5`  

## Section Conclusion
From the above 3 commands, we can tell that the dns server configuration is working as intended, we can start trying to carry out the attack


# Task 1: Construct DNS request
