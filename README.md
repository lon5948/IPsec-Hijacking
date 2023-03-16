# IPsec-Hijacking

### Attack Scenario in this Project

- Scenario：The TCP client has set up IPsec associations in transport mode for

- Attacker：Executing a malicious program to hijack the IPsec session

### Environment Setup

- Using two devices, designated as the client and the server, and establishing the
IPsec/TCP session between them.

##### Server

- Step 1
```
sudo sh ipsec_server.sh
```

- Step 2
```
./tcp_server server_port
```

##### Client

- Step 1
```
sudo sh ipsec_victim.sh
```

- Step 2
```
./tcp_client server_ip > server_port > bp < victim_port >
```

- Step 3
```
./ipsec_hijack
```


