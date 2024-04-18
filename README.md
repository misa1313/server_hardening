# server_hardening
Some good practices to improve security on RHEL-based servers, automated. 

 Tested on :
```
CentOS 7
CloudLinux 7
AlmaLinux 8
CloudLinux 8
AlmaLinux 9 
CloudLinux 9 
```

## Usage:
1. Run the script:
```
bash server_hardening.sh
```

2. Have your IP address, public key, and admin user's name at hand (Optional) 

## Features:

The script will execute 3 main functions:
ssh_hardening - Good practices to secure our SSH config
fw_hardening  - Block all ports except the ones specified
user_pass_policy - Settings about user's password complexity, attempts, change frequency, etc. 
