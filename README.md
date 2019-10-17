# brute-force-login-protection

The purpose of this module is to block any login from an IP when 6 unsuccessful attemps have been made

# Installation

- In Jahia, go to "Administration --> Server settings --> System components --> Modules"
- Upload the JAR **brute-force-login-protection-X.X.X.jar**
- Check that the module is started

# Use
- Do not forget to configure the mail server settings if you want to be notified when an IP is blocked
- Go to "Administration --> Server settings --> Configuration --> Brute force login protection"
  - Set the CIDR blocks to whitelist, separated by a comma, in order to prevent any "secure" IP to be blocked
  - Activate the service then save


