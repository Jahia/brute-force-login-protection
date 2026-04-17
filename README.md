# brute-force-login-protection

Blocks login attempts from an IP address after a configurable number of consecutive failed logins. Supports both IPv4 and IPv6.

## Installation

- In Jahia, go to **Administration → Server settings → System components → Modules**
- Upload the JAR `brute-force-login-protection-X.X.X.jar`
- Check that the module is started

## Configuration

Go to **Administration → Server settings → Configuration → Brute force login protection**.

- **Service status** — toggle the protection on/off.
- **Number of failed logins max** — threshold at which an IP is blocked (default: 6).
- **CIDRs whitelist** — comma-separated list of IPv4 and/or IPv6 CIDR blocks that are never blocked. Defaults to `127.0.0.1/32,::1/128`. Examples: `192.168.0.0/24`, `2001:db8::/32`.

Configure the Jahia mail server settings to receive a notification email the first time each IP is blocked.

## Tracked IPs

The **Tracked IPs** section lists every IP with at least one failed login attempt, its failed-login count, and whether it currently exceeds the threshold (blocked) or is still below it (tracked).

- **Unblock** — remove a specific IP from the cache. The counter resets to zero and the IP can log in again.
- **Flush cache** — clear every tracked IP at once and force the settings to be re-read from the repository.
