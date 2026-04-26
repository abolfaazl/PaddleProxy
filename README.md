
# PaddleProxy 🛶

PaddleProxy is a high-performance, secure, and multi-protocol proxy server (SOCKS5 & HTTP CONNECT) built with Python's `asyncio`. It is designed for developers and power users who need granular control over their traffic, user management, and security.

##  Features

-   **Dual Protocol Support:** Seamlessly handles both SOCKS5 and HTTP CONNECT methods.
-   **UDP Relay:** Supports UDP ASSOCIATE for online gaming, VoIP calls (Telegram/Skype), and WebRTC.
-   **Multi-User Management:**
    -   Create and update users without restarting the server.
    -   Granular control: Set unique passwords, quotas, and speeds for each user.
-   **Traffic & Quota Control:**
    -   **Total Quota:** Set a hard limit on lifetime data usage (MB).
    -   **Daily Quota:** Auto-resetting daily limits for recurring bandwidth management.
    -   **Speed Limiting:** Real-time bandwidth throttling per user (KB/s).
    -   **Expiration System:** Set an expiration date (in days) for user accounts.
-   **Advanced Security:**
    -   **Anti-Brute Force:** Automatically bans IPs after 10 failed authentication attempts for 24 hours.
    -   **Password Hashing:** Secure storage using SHA-256 (automatic migration from legacy configs).
    -   **Blacklist System:** Block specific domains (e.g., Windows Updates, Telemetry) globally.
    -   **Banned IP Management:** View, track (remaining time), and manually unban IPs via the TUI.
-   **Real-time Monitoring:**
    -   **Live Dashboard:** A refreshing TUI showing active users, status (Expired/Limit Reached), and real-time usage.
    -   **Top Domains:** Tracks and displays the most visited domains by traffic.
-   **Logging:** Professional-grade activity and security logs saved to `proxy.log`.
-   **Custom DNS:** Built-in multi-DNS resolver to bypass local DNS poisoning or censorship.

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/abolfaazl/PaddleProxy.git
    cd PaddleProxy
    ```

2.  **Install dependencies:**
    ```bash
    pip install dnspython
    ```

## 🛠 Usage

### Interactive Mode (Management TUI)
Run the proxy with the terminal UI to manage users, view live stats, and configure settings:
```bash
python app.py
```
### Background Mode

Run the proxy as a silent service (no UI). The server will automatically sync changes if you edit `config.json` manually or through another TUI instance.

-   **Windows:** `pythonw app.py -b`
    
-   **Linux:** `nohup python3 app.py -b &`
    

### 📋 Management Interface Options

-   `1`: **Manage Users** - Add new users or update Password, Quota, Daily Limit, Speed, and Expiry.
    
-   `2`: **Live Traffic Monitor** - Real-time view of who is consuming data and which domains are top-ranked.
    
-   `3/4`: **Blacklist** - Manage domain-level blocks.
    
-   `5`: **Toggle Authentication** - Quickly enable or disable user login requirements.
    
-   `6`: **Change Port** - Update the server port (requires restart).
    
-   `7`: **DNS Settings** - Add or reset custom DNS servers (e.g., 8.8.8.8, 1.1.1.1).
    
-   `8`: **Ban Management** - View "jailed" IPs and their remaining sentence time.
    
-   `9`: **Detached Exit** - Closes the TUI but keeps the proxy server running in the background.
    
-   `0`: **Full Stop** - Completely shuts down the proxy server and the management interface.
    

## 🛡 Security Note

PaddleProxy hashes passwords for security. If you are migrating from an older version, the server will automatically detect plain-text passwords on the first run and convert them to secure SHA-256 hashes.

All security events like failed login attempts and bans are recorded with timestamps in `proxy.log`.

## 📄 License

This project is open-source and available under the [MIT License](https://www.google.com/search?q=LICENSE&authuser=6).