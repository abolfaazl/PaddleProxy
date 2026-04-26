# PaddleProxy 🛶

PaddleProxy is a high-performance, secure, and multi-protocol proxy server (SOCKS5 & HTTP CONNECT) built with Python's `asyncio`. It is designed for developers and power users who need granular control over their traffic, user management, and security.

## ✨ Features

-   **Dual Protocol Support:** Seamlessly handles both SOCKS5 and HTTP CONNECT methods.
-   **Multi-User Management:** Create multiple users with unique credentials.
-   **Traffic Control:**
    -   **Total Quota:** Set a hard limit on total data usage (MB).
    -   **Daily Quota:** Reset limits every 24 hours.
    -   **Speed Limiting:** Restrict bandwidth per user (KB/s).
-   **Advanced Security:**
    -   **Anti-Brute Force:** Automatically bans IPs after 5 failed authentication attempts for 24 hours.
    -   **Blacklist System:** Block specific domains globally.
    -   **IP Management:** View and manually unban IPs via the terminal interface.
-   **Real-time Monitoring:** Live terminal dashboard showing active users, usage stats, and top domains.
-   **Logging:** Detailed activity and security logs saved to `proxy.log`.
-   **Custom DNS:** Built-in DNS resolver to bypass local DNS poisoning.

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/abolfaazl/PaddleProxy.git](https://github.com/abolfaazl/PaddleProxy.git)
    cd PaddleProxy
    ```

2.  **Install dependencies:**
    ```bash
    pip install dnspython
    ```

## 🛠 Usage

### Interactive Mode (Management)
Run the proxy with the terminal UI to manage users and view stats:
```bash
python app.py