#!/usr/bin/env python3
"""
ethical-security-tools.py - Educational security tools for authorized testing ONLY
DISCLAIMER: Use only on systems you own or have explicit permission to test.
"""

import hashlib
import socket
import requests
from datetime import datetime

class EthicalSecurityTools:
    def __init__(self):
        print("🔒 ETHICAL SECURITY TESTING TOOLKIT")
        print("⚠️  Use only with EXPLICIT PERMISSION")
        print("=" * 50)
    
    def hash_cracker_educational(self, hash_value, wordlist_path):
        """
        EDUCATIONAL: Demonstrate password hash cracking concepts
        Use only on hashes you created or have permission to test
        """
        print(f"\n🔐 Educational Hash Analysis")
        print(f"Hash: {hash_value}")
        print(f"Length: {len(hash_value)} characters")
        
        # Common hash length identification
        hash_lengths = {
            32: "MD5",
            40: "SHA-1",
            64: "SHA-256",
            96: "SHA-384",
            128: "SHA-512"
        }
        
        hash_type = hash_lengths.get(len(hash_value), "Unknown")
        print(f"Possible algorithm: {hash_type}")
        
        # Only proceed with user confirmation
        response = input(f"\nLoad wordlist from {wordlist_path}? (yes/no): ")
        if response.lower() != 'yes':
            print("Operation cancelled.")
            return
        
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, word in enumerate(f, 1):
                    word = word.strip()
                    # Test different hash algorithms
                    if hashlib.md5(word.encode()).hexdigest() == hash_value:
                        print(f"\n✅ Match found at line {i}: {word}")
                        print(f"Algorithm: MD5")
                        return word
                    elif hashlib.sha256(word.encode()).hexdigest() == hash_value:
                        print(f"\n✅ Match found at line {i}: {word}")
                        print(f"Algorithm: SHA-256")
                        return word
                    
                    # Progress indicator
                    if i % 10000 == 0:
                        print(f"Processed {i} words...", end='\r')
            
            print("\n❌ No match found in wordlist")
            
        except FileNotFoundError:
            print(f"❌ Wordlist not found: {wordlist_path}")
    
    def network_scanner_educational(self, target_ip, ports=None):
        """
        EDUCATIONAL: Basic port scanning for network awareness
        Use only on networks you own or have permission to scan
        """
        print(f"\n🌐 Educational Network Scanner")
        print(f"Target: {target_ip}")
        print("Common ports only (no privileged ports)")
        
        # Common non-privileged ports for educational purposes
        common_ports = ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080]
        
        print("\nPort scanning started...")
        print("=" * 40)
        
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    service_name = self.get_service_name(port)
                    print(f"Port {port}/TCP - OPEN - {service_name}")
                    open_ports.append(port)
                
                sock.close()
                
            except socket.error:
                pass
        
        print("=" * 40)
        print(f"Scan complete. Found {len(open_ports)} open ports.")
        
        return open_ports
    
    def get_service_name(self, port):
        """Get common service name for port"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Proxy"
        }
        return services.get(port, "Unknown")
    
    def ssl_tls_checker(self, domain):
        """
        Check SSL/TLS configuration of a website
        Legitimate security audit tool
        """
        print(f"\n🔒 SSL/TLS Configuration Check for {domain}")
        
        try:
            import ssl
            import urllib.request
            
            context = ssl.create_default_context()
            
            with urllib.request.urlopen(f"https://{domain}", context=context, timeout=5) as response:
                cert = response.info().get('Server')
                print(f"Server: {cert}")
                print(f"Status Code: {response.status}")
                print(f"SSL/TLS Connection: Successful")
                
                # Get certificate info
                cert_info = context.get_ca_certs()
                if cert_info:
                    print(f"Certificate issuer: {cert_info[0].get('issuer')}")
                
        except Exception as e:
            print(f"❌ Error: {e}")
    
    def whois_lookup_legal(self, domain):
        """
        Perform WHOIS lookup (public information)
        """
        print(f"\n📋 WHOIS Lookup for {domain}")
        
        try:
            import whois  # Requires python-whois package
            
            w = whois.whois(domain)
            
            print(f"Domain: {w.domain_name}")
            print(f"Registrar: {w.registrar}")
            print(f"Creation Date: {w.creation_date}")
            print(f"Expiration Date: {w.expiration_date}")
            print(f"Name Servers: {w.name_servers}")
            
        except ImportError:
            print("Install python-whois: pip install python-whois")
        except Exception as e:
            print(f"Error: {e}")
    
    def password_strength_checker(self, password):
        """
        Check password strength for educational purposes
        """
        print(f"\n🔐 Password Strength Analysis")
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("❌ Password too short (minimum 8 characters)")
        
        # Complexity checks
        import re
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("⚠️ Add uppercase letters")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("⚠️ Add lowercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("⚠️ Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            feedback.append("⚠️ Add special characters")
        
        # Common password check
        common_passwords = ['password', '123456', 'qwerty', 'letmein', 'welcome']
        if password.lower() in common_passwords:
            score = 0
            feedback.append("❌ This is a very common password")
        
        # Display results
        strength = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]
        print(f"Password: {'*' * len(password)}")
        print(f"Length: {len(password)} characters")
        print(f"Score: {score}/6 - {strength[min(score, 5)]}")
        
        if feedback:
            print("\nRecommendations:")
            for item in feedback:
                print(f"  {item}")
        
        return score

# Example usage
if __name__ == "__main__":
    tools = EthicalSecurityTools()
    
    print("\nAvailable educational tools:")
    print("1. Hash Analysis (Educational)")
    print("2. Network Scanner (Educational - Own networks only)")
    print("3. SSL/TLS Configuration Check")
    print("4. WHOIS Lookup (Public info)")
    print("5. Password Strength Checker")
    
    choice = input("\nSelect tool (1-5): ")
    
    if choice == '1':
        # Example with a hash you created
        test_hash = input("Enter a hash to analyze (create one with: echo -n 'test' | md5sum): ")
        wordlist = input("Wordlist path (or press enter for default): ") or "common_passwords.txt"
        tools.hash_cracker_educational(test_hash, wordlist)
    
    elif choice == '2':
        target = input("Enter target IP (must be YOUR OWN system): ")
        if input(f"Confirm you own or have permission to scan {target} (yes/no): ").lower() == 'yes':
            tools.network_scanner_educational(target)
        else:
            print("Scan cancelled. Only scan systems you own or have permission to test.")
    
    elif choice == '3':
        domain = input("Enter domain to check SSL/TLS: ")
        tools.ssl_tls_checker(domain)
    
    elif choice == '4':
        domain = input("Enter domain for WHOIS lookup: ")
        tools.whois_lookup_legal(domain)
    
    elif choice == '5':
        password = input("Enter password to check (won't be stored): ")
        tools.password_strength_checker(password)
