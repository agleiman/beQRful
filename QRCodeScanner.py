import time  # Used to add delays between processes
import re  # Provides support for regular expressions
import base64  # Used for encoding URLs to base64 for VirusTotal
import requests  # For making HTTP requests to external APIs
import ssl  # Used to check SSL certificates of URLs
import socket  # Enables low-level networking interface for SSL check
import os  # Allows interaction with the operating system
import threading  # For running certain operations in separate threads
from urllib.parse import urlparse  # Helps to parse and extract parts of URLs
from PIL import ImageGrab  # Used to capture a screenshot of the screen
from pyzbar.pyzbar import decode, PyZbarError  # Used to decode QR codes from images and handle decoding errors
from csv_writer import CSVWriter  # Imports a custom module to write results to a CSV file
from datetime import datetime  # Provides current date and time
from concurrent.futures import ThreadPoolExecutor  # Used to run multiple functions in parallel threads

class QRScanner:  # Defines a class named QRScanner
    CSV_FILE = "QR_info.csv"  # The name of the CSV file where results will be stored
    API_KEY = "620f08e70dd2e18baaed91974a00bafc69243b54102584d5297e50b6ee01d5b5"  # VirusTotal API key
    VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/urls/"  # URL for VirusTotal API
    PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/index.php"  # URL for PhishTank API (not used here)
    GOOGLE_SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"  # Google Safe Browsing API URL
    GOOGLE_API_KEY = "AIzaSyDnrBjEv1ySf8YRQVwYYBOtElfo2sEaMDY"  # Google Safe Browsing API key

    # List of keywords or phrases commonly associated with malicious content
    MALICIOUS_PATTERNS = [
        'download', 'malicious', 'exe', 'zip', 'file', 'malware', 'phishing', 'ransomware',
        'trojan', 'virus', 'spyware', 'adware', 'keylogger', 'worm', 'backdoor', 'scam', 
        'fraud', 'stealer', 'hacker', 'crack', 'patch', 'unwanted', 'infected', 'exploit', 
        'bypass', 'fake', 'pirate', 'cracked', 'pwn', 'rootkit', 'shell', 'suspicious', 
        'attack', 'phish', 'fake', 'malvertising', 'cryptojacking', 'breach', 'zero-day',
        'spy', 'steal', 'stolen', 'unsecured', 'darkweb', 'illegitimate', 'blackhat', 
        'botnet', 'cve', 'exploit', 'flood', 'brute-force', 'do-not-click', 'dangerous', 
        'vulnerable', 'leak', 'hack', 'fraudulent', 'untrusted', 'rogue', 'dodgy', 'scammer',
        'unsafe', 'danger', 'illicit', 'unauthorized', 'malicious-redirect', 'unsafe-link',
        'unsafe-download', 'compromised', 'hidden', 'unverified', 'injection', 'spoofed',
        'targeted', 'phish-url', 'suspicious-activity', 'spamming', 'dirty', 'virus-infected',
        'fake-login', 'webshell', 'malicious-script', 'brute', 'exploit-kit', 'fake-ads', 
        'deceptive', 'stealth', 'encrypted', 'stealthy', 'hidden-redirect', 'hacked',
        'illegitimate', 'spoofed-url', 'online-threat', 'unsafe-site', 'fake-website', 
        'fake-app', 'redirects', 'malware-execution', 'fraudulent-site', 'web-exploit',
        'remote-access', 'social-engineering', 'typosquatting', 'scam-page', 'fraudulent-link',
        'trojan-horse', 'spoofing', 'misleading', 'blacklist', 'spam', 'fake-update',
        'drive-by-download', 'illegal', 'deceptive-ads', 'malicious-cookie', 'denial-of-service', 
        'fake-alert', 'critical-vulnerability', 'data-theft', 'illicit-download', 'infectious',
        'phishing-login', 'dangerous-download', 'data-leak', 'unauthorized-access', 'spoofed-email',
        'fake-social', 'fake-invoice', 'cryptocurrency-mining', 'fake-crypto-wallet', 'malicious-app',
        'crypto-malware', 'fake-crypto', 'unauthorized-transfer'
    ]
    
    SUSPICIOUS_FILE_EXTENSIONS = ['.exe', '.zip', '.rar', '.bat', '.js']  # File types commonly used for malicious downloads

    MAX_QR_LENGTH = 500  # Maximum allowed length of QR data to avoid processing very long data

    THREAD_POOL_SIZE = 4  # Number of threads to use for parallel URL safety checks

    def __init__(self):  # Constructor method to initialize the QRScanner object
        self.writer = CSVWriter(self.CSV_FILE)  # Create an instance of CSVWriter to write results to file

    def contains_malicious_patterns_or_extensions(self, url: str) -> str:  # Checks for known bad patterns or extensions in a URL
        if any(pattern in url.lower() for pattern in self.MALICIOUS_PATTERNS):  # Check if any malicious pattern exists in URL
            return "Malicious"  # Return 'Malicious' if found
        if any(url.lower().endswith(ext) for ext in self.SUSPICIOUS_FILE_EXTENSIONS):  # Check if URL ends with suspicious extension
            return "Suspicious"  # Return 'Suspicious' if extension matches
        return None  # Return None if URL seems clean

    def check_url_safety_virustotal(self, url: str) -> str:  # Checks the URL using VirusTotal API
        url_encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")  # Encode the URL in base64 format
        headers = {"x-apikey": self.API_KEY}  # Set the request header with VirusTotal API key
        try:
            response = requests.get(f"{self.VIRUSTOTAL_API_URL}{url_encoded}", headers=headers)  # Send GET request to VirusTotal
            if response.status_code == 200:  # Check if the response is successful
                data = response.json()  # Parse JSON response
                malicious_count = int(data['data']['attributes']['last_analysis_stats']['malicious'])  # Get count of engines flagging as malicious
                return "Malicious" if malicious_count > 0 else "Safe"  # Return based on count
        except requests.RequestException:
            return "Error"  # Return error if API request fails
        return "Error"  # Default error return if response is invalid

    def check_url_safety_google(self, url: str) -> str:  # Checks the URL using Google Safe Browsing API
        try:
            params = {
                'key': self.GOOGLE_API_KEY,  # Google API key
                'threatInfo': {
                    'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],  # Specify types of threats to check
                    'platformTypes': ['ANY_PLATFORM'],  # Specify platform
                    'threatEntryTypes': ['URL'],  # Type of threat entry
                    'threatEntries': [{'url': url}]  # The actual URL to check
                }
            }
            response = requests.post(self.GOOGLE_SAFE_BROWSING_API_URL, json=params)  # Send POST request with threat parameters
            if response.status_code == 200 and 'matches' in response.json():  # If matches found in response
                return "Malicious"  # URL is malicious
        except requests.RequestException:
            return "Error"  # Return error if request fails
        return "Safe"  # Return safe if no matches found

    def check_ssl_certificate(self, url: str) -> str:  # Checks if the URL has a valid SSL certificate
        try:
            parsed_url = urlparse(url)  # Parse the URL to extract hostname
            with ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=parsed_url.hostname) as s:  # Create a secure socket connection
                s.connect((parsed_url.hostname, 443))  # Connect to the server on port 443
                s.getpeercert()  # Get SSL certificate
                return "Safe"  # If certificate is retrieved, return safe
        except Exception:
            return "Invalid SSL"  # If any error occurs, consider SSL invalid

    def is_url_malicious(self, url: str) -> str:  # Main function to determine if a URL is malicious
        result = self.contains_malicious_patterns_or_extensions(url)  # First check for bad patterns or extensions
        if result:
            return result  # Return immediately if malicious or suspicious

        with ThreadPoolExecutor(max_workers=self.THREAD_POOL_SIZE) as executor:  # Create thread pool to check URL in parallel
            checks = list(executor.map(lambda f: f(url), [  # Run all safety checks concurrently
                self.check_url_safety_virustotal,
                self.check_url_safety_google,
                self.check_ssl_certificate
            ]))

        return "Malicious" if any(check == "Malicious" for check in checks) else "Safe"  # Final verdict

    def capture_and_save(self):  # Captures the screen and decodes QR codes from it
        screenshot = ImageGrab.grab()  # Capture a screenshot of the full screen
        try:
            decoded_objects = decode(screenshot)  # Attempt to decode any QR codes in the screenshot
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Get current timestamp

            if decoded_objects:  # If any QR codes were found
                for obj in decoded_objects:
                    qr_data = obj.data.decode('utf-8', errors='ignore')  # Decode QR data to text

                    if len(qr_data) > self.MAX_QR_LENGTH:  # Check if data is too long
                        qr_data = "Data Too Large"  # Replace with warning if it is

                    if re.match(r'https?://', qr_data):  # Check if the data is a URL
                        thread = threading.Thread(target=self.process_qr_url, args=(timestamp, qr_data))  # Start a thread to process URL
                        thread.start()  # Start thread
                        thread.join()  # Wait for thread to complete
                        time.sleep(0.1)  # Add a short delay
                    else:
                        print(f"| {timestamp:<21} | {qr_data[:28]:<29} | {'Non-URL':<17} |", flush=True)  # Print non-URL data
            else:
                print(f"| {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<21} | {'No QR code detected':<29} | {'No QR code':<16} |", flush=True)  # No QR code found

        except PyZbarError as e:  # Catch errors related to QR decoding
            print(f"Error decoding QR Code: {str(e)}", flush=True)
        except Exception as e:  # Catch any other exceptions
            print(f"QR Read Failed: {str(e)}", flush=True)

    def process_qr_url(self, timestamp, qr_data):  # Processes a decoded QR URL
        response = self.is_url_malicious(qr_data)  # Check if the URL is safe
        self.writer.write_to_csv(f"{timestamp}, {qr_data}, {response}")  # Save result to CSV
        print(f"| {timestamp:<21} | {qr_data[:28]:<29} | {response:<16} |", flush=True)  # Print result to console

if __name__ == "__main__":  # Entry point of the script
    qr_scanner = QRScanner()  # Create an instance of QRScanner
