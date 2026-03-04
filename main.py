import re
from email.utils import parseaddr
import requests
import email
import os
from dotenv import load_dotenv
from email import policy
from urllib.parse import urlparse
import hashlib
load_dotenv('VT_API_KEY.env')
vt_key = os.getenv('VT_KEY')
points = 0
def headers_analysis(email_file):
    global points
    with open(email_file, 'rb') as file: 
        msg = email.message_from_binary_file(file, policy=policy.default)
    
    sender_raw = msg.get('From')
    reply_to_raw = msg.get('Reply-To')

    sender_clean = parseaddr(sender_raw)[1].lower()
    reply_to_clean = parseaddr(reply_to_raw)[1].lower()

    print(f"Sender: {sender_clean}")
    print(f"Reply-To: {reply_to_clean}")
    
    if reply_to_clean != "":
        if sender_clean != reply_to_clean:
            print("Warning: Sender and Reply-To addresses do not match. This could be a phishing attempt.")
            points += 4
        else:
            print("Sender and Reply-To addresses match. This is less likely to be a phishing attempt.")
    else:
        print("No Reply-To address found. This is less likely to be a phishing attempt.")
def url_analysis(email_file):
    global points
    with open(email_file, 'rb') as file:
        msg = email.message_from_binary_file(file, policy=policy.default)
    
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, msg.as_string())
    if not urls:
        print("No URLs found in the email. This is less likely to be a phishing attempt.")
        return
    if os.path.exists('blacklist.txt'):
        with open('blacklist.txt', 'r') as f:
            blacklist = [line.strip().lower() for line in f if line.strip()]
    else:
        blacklist = []

    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        print(f"URL: {url}")
        print(f"Domain: {domain}")
        
        is_blacklisted = False
        for blacklisted_domain in blacklist:
            if blacklisted_domain in domain:
                print(f"CRITICAL Warning: Domain {domain} is on the blacklist! High likelihood of phishing.")
                points += 10
                is_blacklisted = True
                break
                
        if is_blacklisted:
            continue
        
        suspicious_words = ['login', 'secure', 'account', 'update', 'verify']
        for word in suspicious_words:
            if word in domain:
                print("Warning: URL contains suspicious words. This could be a phishing attempt.")
                points += 5
                break
        else:
            print("URL does not contain suspicious words and is not blacklisted. This is less likely to be a phishing attempt.")
    
def text_scan(email_file):
    global points
    with open(email_file, 'rb') as file:
        msg = email.message_from_binary_file(file, policy=policy.default)
    
    body_part = msg.get_body(preferencelist=('plain'))
    if body_part:
        email_text = body_part.get_content()
    else:
        email_text = msg.get_payload(decode=True).decode(errors='ignore') 
    # print(f"Email Text: {email_text}")
    
    suspicious_phrases = ['urgent', 'immediately', 'click here', 'verify your account']
    for word in suspicious_phrases:
        if word in email_text.lower():
            print("Warning: Email text contains suspicious phrases. This could be a phishing attempt.")
            points += 3
            break
    else:
        print("Email text does not contain suspicious phrases. This is less likely to be a phishing attempt.")

def virustotal_scan(email_file):
    global points
    if not vt_key:
        print("VirusTotal API key not found. Skipping VirusTotal scan.")
        return
    sha256_hash = hashlib.sha256()
    with open(email_file, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    headers_api = {'x-apikey': vt_key}
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    response = requests.get(url, headers=headers_api)
    if response.status_code == 200:
        data = response.json()
        if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            print("Warning: VirusTotal scan detected malicious content. This is a strong indication of a phishing attempt.")
            points += 10
        else:
            print("VirusTotal scan did not detect malicious content. This is less likely to be a phishing attempt.")
    elif response.status_code == 404:
        print("File not found in VirusTotal. This is a new file that has not been analyzed before.")
        with open(email_file, 'rb') as f:
            files = {'file': (email_file, f)}
            post_response = requests.post('https://www.virustotal.com/api/v3/files', headers=headers_api, files=files)
        
        if post_response.status_code == 200:
            print("File successfully uploaded to VirusTotal for analysis.")
            print(f"You can check the results later at: https://www.virustotal.com/gui/file/{file_hash}")
        else:
            print(f"Failed to upload file to VirusTotal. Status: {post_response.status_code}")
            
    else:
        print(f"Unexpected response status from VirusTotal: {response.status_code}")

def summary_report():
    print(f"Total Phishing Score: {points}")
    if points >= 15:
        print("High likelihood of phishing attempt.")
    elif points >= 5:
        print("Moderate likelihood of phishing attempt.")
    else:
        print("Low likelihood of phishing attempt.")

def main():
    email_file = input("Enter the name of file or path to the email file: ")
    if os.path.isfile(email_file):
        headers_analysis(email_file)
        url_analysis(email_file)
        text_scan(email_file)
        virustotal_scan(email_file)
        summary_report()
    else:
        print("File not found. Please check the file name and try again.")

if __name__ == "__main__":
    main()