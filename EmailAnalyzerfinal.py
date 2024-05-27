import streamlit as st
import email
from email.header import decode_header
from email.utils import parsedate_to_datetime
from bs4 import BeautifulSoup
from email import message_from_file
from summarizer import Summarizer
import re
import requests
import html


# Define functions outside of main()
def extract_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(part.get_content_charset(), errors='ignore')
    else:
        content_type = msg.get_content_type()
        if content_type == 'text/plain':
            payload = msg.get_payload(decode=True)
            if payload:
                return payload.decode(msg.get_content_charset(), errors='ignore')
    return '' 

def analyze_email_body(email_body):
    urls = extract_urls(email_body)
    for url in urls:
        if is_phishing_url(url):
            st.warning(f"Phishing URL detected:{url}")

    # Analyze the email body for keywords related to phishing or spam
    #phishing_keywords = ['password', 'account', 'urgent', 'verify', 'login', 'reset', 'suspicious', 'unusual']
    #for keyword in phishing_keywords:
    #    if keyword in email_body.lower():
    #        st.warning(f"Phishing keyword detected in email body:{keyword}")


def extract_urls(text):
    return re.findall(r'https?://\S+', text)

def is_phishing_url(url):
    try:
        response = requests.get(url)
        return response.status_code != 200
    except Exception as e:
        st.error(f"Error while checking URL:{e}")
        return False

st.set_page_config(layout="wide")

custom_css = """
<style>
.stApp {
    background-color: #000000; /* dark blue background */
    color: #00FF00; /* green text */
}

.box {
    background-color: #000000; /* dark blue background */
    color: #00FF00; /* green text */
    border: 2px solid #00FF00; /* green border */
    border-radius: 20px;
    padding: 10px;
    margin: 10px;
}
</style>
"""

# Function to generate box shape HTML
def create_box(content):
    return f"""
    <div class="box">
        {content}
    </div>
    """

# Apply custom CSS
st.markdown(custom_css, unsafe_allow_html=True)

# Define your VirusTotal API key
API_KEY = "72bfd0d1cb696840a98f44f33f26c4dcc58ef6c2cb57d04df2e73ebee50624ef"

def extract_attachments(msg):
    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition'):
            attachments.append(part)
    return attachments

def is_potentially_malicious(attachment):
    filename = attachment.get_filename()
    try:
        url_upload = "https://www.virustotal.com/api/v3/files"

        files = {"file": (filename, attachment.get_payload(decode=True))}
        headers_upload = {"x-apikey": API_KEY}

        response_upload = requests.post(url_upload, files=files, headers=headers_upload)

        if response_upload.status_code == 200:
            analysis_id = response_upload.json()["data"]["id"]

            url_analysis = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            headers_analysis = {"x-apikey": API_KEY}

            response_analysis = requests.get(url_analysis, headers=headers_analysis)

            if response_analysis.status_code == 200:
                mal = response_analysis.json()["data"]["attributes"]["stats"]["malicious"]
                sus = response_analysis.json()["data"]["attributes"]["stats"]["suspicious"]
                hless = response_analysis.json()["data"]["attributes"]["stats"]["harmless"]
                undtd = response_analysis.json()["data"]["attributes"]["stats"]["undetected"]
                st.write("Analysis results for", filename)
                st.write(" - *Malicious:*", mal)
                st.write(" - *Suspicious:*", sus)
                st.write(" - *Harmless:*", hless)
                st.write(" - *Undetected:*", undtd)
                return mal > 0 or sus > 0
            else:
                st.error("Analysis request failed for", filename)
        
        else:
            st.error("Upload request failed for", filename)
        
    except Exception as e:
        st.error(f"Error while scanning with VirusTotal: {e}")
    
    return False

def extract_ip_from_received_header(received_header):
    ip_addresses = []
    for header in received_header:
        ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', header)
        if ip_match:
            ip_addresses.append(ip_match.group(1))
    return ip_addresses

def scrape_threatpost(page_num):
    url = f'https://threatpost.com/page/{page_num}'
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    articles = []
    for article in soup.find_all('article'):
        title = article.find('h2').text.strip()
        link = article.find('a')['href']
        articles.append({'title': title, 'link': link})
    
    return articles

def extract_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(part.get_content_charset(), errors='ignore')
    else:
        content_type = msg.get_content_type()
        if content_type == 'text/plain':
            payload = msg.get_payload(decode=True)
            if payload:
                return payload.decode(msg.get_content_charset(), errors='ignore')
    return ''

def summarize_eml_content(eml_content):
    # Create a BERT summarizer
    bert_model = Summarizer()

    # Generate the summary
    bert_summary = bert_model(eml_content, min_length=60)

    return bert_summary

def check_social_engineering(email_text):
    try:
    # Parse the email text
        msg = email.message_from_string(email_text)

        # Extract email body
        if msg.is_multipart():
            body = ''.join(part.get_payload(decode=True).decode('utf-8') for part in msg.get_payload())
        else:
            body = msg.get_payload(decode=True).decode('utf-8')

        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='ignore')

        suspicious_patterns = {
                'urgent': r'\b(?:urgent)\b',
                'important': r'\b(?:important)\b',
                'verify': r'\b(?:verify)\b',
                'validate': r'\b(?:validate)\b',
                'confirm': r'\b(?:confirm)\b',
                'password': r'\b(?:password)\b',
                'login': r'\b(?:login)\b',
                'account': r'\b(?:account)\b',
                'click': r'\b(?:click)\b',
                'download': r'\b(?:download)\b',
                'open': r'\b(?:open)\b',
                'access': r'\b(?:access)\b',
                'install': r'\b(?:install)\b',
                'free': r'\b(?:free)\b',
                'prize': r'\b(?:prize)\b',
                'lottery': r'\b(?:lottery)\b',
                'win': r'\b(?:win)\b',
                'claim': r'\b(?:claim)\b',
                'phishing': r'\b(?:phishing)\b',
                'scam': r'\b(?:scam)\b',
                'fraud': r'\b(?:fraud)\b',
                'hack': r'\b(?:hack)\b',
            }

        detected_patterns = []
        for pattern_name, pattern_regex in suspicious_patterns.items():
            if re.search(pattern_regex, body, flags=re.IGNORECASE):
                detected_patterns.append(pattern_name)

        if detected_patterns:
            return detected_patterns
        else:
            return None  # Return None if no suspicious patterns detected

    except Exception as e:
        #st.error(f"Error while analyzing email content: {e}")
        return None



def main():
    st.title("Email Analyzer")
    uploaded_file = st.file_uploader("Upload an email file", type="eml")

    # Create four square boxes
    col1, col2, col3, col4 = st.columns(4)

    if uploaded_file:
        email_bytes = uploaded_file.getvalue()
        msg = email.message_from_bytes(email_bytes)
        email_content = extract_email_body(msg)
        summary = summarize_eml_content(email_content)
        email_text = uploaded_file.getvalue().decode("utf-8")
        msgg = email.message_from_string(email_text)
        
        # Decode and format subject
        subject = decode_header(msg.get('Subject', ''))[0][0]
        subject = subject.decode('utf-8') if isinstance(subject, bytes) else subject
        
        # Format date
        date = parsedate_to_datetime(msg.get('Date', ''))
        formatted_date = date.strftime('%Y-%m-%d %H:%M:%S %Z') if date else None
        
        # Extract other headers
        sender = msg.get('From', '').split('<', 1)[-1].rstrip('>')
        receiver = msg.get('To', '').split('<', 1)[-1].rstrip('>')
        message_id = msg.get('Message-ID', '')
        received_from = [value for key, value in msg.items() if key.lower() == 'received']
        ip_addresses = extract_ip_from_received_header(received_from)

        with col1:
            st.subheader("Email Header Information")
            st.markdown(create_box(f"Sender: {sender} <br> Receiver: {receiver} <br> Subject: {subject} <br> Date: {formatted_date}"), unsafe_allow_html=True)
            
            st.write("*Received From:*")
            received_box_content = "<ul>"
            for rf in received_from:
                encoded_rf = html.escape(rf)
                received_box_content += f"<li>{encoded_rf}</li>"
            received_box_content += "</ul>"
            st.markdown(create_box(received_box_content), unsafe_allow_html=True)

                # st.markdown(create_box(f" - {rf}"), unsafe_allow_html=True)
                #st.write(f" - {rf}")
                # Extract IP address from Received header
                

            if date and date.year < 2007:
                st.warning("Unusual message date.")
            if len(received_from) > 2:
                st.warning("Multiple 'Received' headers detected, potential email forwarding.")
            if 'urgent' in subject.lower():
                st.warning("Subject line contains the word 'urgent'. Potential spam.")
            if 'localhost' in message_id:
                st.warning("Message ID contains 'localhost'. Potential spoofing.")


        with col2:
            st.subheader("Email Body Analysis")
        
            email_body = extract_email_body(msg)
            analyze_email_body_result = analyze_email_body(email_body)
            st.write(analyze_email_body_result)

            st.subheader("Phishing Detection")
            phishing_patterns = check_social_engineering(email_text)
            if phishing_patterns is not None:
                #warning_message=("Suspicious patterns detected in email body:", ", ".join(phishing_patterns))
                #st.warning(warning_message)
                warning_message = "Phishing keywords detected in email body: "
                #st.warning("Phishing keywords detected in email body:")
                warning_message += ", ".join(phishing_patterns)
                st.warning(warning_message)
            else:
                st.info("No suspicious phishing patterns detected.")
            
            st.subheader("Sender Reputation Analysis")
            ip_address = None  # Initialize ip_address variable here
            for rf in received_from:
                ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', rf)
                if ip_match:
                    ip_address = ip_match.group(1)
                    break  # Exit the loop once IP address is found
            try:
                if ip_address:
                    ip_analysis = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

                    header = {"x-apikey": API_KEY}

                    response_upload = requests.get(ip_analysis, headers=header)

                if response_upload.status_code == 200:
                    malicious = response_upload.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
                    suspicious = response_upload.json()["data"]["attributes"]["last_analysis_stats"]["suspicious"]
                    harmless = response_upload.json()["data"]["attributes"]["last_analysis_stats"]["harmless"]
                    st.write("Analysis results for", ip_address)
                    st.write(" - *Malicious:*", malicious)
                    st.write(" - *Suspicious:*", suspicious)
                    st.write(" - *Harmless:*", harmless)

                    last_analysis_results = response_upload.json()['data']['attributes']['last_analysis_results']
                    # Extract engine names that are marked as malicious
                    
                    
                    
                    # Print the malicious engine names
                    if malicious>0:
                        malicious_engines = [engine_name for engine_name, result in last_analysis_results.items() if result['result'] == 'malicious']
                        st.write("Malicious Engines:")
                        for engine_name in malicious_engines:
                            st.write(" -", engine_name)

                    if suspicious>0:
                        suspicious_engines = [engine_name for engine_name, result in last_analysis_results.items() if result['result'] == 'suspicious']
                        st.write("Suspicious Engines:")
                        for engine_name1 in suspicious_engines:
                            st.write(" -", engine_name1)

                else:
                    st.error("Analysis request failed for", ip_address)
                
            except Exception as e:
                st.error(f"Error while scanning with VirusTotal: {e}")

            


        with col3:
            st.subheader("Attachment Analysis")
            attachments = extract_attachments(msg)
            attachment_count = 1
            if attachments:
                st.write("*Attachments found*")
                for attachment in attachments:
                    filename = attachment.get_filename()
                    content_type = attachment.get_content_type()
                    file_size = len(attachment.get_payload(decode=True))
                    st.markdown(f"### Attachment {attachment_count}")
                    attachment_count += 1
                    st.write(" - *Filename:*", filename)
                    st.write(" - *Content Type:*", content_type)
                    st.write(" - *File Size:*", file_size/(1024*1024), "Mb")
                    if is_potentially_malicious(attachment):
                        st.warning("   Warning: Potentially malicious file detected:", filename)
                        # You can add further actions here, like quarantining the file
            else:
                st.write("No attachments found.")

            st.subheader("Email Content Summary")
            st.write(summary)

            st.title("Threatpost Articles")

            # Number of pages to scrape
            num_pages = 3

            # Terms to filter articles
            filter_terms = ['cybersecurity', 'emails', 'attacks', 'email']

            all_articles = []
            for page_num in range(1, num_pages + 1):
                all_articles.extend(scrape_threatpost(page_num))

            # Display only the top 10 articles that contain the filter terms
            count = 0
            for article in all_articles:
                article_title = article['title'].lower()
                if any(term in article_title for term in filter_terms):
                    st.write(f"[{article['title']}]({article['link']})")
                    count += 1
                if count == 10:
                    break


        with col4:
            st.subheader("Header Forgery Analysis:")
            # Check for inconsistencies in sender's domain
            sender_domain = re.search(r"@[\w.]+", msg.get("From", "")).group(0).lower()
            if sender_domain not in msg.get("Received", ""):
                st.warning("Sender's domain does not match Received headers.")
            # Check for inconsistencies in message ID
            message_id = msg.get("Message-ID", "").lower()
            if not message_id.startswith("<") or not message_id.endswith(">"):
                st.warning("Message ID is not formatted correctly.")
            # Check for inconsistencies in routing information
            received_headers = msg.get_all("Received", [])
            for received in received_headers:
                if "from" in received.lower() and "by" in received.lower() and "with" in received.lower():
                    continue
                else:
                    st.warning(f"Received header does not contain expected routing information: {received.strip()}")
            
            st.subheader("Compliance Checks:")
            # Check DMARC, DKIM, and SPF
            dmarc = msg.get("Authentication-Results", "").lower()
            if "dmarc=pass" not in dmarc:
                st.warning("DMARC check failed.")
            else:
                st.success("DMARC check passed.")
            dkim = msg.get("DKIM-Signature", "").lower()
            if "dkim=pass" not in dkim:
                st.warning("DKIM check failed.")
            else:
                st.success("DKIM check passed.")
            spf = msg.get("Received-SPF", "").lower()
            if "pass" not in spf:
                st.warning("SPF check failed.")
            else:
                st.success("SPF check passed.")

            st.subheader("Network Forensics:")
            # Analyze SMTP logs
            smtp_logs = msg.get_all("Received", [])
            for log in smtp_logs:
                st.write("SMTP Log:", log)
            # Analyze email server logs
            email_server_logs = msg.get_all("X-Mailer", [])
            for log in email_server_logs:
                st.write("Email Server Log:", log)
            # Analyze firewall logs
            firewall_logs = msg.get_all("X-Originating-IP", [])
            for log in firewall_logs:
                st.write("Firewall Log:", log)

    else:
        st.write("no file uploaded")


if __name__ == "__main__":
    main()
