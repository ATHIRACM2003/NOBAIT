#DETECTION CORRECTED!!

import streamlit as st  # Move this import to the top

st.set_page_config(
    page_title="NoBait - Your Anti-Phishing Assistant",
    page_icon=":shield:",
    layout="centered",
)

import os
import re
import whois
import ssl
import socket
import tldextract
import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv
import google.generativeai as gen_ai

# Load environment variables
load_dotenv()


GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
    st.warning("⚠️ Google API key is missing. AI responses might not work.")
else:
    gen_ai.configure(api_key=GOOGLE_API_KEY)

# Basic chatbot responses
chatbot_responses = {
    "hello": "Hello! How can I assist you today?",
    "hi": "Hi there! What can I help you with?",
    "how are you": "I'm just a bot, but I'm here to help!",
    "what is phishing": "Phishing is a cyber attack where attackers impersonate legitimate entities to steal sensitive information.",
    "how to avoid phishing": "To avoid phishing, never click on suspicious links, verify sender identities, and use multi-factor authentication.",
    "tell me about ssl": "SSL (Secure Sockets Layer) is a security protocol that encrypts data between a browser and a server, making transactions secure.",
    "bye": "Goodbye! Stay safe online!",
}


# Function to check SSL certificate
def check_ssl_certificate(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            return bool(s.getpeercert())
    except Exception:
        return False


# Function to detect phishing using heuristics
def heuristic_phishing_detection(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower().replace("www.", "")

    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    domain_name = extracted.domain
    suffix = extracted.suffix

    risk_score = 0
    reasons = []

    # 🚨 1. URL Length
    if len(url) > 75:
        risk_score += 1
        reasons.append("URL is too long")

    # 🚨 2. Special Characters
    if "@" in url:
        risk_score += 2
        reasons.append("URL contains '@' symbol")
    if "-" in domain:
        risk_score += 1
        reasons.append("Domain contains hyphen ('-')")
    if "_" in url:
        risk_score += 1
        reasons.append("URL contains underscore ('_')")

    # 🚨 3. Subdomain Depth
    subdomain_depth = len(subdomain.split(".")) if subdomain else 0
    if subdomain_depth > 2:
        risk_score += 2
        reasons.append("Too many subdomains")

    # 🚨 4. IP Address Instead of Domain
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", domain):
        risk_score += 3
        reasons.append("Uses an IP address instead of a domain name")

    # 🚨 5. WHOIS Domain Age
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            if isinstance(creation_date, datetime.datetime):
                age_days = (datetime.datetime.now() - creation_date).days
                if age_days < 180:
                    risk_score += 3
                    reasons.append("Domain is newly registered (< 6 months)")
    except Exception:
        risk_score += 2
        reasons.append("WHOIS lookup failed")

    # 🚨 6. SSL Certificate Check
    if not check_ssl_certificate(domain):
        risk_score += 2
        reasons.append("No SSL Certificate (HTTP instead of HTTPS)")

    # 🚨 7. Suspicious Keywords
    phishing_keywords = ["login", "verify", "update", "secure", "account", "bank", "paypal", "security", "ebay"]
    for keyword in phishing_keywords:
        if keyword in domain:
            risk_score += 2
            reasons.append(f"Suspicious keyword found in domain: '{keyword}'")

    # 🚨 Final decision
    threshold = 5
    is_phishing = risk_score >= threshold

    return is_phishing, reasons


# Streamlit Chatbot UI
st.title(":shield: NoBait - Anti-Phishing Assistant")

# Initialize chat history if not present
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# New user input
user_input = st.chat_input("Ask about phishing or check a link...")

if user_input:
    # Store and show user message
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    # Check if the input is a URL
    url_pattern = r"\b(?:https?://|www\.)[a-zA-Z0-9.-]+\.[a-zA-Z0-9]{2,}\b"
    urls = re.findall(url_pattern, user_input)

    if urls:
        for url in urls:
            is_phish, reasons = heuristic_phishing_detection(url)
            if is_phish:
                warning_msg = f"\U0001F6A8 **Warning!** The URL `{url}` appears suspicious."
                if reasons:
                    warning_msg += "\n\nDetected Issues:"
                    for reason in reasons:
                        warning_msg += f"\n- {reason}"
                st.session_state.messages.append({"role": "assistant", "content": warning_msg})
                with st.chat_message("assistant"):
                    st.markdown(warning_msg)
            else:
                safe_msg = f"✅ The URL `{url}` seems safe, but always verify before proceeding."
                st.session_state.messages.append({"role": "assistant", "content": safe_msg})
                with st.chat_message("assistant"):
                    st.markdown(safe_msg)
    else:
        response = chatbot_responses.get(user_input.lower(), "Let me check...")

        if response == "Let me check..." and GOOGLE_API_KEY:
            try:
                model = gen_ai.GenerativeModel('gemini-2.0-flash')
                chat_session = model.start_chat()
                gemini_response = chat_session.send_message(user_input)
                response = gemini_response.text if hasattr(gemini_response, "text") else "I couldn't generate a response."
            except Exception as e:
                response = f"An error occurred: {e}"

        st.session_state.messages.append({"role": "assistant", "content": response})
        with st.chat_message("assistant"):
            st.markdown(response)
