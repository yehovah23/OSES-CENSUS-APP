# E:\django\my_django_projects\myproject\census\utils.py

import random
from django.utils import timezone
from django.conf import settings
from .models import OTP, CustomUser
import requests # Import the requests library

# --- Constants for OTP generation ---
OTP_CHARS = "0123456789"
# --- End Constants ---

def generate_otp_code(length=settings.OTP_LENGTH):
    """Generates a random numeric OTP code."""
    return ''.join(random.choice(OTP_CHARS) for _ in range(length))

def create_and_send_otp(phone_number):
    """
    Generates an OTP, saves it to the database, and sends it via EasySend SMS API.
    """
    # Delete any existing unverified OTPs for this phone number
    OTP.objects.filter(phone_number=phone_number, is_verified=False).delete()

    otp_code = generate_otp_code()
    expires_at = timezone.now() + timezone.timedelta(minutes=settings.OTP_EXPIRATION_MINUTES)

    otp_instance = OTP.objects.create(
        phone_number=phone_number,
        code=otp_code,
        expires_at=expires_at,
        is_verified=False
    )

    # --- EasySend SMS API Integration ---
    # Confirm this API URL with EasySend SMS documentation.
    # This is a common pattern for SMS APIs, often a gateway endpoint.
    EASYSEND_SMS_API_URL = "https://api.easysendsms.app/bulksms" # Example URL, CONFIRM THIS!

    USERNAME = settings.EASYSEND_SMS_USERNAME
    PASSWORD = settings.EASYSEND_SMS_PASSWORD
    # Remove '+' from phone_number for the 'To' parameter as per EasySend SMS documentation
    # Example: "+256771234567" becomes "256771234567"
    TO_NUMBER = phone_number.replace('+', '')
    # The 'From' parameter (Sender Name) can be alphanumeric (max 11) or numeric (max 15).
    # If your SENDER_NAME in settings.py includes '+', remove it here if it's a numeric sender ID
    # that shouldn't have the '+'. For alphanumeric sender IDs, just use as is.
    FROM_SENDER = settings.EASYSEND_SMS_SENDER_NAME

    message_body = f"Your OTP for self-enumeration is: {otp_code}. It expires in {settings.OTP_EXPIRATION_MINUTES} minutes."
    MESSAGE_TYPE = 0 # 0 for Plain text (GSM 3.38 Character encoding)

    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "From": FROM_SENDER,
        "To": TO_NUMBER,
        "Text": message_body,
        "Type": MESSAGE_TYPE
    }

    try:
        # EasySend SMS API typically uses GET or POST with form-encoded data, or sometimes JSON.
        # Given the parameters are simple key-value, form-encoded might be more common,
        # but JSON is robust. Check their documentation for exact request format (form-encoded vs JSON).
        # For now, I'll use json=payload, but be prepared to change to data=payload for form-encoded.
        response = requests.post(EASYSEND_SMS_API_URL, json=payload)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)

        # EasySend SMS might return plain text or simple success/failure.
        # You'll need to inspect their actual response to refine this.
        # Assuming a basic check for now.
        response_text = response.text
        print(f"EasySend SMS Raw Response: {response_text}") # For debugging

        # A very basic success check (e.g., if the response contains "success" or a specific code)
        # You MUST refine this based on actual EasySend SMS API successful response.
        if "OK" in response_text.upper() or "SUCCESS" in response_text.upper():
            print(f"OTP sent successfully to {phone_number} via EasySend SMS.")
            return otp_instance
        else:
            error_message = f"EasySend SMS error: {response_text}"
            print(f"Error sending SMS via EasySend SMS to {phone_number}: {error_message}")
            return None # Indicate failure to send SMS

    except requests.exceptions.RequestException as e:
        print(f"Network or API error while sending SMS to {phone_number} via EasySend SMS: {e}")
        # Log this error
        return None
    # --- End EasySend SMS API Integration ---
