"""Synthetic fixture: hardcoded credentials committed to source."""

import boto3
import requests

# VULNERABLE: real-shaped AWS key pair hardcoded in source.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABLE: DB connection string with plaintext password.
DATABASE_URL = "postgresql://admin:SuperSecret123!@prod-db.internal:5432/app"

# VULNERABLE: third-party API key hardcoded. The value is deliberately
# NOT a real-looking key (breaks the alphanumeric run GitHub's secret
# scanner and Stripe's own key-format regex match on) -- this is a static
# eval fixture, not a runtime credential, and doesn't need to be
# byte-for-byte key-shaped for the LLM to recognize "hardcoded API key
# assigned to a variable passed as Stripe auth" as the vulnerability.
STRIPE_SECRET_KEY = "sk_live_<PLACEHOLDER_HARDCODED_IN_SOURCE_NOT_A_REAL_KEY>"


def get_s3_client():
    return boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )


def charge_customer(amount_cents: int, customer_id: str):
    return requests.post(
        "https://api.stripe.com/v1/charges",
        auth=(STRIPE_SECRET_KEY, ""),
        data={"amount": amount_cents, "customer": customer_id},
    )
