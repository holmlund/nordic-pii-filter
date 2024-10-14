"""
title: Nordic PII Redaction Filter
author: David Holmlund (adapted from justinh-rahb PII Filter)
author_url: https://github.com/holmlund
sponsor: Digitalist Open Tech
original_author_url: https://github.com/justinh-rahb
funding_url: https://github.com/open-webui
version: 1.1
license: MIT
"""

import re
from pydantic import BaseModel, Field
from typing import Optional, Dict, Pattern
import logging

# Set up logging to only show errors
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


class Filter:
    class Valves(BaseModel):
        priority: int = Field(
            default=0, description="Priority level for the filter operations."
        )
        redact_nordic_personal_number: bool = Field(
            default=True,
            description="Redact Nordic (Swedish, Danish, Norwegian, Finnish) personal numbers.",
        )
        redact_email: bool = Field(default=True, description="Redact email addresses.")
        redact_phone: bool = Field(default=True, description="Redact phone numbers.")
        redact_ssn: bool = Field(
            default=False, description="Redact US social security numbers."
        )
        redact_credit_card: bool = Field(
            default=True, description="Redact credit card numbers."
        )
        redact_ip_address: bool = Field(
            default=True, description="Redact IP addresses."
        )
        enabled_for_admins: bool = Field(
            default=True,
            description="Whether PII Redaction is enabled for admin users.",
        )
        redact_outlet: bool = Field(
            default=False,
            description="Whether to redact PII in outgoing messages.",
        )

    def __init__(self):
        self.valves = self.Valves()
        self.patterns: Dict[str, Pattern] = {
            "nordic_personal_number": re.compile(
                r"\b(?:"
                # Swedish format
                r"(?:19|20)?\d{2}"  # Year (YY or YYYY)
                r"(?:0[1-9]|1[0-2])"  # Month (01-12)
                r"(?:0[1-9]|[12]\d|3[01])"  # Day (01-31)
                r"[-]?\d{4}|"
                # Norwegian format
                r"(?:0[1-9]|[12][0-9]|3[01])"  # Day (01-31)
                r"(?:0[1-9]|1[0-2])"  # Month (01-12)
                r"\d{7}|"
                # Finnish format
                r"(?:0[1-9]|[12]\d|3[01])"  # Day (01-31)
                r"(?:0[1-9]|1[0-2])"  # Month (01-12)
                r"(?:\d{2}[+\-A-Y])"  # Year and century sign
                r"(?:\d{4}|\d{3}[\dA-Y])|"
                # Danish format
                r"(?:0[1-9]|[12][0-9]|3[01])"  # Day (01-31)
                r"(?:0[1-9]|1[0-2])"  # Month (01-12)
                r"\d{2}"  # Year (YY)
                r"[-]?\d{4}"  # Optional separator and four digits
                r")\b"
            ),
            "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            "phone": re.compile(
                r"""
                \b                                # Word boundary
                (?:                               # Optional country code group
                    (?:\+|00)                     # Plus sign or 00
                    (?:45|46|47|354|358)          # Country codes: DK, SE, NO, IS, FI
                    [\s-]?                        # Optional separator after country code
                )?
                (?:\d[\s-]?){6,10}                # 6 to 10 digits with optional separators
                \b                                # Word boundary
                """,
                re.VERBOSE
            ),
            "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
            "ip_address": re.compile(
                r"""
                \b
                (?:
                    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
                    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
                    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
                    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
                )
                \b
                """,
                re.VERBOSE
            ),
        }

    def safe_log_error(self, message: str, error: Exception) -> None:
        """
        Safely log an error without potentially exposing PII.

        Args:
            message (str): The error message.
            error (Exception): The exception that was raised.
        """
        error_type = type(error).__name__
        logger.error(f"{message}: {error_type}")

    def redact_pii(self, text: str) -> str:
        """
        Redact personally identifiable information from the given text.

        Args:
            text (str): The input text to redact.

        Returns:
            str: The text with PII redacted.
        """
        redaction_map = {
            "nordic_personal_number": (
                "[PERSONAL NUMBER REDACTED]",
                self.valves.redact_nordic_personal_number,
            ),
            "email": ("[EMAIL REDACTED]", self.valves.redact_email),
            "phone": ("[PHONE REDACTED]", self.valves.redact_phone),
            "ssn": ("[SSN REDACTED]", self.valves.redact_ssn),
            "credit_card": ("[CREDIT CARD REDACTED]", self.valves.redact_credit_card),
            "ip_address": ("[IP ADDRESS REDACTED]", self.valves.redact_ip_address),
        }

        for pattern_name, (replacement, should_redact) in redaction_map.items():
            if should_redact:
                pattern = self.patterns.get(pattern_name)
                if pattern:
                    try:
                        text = pattern.sub(replacement, text)
                    except Exception as e:
                        self.safe_log_error(f"Error redacting {pattern_name}", e)

        return text

    def inlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        """
        Process incoming messages, redacting PII if necessary.

        Args:
            body (dict): The message body containing the messages.
            __user__ (Optional[dict]): User information, if available.

        Returns:
            dict: The processed message body.
        """
        try:
            if (
                __user__ is None
                or __user__.get("role") != "admin"
                or self.valves.enabled_for_admins
            ):
                messages = body.get("messages", [])
                for message in messages:
                    if message.get("role") == "user":
                        content = message.get("content", "")
                        message["content"] = self.redact_pii(content)
        except Exception as e:
            self.safe_log_error("Error processing inlet", e)

        return body

    def outlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        """
        Process outgoing messages, redacting PII if necessary.

        Args:
            body (dict): The message body to be sent.
            __user__ (Optional[dict]): User information, if available.

        Returns:
            dict: The processed message body.
        """
        try:
            if self.valves.redact_outlet and (
                __user__ is None
                or __user__.get("role") != "admin"
                or self.valves.enabled_for_admins
            ):
                messages = body.get("messages", [])
                for message in messages:
                    if message.get("role") == "assistant":
                        content = message.get("content", "")
                        message["content"] = self.redact_pii(content)
        except Exception as e:
            self.safe_log_error("Error processing outlet", e)

        return body