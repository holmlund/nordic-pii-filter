# Nordic PII Filter

A Nordic PII (Personally Identifiable Information) filter for Open-Webui. Originally based on the work of [justinh-rahb](https://openwebui.com/f/justinrahb/pii_filter) but reworked and adapted for use in the Nordic countries (Sweden, Norway, Denmark & Finland).

## Description

This project provides a Python-based PII redaction filter specifically designed for Nordic countries (Sweden, Norway, Denmark, Finland, and Iceland). It can detect and redact various types of personal information in text, including:

- Nordic personal numbers
- Email addresses
- Phone numbers
- Credit card numbers
- US social security numbers
- IP addresses

## Features

- Customizable redaction options
- Support for both incoming and outgoing message processing
- Configurable admin settings
- Error logging with PII protection

## Installation

Add as a filter in the Open-Webui filter section.

## Configuration

The filter can be configured using `Valves` 

## License

This project is licensed under the MIT License.

## Acknowledgments

- Original PII Filter by justinh-rahb
- Sponsored by Digitalist Open Tech
