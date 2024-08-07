# HIP.py


HIP.py is a versatile script that provides various text manipulation, encryption, and document processing functionalities, inspired by CyberChef. The script allows users to encode, decode, encrypt, and manipulate text using numerous algorithms and techniques, as well as handle document creation and email sending tasks.

```
python3.9 hip.py --help all
usage: hip.py [-h] [--lulz] [--help_all]
              {encode,decode,inject,inject_prompts,reveal_hidden_text,convert_tags,utf,case,reverse,decimal,hexadecimal,inject_hidden_prompt,prompt_injection}
              ...

Hide Injected Prompts (HIP)

positional arguments:
  {encode,decode,inject,inject_prompts,reveal_hidden_text,convert_tags,utf,case,reverse,decimal,hexadecimal,inject_hidden_prompt,prompt_injection}
                        Sub-command help
    encode              Encode ASCII Art
    decode              Decode ASCII Art
    inject              Inject hidden text
    inject_prompts      Inject hidden text with prompts
    reveal_hidden_text  Reveal hidden text
    convert_tags        Convert HTML/XML tags
    utf                 UTF-16/UTF-8 Encode/Decode
    case                Convert to Upper/Lower Case
    reverse             Reverse Text
    decimal             Convert to/From Decimal
    hexadecimal         Convert to/From Hexadecimal
    inject_hidden_prompt
                        Inject hidden prompt into document
    prompt_injection    Apply prompt injection techniques to text

optional arguments:
  -h, --help            show this help message and exit
  --lulz                Prints a fun message
  --help_all            Show all command options available
```
## Table of Contents
1. [Installation](#installation)
2. [Usage](#usage)
3. [Encryptions/Encodings Functions](#encryptionsencodings-functions)
   - [AES Encryption](#aes-encryption)
   - [Base64 Encoding](#base64-encoding)
   - [Base32 Encoding](#base32-encoding)
   - [Base85 Encoding](#base85-encoding)
   - [XOR Encryption](#xor-encryption)
   - [ROT13 Encoding](#rot13-encoding)
   - [URL Encoding](#url-encoding)
   - [HTML Entity Encoding](#html-entity-encoding)
   - [Morse Code Encoding](#morse-code-encoding)
4. [Compression/Decompression Functions](#compressiondecompression-functions)
   - [GZIP Compression](#gzip-compression)
   - [ZLIB Compression](#zlib-compression)
   - [BZIP2 Compression](#bzip2-compression)
5. [Data Formats Functions](#data-formats-functions)
   - [Hex Dump](#hex-dump)
   - [Base64 to Hex](#base64-to-hex)
   - [Hex to Base64](#hex-to-base64)
   - [Binary Conversion](#binary-conversion)
   - [UTF-16 and UTF-8 Encoding](#utf-16-and-utf-8-encoding)
6. [String Operations](#string-operations)
   - [Case Conversion](#case-conversion)
   - [Text Reversal](#text-reversal)
   - [Decimal Conversion](#decimal-conversion)
   - [Hexadecimal Conversion](#hexadecimal-conversion)
   - [Octal Conversion](#octal-conversion)
7. [Text Manipulation](#text-manipulation)
8. [Hashing Functions](#hashing-functions)
   - [MD5 Hash](#md5-hash)
   - [SHA1 Hash](#sha1-hash)
   - [SHA256 Hash](#sha256-hash)
   - [SHA512 Hash](#sha512-hash)
   - [CRC32 Hash](#crc32-hash)
9. [Miscellaneous Functions](#miscellaneous-functions)
   - [Timestamp Conversion](#timestamp-conversion)
   - [UUID Operations](#uuid-operations)
   - [Random Number Generation](#random-number-generation)
   - [Math Operations](#math-operations)
   - [JSON and XML Formatting](#json-and-xml-formatting)
10. [Document Creation Functions](#document-creation-functions)
    - [Word Document](#word-document)
    - [Excel Spreadsheet](#excel-spreadsheet)
    - [PowerPoint Presentation](#powerpoint-presentation)
    - [OneNote Document](#onenote-document)
    - [HTML Document](#html-document)
11. [Email Functions](#email-functions)
    - [Binary to Base64 Encoding](#binary-to-base64-encoding)
    - [Base64 to Binary Decoding](#base64-to-binary-decoding)
    - [Sending Emails](#sending-emails)
12. [Prompt Injection Functions](#prompt-injection-functions)
    - [Hidden Prompt Injection](#hidden-prompt-injection)
    - [Applying Prompt Injection Techniques](#applying-prompt-injection-techniques)
13. [Proofpoint URL Defense](#proofpoint-url-defense)
14. [Link Encoding/Decoding](#link-encodingdecoding)
15. [Appendix](#appendix)
    - [Code Explanation](#code-explanation)

## Installation

Before using HIP.py, ensure that you have Python 3.9 installed along with the required libraries. Install the dependencies using the following command:

```
pip3.9 install python-docx openpyxl python-pptx pycryptodome
```
Usage

HIP.py can be executed from the command line. The script supports a variety of options and commands. Below are detailed usage examples for each functionality.

Encryptions/Encodings Functions

AES Encryption

Encrypt a message:
```
python3.9 hip.py --aes-encrypt "Your message" --password "yourpassword"
```
Decrypt a message:
```
python3.9 hip.py --aes-decrypt "Encrypted message" --password "yourpassword"
```
Base64 Encoding

Encode a message in Base64:
```
python3.9 hip.py --base64-encode "Your message"
```
Decode a Base64 encoded message:

```
python3.9 hip.py --base64-decode "Base64 encoded message"
```
Base32 Encoding

Encode a message in Base32:

```
python3.9 hip.py --base32-encode "Your message"
```
Decode a Base32 encoded message:

```
python3.9 hip.py --base32-decode "Base32 encoded message"
```
Base85 Encoding

Encode a message in Base85:

```
python3.9 hip.py --base85-encode "Your message"
```
Decode a Base85 encoded message:

```
python3.9 hip.py --base85-decode "Base85 encoded message"
```
XOR Encryption

Encrypt a message with XOR:

```
python3.9 hip.py --xor-encrypt "Your message" --key "yourkey"
```
Decrypt a message with XOR:
```
python3.9 hip.py --xor-decrypt "Encrypted message" --key "yourkey"
```
ROT13 Encoding

Encode a message in ROT13:
```
python3.9 hip.py --rot13 "Your message"
```
URL Encoding

Encode a message in URL encoding:
```
python3.9 hip.py --url-encode "Your message"
```
Decode a URL encoded message:
```
python3.9 hip.py --url-decode "URL encoded message"
```
HTML Entity Encoding

Encode a message in HTML entities:
```
python3.9 hip.py --html-encode "Your message"
```
Decode HTML entities:

```
python3.9 hip.py --html-decode "HTML encoded message"
```
Morse Code Encoding

Encode a message in Morse code:
```
python3.9 hip.py --morse-encode "Your message"
```
Decode a Morse code message:
```
python3.9 hip.py --morse-decode "Morse code message"
```
Compression/Decompression Functions

GZIP Compression

Compress a message with GZIP:
```
python3.9 hip.py --gzip-compress "Your message"
```
Decompress a GZIP compressed message:
```
python3.9 hip.py --gzip-decompress "GZIP compressed message"
```
ZLIB Compression

Compress a message with ZLIB:
```
python3.9 hip.py --zlib-compress "Your message"
```
Decompress a ZLIB compressed message:

```
python3.9 hip.py --zlib-decompress "ZLIB compressed message"
```
BZIP2 Compression

Compress a message with BZIP2:
```
python3.9 hip.py --bzip2-compress "Your message"
```
Decompress a BZIP2 compressed message:
```
python3.9 hip.py --bzip2-decompress "BZIP2 compressed message"
```
Data Formats Functions

Hex Dump

Generate a hex dump of a message:
```
python3.9 hip.py --hex-dump "Your message"
```
Base64 to Hex

Convert a Base64 encoded message to hex:
```
python3.9 hip.py --base64-to-hex "Base64 encoded message"
```
Hex to Base64

Convert a hex encoded message to Base64:
```
python3.9 hip.py --hex-to-base64 "Hex encoded message"
```
Binary Conversion

Convert a message to binary:
```
python3.9 hip.py --to-binary "Your message"
```
Convert a binary message to text:
```
python3.9 hip.py --from-binary "Binary message"
```
UTF-16 and UTF-8 Encoding

Convert a message to UTF-16:
```
python3.9 hip.py --to-utf16 "Your message"
```
Convert a UTF-16 message to UTF-8:
```
python3.9 hip.py --utf16-to-utf8 "UTF-16 message"
```
Convert a message to UTF-8:
```
python3.9 hip.py --to-utf8 "Your message"
```
Convert a UTF-8 message to UTF-16:
```
python3.9 hip.py --utf8-to-utf16 "UTF-8 message"
```
String Operations

Case Conversion

Convert a message to uppercase:
```
python3.9 hip.py --uppercase "Your message"
```
Convert a message to lowercase:
```
python3.9 hip.py --lowercase "Your message"
```
Text Reversal

Reverse a message:
```
python3.9 hip.py --reverse "Your message"
```
Decimal Conversion

Convert a message to decimal:
```
python3.9 hip.py --to-decimal "Your message"
```
Convert a decimal message to text:

```
python3.9 hip.py --from-decimal "Decimal message"
```
Hexadecimal Conversion

Convert a message to hexadecimal:
```
python3.9 hip.py --to-hex "Your message"
```
Convert a hexadecimal message to text:
```
python3.9 hip.py --from-hex "Hexadecimal message"
```
Octal Conversion

Convert a message to octal:
```
python3.9 hip.py --to-octal "Your message'
```
Convert an octal message to text:
```
python3.9 hip.py --from-octal "Octal message"
```
Text Manipulation

Perform various text manipulations

Hashing Functions

MD5 Hash

Generate an MD5 hash of a message:
```
python3.9 hip.py --md5 "Your message"
```
SHA1 Hash

Generate a SHA1 hash of a message:
```
python3.9 hip.py --sha1 "Your message"
```
SHA256 Hash

Generate a SHA256 hash of a message:
```
python3.9 hip.py --sha256 "Your message"
```
SHA512 Hash

Generate a SHA512 hash of a message:
```
python3.9 hip.py --sha512 "Your message"
```
CRC32 Hash

Generate a CRC32 hash of a message:
```
python3.9 hip.py --crc32 "Your message"
```
Miscellaneous Functions

Timestamp Conversion

Convert a timestamp to human-readable format:
```
python3.9 hip.py --timestamp-to-human "timestamp"
```
Convert a human-readable date to timestamp:
```
python3.9 hip.py --human-to-timestamp "date"
```
UUID Operations

Generate a UUID:
```
python3.9 hip.py --generate-uuid
```
Convert a UUID to integer:
```
python3.9 hip.py --uuid-to-int "UUID"
```
Convert an integer to UUID:
```
python3.9 hip.py --int-to-uuid "integer"
```
Random Number Generation

Generate a random number:
```
python3.9 hip.py --random-number
```
Math Operations

Perform basic math operations:
```
python3.9 hip.py --math "operation"
```
JSON and XML Formatting

Format JSON data:
```
python3.9 hip.py --format-json "JSON data"
```
Minify JSON data:
```
python3.9 hip.py --minify-json "JSON data"
```
Pretty-print XML data:
```
python3.9 hip.py --pretty-print-xml "XML data"
```
Parse XML data:
```
python3.9 hip.py --parse-xml "XML data"
```
Document Creation Functions

Word Document

Create a Word document:

```
python3.9 hip.py --create-word "filename"
```
Excel Spreadsheet

Create an Excel spreadsheet:
```
python3.9 hip.py --create-excel "filename"
```
PowerPoint Presentation

Create a PowerPoint presentation:
```
python3.9 hip.py --create-powerpoint "filename"
```
OneNote Document

Create a OneNote document:
```
python3.9 hip.py --create-onenote "filename"
```
HTML Document

Create an HTML document:
```
python3.9 hip.py --create-html "filename" "title" "body"
```
Email Functions

Binary to Base64 Encoding

Encode a binary file to Base64:
```
python3.9 hip.py --binary-to-base64 "input_file" "output_file"
```
Base64 to Binary Decoding

Decode a Base64 file to binary:
```
python3.9 hip.py --base64-to-binary "input_base64_file" "output_file"
```
Sending Emails

Send an email:
```
python3.9 hip.py --send-email "sender" "recipient" "subject" "body" "smtp_server" "attachment_path"
```
Prompt Injection Functions

Hidden Prompt Injection

Inject a hidden prompt into a document:
```
python3.9 hip.py --inject-hidden-prompt "doc_path" "doc_type" "location" 
"payload" "is_file"
```
Applying Prompt Injection Techniques

Apply prompt injection techniques:
```
python3.9 hip.py --apply-prompt-injections "input_text" "techniques" "examples" "intermediate_prompts"
```
Proofpoint URL Defense

Decode Proofpoint URL Defense links

Decode a Proofpoint URL Defense (v3) link:
```
python3.9 hip.py --decode-url-defense "link"
```
Link Encoding/Decoding

Encode a link to Base64

Encode a link:
```
python3.9 hip.py --encode-link "link"
```
Decode a Base64 encoded link

Decode a link:
```
python3.9 hip.py --decode-link "encoded_link"
```
# Detailed Explanation

The HIP script is designed to provide a wide range of functionalities through a command-line interface. Each command is associated with a specific operation, allowing users to perform complex text processing, encryption, encoding, and other tasks with ease. The script leverages various Python libraries to implement these functionalities, ensuring high performance and reliability.

## When to Use Each Function

- **Hidden Prompt Injection**: Use this feature to inject hidden prompts into documents for testing or other purposes.
- **Text Processing**: Useful for encoding messages in ASCII art, generating text embeddings, and converting tags.
- **Encryptions/Encodings**: Use these functions for secure text encryption, encoding, and decoding.
- **Compression/Decompression**: Compress or decompress text data for efficient storage or transmission.
- **Data Formats**: Convert text to different formats for compatibility with various applications.
- **Conversion**: Change text case, reverse text, or convert text to different numeric bases.
- **String Operations**: Perform find/replace, split/join operations, and other string manipulations.
- **Hashing**: Generate hashes for data integrity verification.
- **Miscellaneous**: Perform timestamp conversions, generate/validate UUIDs, generate random numbers, perform math operations, and format/parse JSON/XML data.

## Code Explanation

The `hip.py` script is organized into various sections, each providing specific functionalities. Here is a detailed explanation of the script:

### Imports

The script begins with importing necessary libraries:

- `argparse` for parsing command-line arguments.
- `base64`, `re`, `zipfile`, `os`, `pyperclip`, `datetime`, `uuid`, `random`, `json`, `hashlib`, `binascii`, `gzip`, `zlib`, `bz2`, `urllib.parse`, `html` for various operations.
- `Crypto.Cipher` and `Crypto.Random` for AES encryption.

### Encryption/Encoding Functions

These functions handle encryption and encoding operations:

- **AES Encryption/Decryption**: Uses a password to encrypt/decrypt text using AES-GCM.
- **Base64, Base32, Base85 Encode/Decode**: Encodes/decodes text in various base formats.
- **XOR Encryption**: Encrypts text using XOR with a key.
- **ROT13**: Applies ROT13 encoding to text.
- **URL Encode/Decode**: Encodes/decodes text for safe URL transmission.
- **HTML Entity Encode/Decode**: Encodes/decodes text as HTML entities.
- **Morse Code Encode/Decode**: Encodes/decodes text in Morse code.

### Compression/Decompression Functions

These functions handle text compression and decompression:

- **Gzip, Zlib, Bzip2 Compress/Decompress**: Compresses/decompresses text using different algorithms.

### Data Formats Functions

These functions convert text between different formats:

- **Hex Dump/From Hex Dump**: Converts text to/from hexadecimal representation.
- **Base64 to Hex/Hex to Base64**: Converts text between Base64 and hexadecimal formats.
- **Binary to Hex/Hex to Binary**: Converts text between binary and hexadecimal formats.
- **UTF-16, UTF-8 Encode/Decode**: Encodes/decodes text in UTF-16 and UTF-8.

### Conversion Functions

These functions perform various text conversions:

- **Case Conversion**: Converts text to upper/lower case.
- **Reverse Text**: Reverses the order of characters in text.
- **Decimal, Hexadecimal, Octal Conversion**: Converts text to/from different numeric bases.

### String Operations Functions

These functions perform operations on strings:

- **Find/Replace**: Finds and replaces text.
- **Split/Join**: Splits text into a list or joins a list into text.
- **Length**: Calculates the length of text.
- **Truncate**: Truncates text to a specified length.
- **Pad**: Pads text to a specified length with a character.
- **Extract Regex**: Extracts text matching a regular expression.
- **Escape/Unescape**: Escapes/unescapes special characters.

### Hashing Functions

These functions generate hashes of text:

- **MD5, SHA-1, SHA-256, SHA-512**: Generates different types of hashes.
- **CRC32**: Generates a CRC32 checksum.

### Miscellaneous Functions

These functions provide various utilities:

- **Timestamp Convert**: Converts text to/from a timestamp.
- **UUID Generate/Validate**: Generates/validates UUIDs.
- **Random Number Generation**: Generates a random number in a range.
- **Math Operations**: Evaluates mathematical expressions.
- **JSON/XML Format/Parse**: Formats/parses JSON and XML data.

### Main Function

The main function sets up argument parsing and handles the different commands and options. Each command is associated with a specific operation, and the function calls the appropriate utility functions based on the command-line arguments.

## Conclusion

HIP is a powerful and versatile tool for text processing, encryption, encoding, and more. Its comprehensive set of features and flexible command-line interface make it suitable for a wide range of tasks. Whether you need to inject hidden prompts into documents, perform complex text manipulations, or secure your data with encryption, HIP has you covered.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
