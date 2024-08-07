# HIP.py

`HIP.py` is a versatile script that provides various text manipulation, encryption, and document processing functionalities, inspired by CyberChef. The script allows users to encode, decode, encrypt, and manipulate text using numerous algorithms and techniques, as well as handle document creation and email sending tasks.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Encryptions/Encodings Functions](#encryptionsencodings-functions)
    - [AES Encryption](#aes-encryption)
    - [Base64 Encoding](#base64-encoding)
    - [Base32 Encoding](#base32-encoding)
    - [Base85 Encoding](#base85-encoding)
    - [XOR Encryption](#xor-encryption)
    - [ROT13 Encoding](#rot13-encoding)
    - [URL Encoding](#url-encoding)
    - [HTML Entity Encoding](#html-entity-encoding)
    - [Morse Code Encoding](#morse-code-encoding)
  - [Compression/Decompression Functions](#compressiondecompression-functions)
    - [GZIP Compression](#gzip-compression)
    - [ZLIB Compression](#zlib-compression)
    - [BZIP2 Compression](#bzip2-compression)
  - [Data Formats Functions](#data-formats-functions)
    - [Hex Dump](#hex-dump)
    - [Base64 to Hex](#base64-to-hex)
    - [Hex to Base64](#hex-to-base64)
    - [Binary Conversion](#binary-conversion)
    - [UTF-16 and UTF-8 Encoding](#utf-16-and-utf-8-encoding)
  - [String Operations](#string-operations)
    - [Case Conversion](#case-conversion)
    - [Text Reversal](#text-reversal)
    - [Decimal Conversion](#decimal-conversion)
    - [Hexadecimal Conversion](#hexadecimal-conversion)
    - [Octal Conversion](#octal-conversion)
    - [Text Manipulation](#text-manipulation)
  - [Hashing Functions](#hashing-functions)
    - [MD5 Hash](#md5-hash)
    - [SHA1 Hash](#sha1-hash)
    - [SHA256 Hash](#sha256-hash)
    - [SHA512 Hash](#sha512-hash)
    - [CRC32 Hash](#crc32-hash)
  - [Miscellaneous Functions](#miscellaneous-functions)
    - [Timestamp Conversion](#timestamp-conversion)
    - [UUID Operations](#uuid-operations)
    - [Random Number Generation](#random-number-generation)
    - [Math Operations](#math-operations)
    - [JSON and XML Formatting](#json-and-xml-formatting)
  - [Document Creation Functions](#document-creation-functions)
    - [Word Document](#word-document)
    - [Excel Spreadsheet](#excel-spreadsheet)
    - [PowerPoint Presentation](#powerpoint-presentation)
    - [OneNote Document](#onenote-document)
    - [HTML Document](#html-document)
  - [Email Functions](#email-functions)
    - [Binary to Base64 Encoding](#binary-to-base64-encoding)
    - [Base64 to Binary Decoding](#base64-to-binary-decoding)
    - [Sending Emails](#sending-emails)
  - [Prompt Injection Functions](#prompt-injection-functions)
    - [Hidden Prompt Injection](#hidden-prompt-injection)
    - [Applying Prompt Injection Techniques](#applying-prompt-injection-techniques)
  - [Proofpoint URL Defense](#proofpoint-url-defense)
  - [Link Encoding/Decoding](#link-encodingdecoding)
- [Appendix](#appendix)
  - [Code Explanation](#code-explanation)

## Installation

Before using `HIP.py`, ensure that you have Python 3.9 installed along with the required libraries. Install the dependencies using the following command:

```
pip3.9 install python-docx openpyxl python-pptx pycryptodome
```
