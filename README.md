# HIP.py
```
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⡙⠿⣿⣿⣿⣿⣿⣿⣿⣿⠋⢹⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⢻⣦⣌⠻⣿⣿⣿⣿⣿⢃⣴⡆⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠘⣿⣿⣷⣌⠻⣿⠟⣡⣾⣿⡇⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⣿⣿⣿⣿⣷⣤⣾⣿⣿⣿⠁⣿⣿⣿⠿⠿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡋⣛⣛⠿⠟⣛⣛⣸⣿⣿⡿⠟⠛⠛⠛⠿⠿⢿⣦⣵⣶⣶⠆⣼⣿⣿
⣿⣿⡿⢩⣥⣦⣭⡛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡌⢿⣿⣿⣿⣿⣿⠟⠁⣀⡥⢒⣛⣉⣙⣛⠶⠘⢿⣿⠏⣼⣿⣿⣿
⣿⣿⣧⠸⣿⣿⣯⡻⢷⣬⡛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠻⣿⣿⣿⠃⢠⠞⣡⣶⣿⣿⣿⣿⠿⣿⣆⢿⡏⠸⣿⣿⣿⣿
⣿⣿⣿⣧⠹⣿⣿⣿⣦⡙⢿⣦⣍⠻⣿⣿⣿⣿⣿⣿⣿⡿⠇⣹⣿⡏⣦⡴⣛⣛⣋⠉⣻⣿⠴⣛⣛⡛⠸⣿⣷⣬⠍⢙⣿
⣿⣿⣿⣿⣧⡙⣿⣿⣿⣿⣦⡙⢿⣿⣦⣙⢿⣉⠡⢴⣶⣶⣿⣿⣿⡇⢋⣾⣿⣿⣿⣿⡜⢃⣾⣿⣿⣿⣧⢻⡟⣡⣾⣿⣿
⣿⣿⣿⣿⣿⣷⡘⢿⡟⢉⡴⠒⣀⣙⣛⡛⠷⢬⡻⢦⣍⡻⠿⣿⣿⡇⡘⣿⣿⣿⣷⣿⠇⡌⢿⣿⣿⣿⠟⣸⣄⢿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣌⠀⡀⢠⣿⢿⣿⣿⣿⡝⣦⡙⣦⣝⠛⣡⣿⣿⡇⢿⡮⢝⣛⡛⣡⣾⣏⣶⠭⡭⢵⡆⢿⣿⠖⢈⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡄⣿⠛⢿⣿⢹⣷⠈⠳⠌⠡⠾⢿⣿⡿⡁⢸⣿⣶⣶⣾⣿⣏⠿⣸⣿⣶⣿⡇⡆⢰⣾⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⣃⢸⡄⠠⠭⢈⢛⣰⣦⠠⠘⣿⣶⠆⣁⢿⠈⣿⣿⣿⣿⣿⡿⠟⠋⠉⠉⠐⠀⠀⢂⣙⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡟⢡⣾⣿⠘⡇⠟⣃⣡⣤⣍⡙⠃⠇⢬⠛⣀⣛⡃⠀⠙⠿⠛⠉⠀⠀⠀⢀⣤⣤⠀⢀⣠⣼⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⡟⢠⣿⣿⠛⠀⠃⠈⠛⢿⣿⣿⠁⠠⠄⠀⠀⣌⢿⣿⡀⠀⠀⠀⢀⠀⠈⣥⣾⣿⣿⠇⣬⡛⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⢡⣿⣿⢁⡀⠀⣠⣥⣤⡁⢹⣿⢠⣶⣿⣷⣦⠘⣷⣝⢿⣤⣤⢀⠺⠏⠀⠿⠟⢛⢡⣾⣿⣿⣎⢻⣿⣿⣿
⣿⣿⣿⣿⣿⣿⠸⣿⡏⣼⡇⢸⣿⣿⣿⣿⡌⣿⡸⣿⣿⣿⡿⢀⢹⣿⡆⠿⢣⣿⡇⣿⣶⣾⡆⣿⣧⠻⣿⣿⣿⡇⢿⣿⣿
⣿⣿⣿⣿⣿⣿⣇⢻⡇⢻⣷⡘⠿⣿⣿⠟⠡⣿⣗⣈⠉⠩⠀⠨⠈⣿⣿⢀⠻⣿⡇⣿⣿⣿⣧⢸⣿⠃⢿⣿⣿⠇⣼⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣧⠁⣸⣿⣆⠀⠒⠶⠂⢠⣷⣶⢟⡂⢀⢐⡀⢀⣿⣿⢸⣷⢙⡇⣿⣿⣿⣿⢸⡇⣠⣿⣿⡟⣰⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣇⠻⠿⣿⣷⣶⡄⢢⠻⣿⣥⣴⣿⣼⡎⡇⣿⣿⣿⠈⢣⣾⡇⢻⣿⣿⣿⠂⣴⣿⣿⠏⣤⢿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡿⢋⣴⣶⣜⠿⣿⣿⣄⠡⡙⠟⡛⢫⡉⠄⡇⣿⣿⣿⡇⠘⣿⣧⢸⣿⡿⢃⣾⣿⡿⠃⣾⣿⡜⣿⣿⣿
⣿⣿⣿⣿⣿⠟⣩⣾⣿⣿⣿⣿⣷⣦⣭⣭⣄⠐⢀⣿⣿⣿⣾⡇⠻⢿⣿⣿⠰⡜⣿⡘⡟⣡⣿⣿⠟⣰⢰⣿⣿⣧⢿⣿⣿
⣿⣿⣿⡿⣫⣾⣿⣿⣿⠟⣱⣿⣿⣿⣿⣿⣿⡆⣻⣿⣿⣿⣿⡷⠇⣸⣿⣿⣇⢿⣌⠇⣴⣿⣿⢋⡄⣿⢸⣿⣿⣿⡜⣿⣿
⣿⣿⣫⣦⡙⢿⣿⢟⣥⢠⣿⣿⣿⣿⣿⣿⣿⣧⣙⠛⢿⡿⠉⣴⣾⣿⣿⣿⣿⡌⢣⣾⣿⡿⣡⣾⣷⠸⣸⣿⣿⣿⣷⠸⣿
⣻⣿⣿⣿⣟⣠⣴⣾⣣⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣸⣀⣴⣦⣘⣿⣿⣿⣿⣏⣠⣿⣿⣏⣴⣿⣿⣿⣀⣹⣿⣿⣿⣿⣇⣻
```

# Hide Injected Prompts (HIP) Framework

## Overview

This framework is a powerful tool designed for advanced security researchers, providing the ability to inject, hide, and manipulate prompts within Microsoft Office documents (Word, Excel, PowerPoint). By leveraging a variety of encoding, encryption, and compression techniques, the script can obfuscate payloads, embedding them within document XML structures in a manner that evades detection by most security controls.

## Table of Contents

- [Installation](#installation)
- [Purpose](#purpose)
- [Features](#features)
  - [Encryption Functions](#encryption-functions)
  - [Encoding/Decoding Functions](#encodingdecoding-functions)
  - [Compression Functions](#compression-functions)
  - [Microsoft Office Document Manipulation](#microsoft-office-document-manipulation)
- [Usage](#usage)
  - [Basic Commands](#basic-commands)
  - [Injection Options](#injection-options)
  - [Advanced Usage](#advanced-usage)
  - [Inverse Operations](#inverse-operations)
  - [Working with Zipped Documents](#working-with-zipped-documents)
- [Code Explanation](#code-explanation)
  - [Main Functions](#main-functions)
  - [Advanced Combinations](#advanced-combinations)
- [Evasion Techniques](#evasion-techniques)
  - [Using `convert_to_tag_chars`](#using-convert_to_tag_chars)
  - [HTML Injection Challenges](#html-injection-challenges)
  - [High Fidelity Combinations](#high-fidelity-combinations)
- [Contributing](#contributing)
- [License](#license)

## Installation

Ensure you have Python 3.9 or later installed. The required libraries can be installed using `pip3.9`:

```
pip3.9 install python-docx openpyxl python-pptx pycryptodome
```

Clone this repository:

```
git clone https://github.com/your-repo/hide-injected-prompts.git
cd hide-injected-prompts
```

## Purpose

This script is designed for security researchers who need to inject, hide, and manipulate prompts within Microsoft Office documents. It is particularly useful for testing the limits of document-based security controls by embedding complex and layered payloads within the document’s XML structure.

## Features

### Encryption Functions

- **AES Encryption/Decryption**
  - `aes_encrypt(text, password)`: Encrypts `text` using AES encryption with the provided `password`.
  - `aes_decrypt(enc_text, password)`: Decrypts `enc_text using AES encryption with the provided `password`.

- **XOR Encryption/Decryption**
  - `xor_encrypt(text, key)`: Encrypts `text` using the XOR cipher with the provided `key`.
  - `xor_decrypt(enc_text, key)`: Decrypts `enc_text using the XOR cipher with the provided `key`.

### Encoding/Decoding Functions

- **Base64/Base32/Base85**
  - Encoding and decoding functions for converting text into different base formats (Base64, Base32, Base85).

- **ROT13**
  - A simple letter substitution cipher that replaces a letter with the 13th letter after it in the alphabet.

- **URL Encoding**
  - Converts characters into a format that can be transmitted over the internet.

- **HTML Entity Encoding**
  - Converts special characters into HTML entities to hide payloads within HTML content.

### Compression Functions

- **Gzip, Zlib, Bzip2**
  - Compress and decompress text using standard compression algorithms. These functions can reduce the size of the payloads, making them easier to inject into documents.


### Microsoft Office Document Manipulation

The framework provides extensive functionality for injecting payloads into various locations within Microsoft Word, Excel, and PowerPoint documents. These injections are executed within the XML structure of the document after it has been unzipped and can target a wide range of components, such as headers, footers, metadata, relationships (`.rels` files), and more.

#### Injection Locations:

- **Word Documents** (`.docx`):
  - `rels`, `docProps`, `document`, `fontTable`, `settings`, `styles`, `theme`, `webSettings`, `docRels`, `contentTypes`

- **Excel Documents** (`.xlsx`):
  - `workbook`, `sharedStrings`, `sheet1`, `workbookRels`, `docProps`

- **PowerPoint Presentations** (`.pptx`):
  - `presentation`, `slide1`, `slideLayouts`, `slideMasters`, `notesSlide`, `presentationRels`, `docProps`

## Usage

### Basic Commands

#### Injecting a Payload into a Word Document:

```
python3.9 hip.py inject_hidden_prompt document.docx word document "Your hidden prompt here"
```

This command injects the specified prompt into the main document XML of a Word file.

#### Injecting into an Excel Document:

```
python3.9 hip.py inject_hidden_prompt spreadsheet.xlsx excel sheet1 "Your hidden prompt here"
```

Injects the hidden prompt into the primary sheet (Sheet1) of an Excel document.

#### Injecting into a PowerPoint Presentation:

```
python3.9 hip.py inject_hidden_prompt presentation.pptx powerpoint slide1 "Your hidden prompt here"
```

This command injects the hidden prompt into the first slide of a PowerPoint presentation.

### Injection Options

#### Injecting into Multiple Locations:

```
python3.9 hip.py inject_hidden_prompt document.docx word "rels,docProps,document" "Your hidden prompt here"
```

This command injects the payload into the specified locations within a Word document. The payload is injected into the relationships file (`rels`), document properties (`docProps`), and the main document XML (`document`).

#### Using Payload Files:

```
python3.9 hip.py inject_hidden_prompt document.docx word document --file payload.txt
```

This command reads the payload from `payload.txt` and injects it into the main document XML of a Word file.

### Advanced Usage

#### Working with Zipped Documents

For more advanced users, injecting into the raw XML of zipped Office documents provides the ability to target specific components:

1. **Unzip the Document:**

   ```
   unzip document.docx -d unzipped_doc
   ```

2. **Inject into the XML:**

   Use the following command to inject a hidden prompt into an XML file within the unzipped document structure:

   ```
   python3.9 hip.py inject_hidden_prompt unzipped_doc/word/document.xml word document "Your hidden prompt here"
   ```

3. **Re-zip the Document:**

   After injection, re-zip the document:

   ```
   cd unzipped_doc
   zip -r ../document_with_payload.docx *
   cd ..
   ```

   The `document_with_payload.docx` now contains the injected content.

#### Injecting into Other Document Types:

Similar steps can be followed for Excel and PowerPoint files, targeting specific XML components within the unzipped structure.

```
# For Excel:
unzip spreadsheet.xlsx -d unzipped_xls
python3.9 hip.py inject_hidden_prompt unzipped_xls/xl/sharedStrings.xml excel sharedStrings "Your hidden prompt here"
zip -r ../spreadsheet_with_payload.xlsx *
```

```
# For PowerPoint:
unzip presentation.pptx -d unzipped_ppt
python3.9 hip.py inject_hidden_prompt unzipped_ppt/ppt/slides/slide1.xml powerpoint slide1 "Your hidden prompt here"
zip -r ../presentation_with_payload.pptx *
```

### Inverse Operations

To reverse an injection and extract the embedded prompt:

#### Extracting from Word:

```
python3.9 hip.py extract_hidden_prompt document_with_payload.docx word document
```

This command extracts the hidden prompt from the main document XML of the Word file.

#### Extracting from Excel:

```
python3.9 hip.py extract_hidden_prompt spreadsheet_with_payload.xlsx excel sheet1
```

This command extracts the hidden prompt from the primary sheet (Sheet1) of the Excel document.

### Inverse Injection with Complex Operations:

If an operation involves multiple techniques (encryption, encoding, compression), the inverse would involve reversing each operation step by step:

```
python3.9 hip.py extract_hidden_prompt presentation_with_payload.pptx powerpoint slide1 --decrypt aes --decode base85 --decompress gzip --password MySecurePassword
```


## Code Explanation

### Main Functions

- **_prompt_parser**:
  - The `_prompt_parser` subparser is crucial for handling the different types of documents and locations where payloads can be injected. This function ensures that each document type (`word`, `excel`, `powerpoint`) and location (e.g., `document`, `sheet1`, `slide1`) is correctly targeted during the injection process.

### Advanced Combinations

Here are some advanced combinations using the framework to achieve more complex injection scenarios:

#### Example 1: AES Encryption + Base85 Encoding + Gzip Compression

```
python3.9 hip.py inject_hidden_prompt document.docx word document "Your hidden prompt here" --encrypt aes --encode base85 --compress gzip --password MySecurePassword
```

#### Example 2: XOR Encryption + ROT13 + HTML Entity Encoding

```
python3.9 hip.py inject_hidden_prompt spreadsheet.xlsx excel sheet1 "Your hidden prompt here" --encrypt xor --encode rot13 --encode html_entity --key MyXORKey
```

#### Example 3: Multi-Location Injection with Complex Encoding

```
python3.9 hip.py inject_hidden_prompt document.docx word "rels,document,styles" "Your hidden prompt here" --encode base64 --compress zlib
```

### Evasion Techniques

### Security Implications of `convert_to_tag_chars`

The `convert_to_tag_chars` function performs a transformation on an input string by converting each character into a special Unicode character from the Supplementary Private Use Area-A (U+E0000 to U+E007F). This technique can have various implications in the context of security.

```
def convert_to_tag_chars(input_string):
    return ''.join(chr(0xE0000 + ord(ch)) for ch in input_string)

user_input = input()

tagged_output = convert_to_tag_chars(user_input)
print("Tagged output:", tagged_output)
pyperclip.copy(tagged_output)
```
The provided code performs a specific transformation on an input string, converting each character into a special Unicode character from the Supplementary Private Use Area-A (U+E0000 to U+E007F). This operation is particularly interesting and can have various implications in the context of security.

Code Breakdown

Let's break down what each part of the code is doing:

convert_to_tag_chars(input_string) Function:

This function takes a string input_string as its argument.
It converts each character in the input_string into a corresponding character in the Supplementary Private Use Area-A by adding 0xE0000 to the Unicode code point (ord(ch)) of each character in the input string.

The resulting characters are then joined together to form a new string, which is returned.
Example: If input_string is "abc", the function will convert 'a' to a character at 0xE0000 + ord('a'), 'b' to 0xE0000 + ord('b'), and so on, resulting in a string of characters from this private use area.

Technical Depth

The core operation here is the conversion of standard ASCII or Unicode characters into characters from the Supplementary Private Use Area-A. This area of Unicode is typically reserved for custom, non-standard characters that do not have a predefined meaning in Unicode. The code effectively creates a "tagged" or obfuscated version of the input string that may look completely different from the original but can be reverted back if the same transformation logic is known.

Security Risks

Obfuscation of Malicious Content:

Stealthy Data Exfiltration: The convert_to_tag_chars function can be used to obfuscate malicious content or sensitive data. For example, an attacker could use this technique to hide payloads in a document or transmitted data, making it difficult for security systems to recognize or detect.

Evasion of Security Controls: Since the characters generated by this transformation are from a private use area, many text processing systems, filters, and security tools may not be configured to handle or recognize these characters. This could allow malicious code or data to bypass content filtering mechanisms.

Phishing and Social Engineering:

Phishing: The obfuscation can be used in phishing attacks where the displayed text looks innocuous, but the underlying content has been converted into something that evades detection. This could be used in URLs or other text-based phishing strategies.

Manipulation of UI: Users might not be aware that the text they see is not standard text, leading to potential misinterpretation or the execution of unintended actions.

Clipboard Hijacking:

Malicious Clipboard Content: The use of pyperclip.copy(tagged_output) to copy the obfuscated content to the clipboard could be exploited in scenarios where a user might unknowingly paste this content into another application, potentially introducing obfuscated malicious code into a document, command line, or other critical environments.

Data Integrity Issues:

Data Corruption: If this obfuscated text is stored or transmitted without proper handling, it might lead to data corruption, especially if the receiving end does not support or expect characters from the Supplementary Private Use Area-A.

### HTML Injection Challenges

Embedding encoded payloads within an HTML file poses significant challenges for defenders. The use of multiple encoding schemes within an HTML structure can obscure the true nature of the payload, making it difficult for security controls to parse and detect the malicious content.

### High Fidelity Combinations

Here are five high-fidelity combinations that could leave security controls confused:

1. **Triple Encoding**: Base85 + ROT13 + URL Encode
   ```
   python3.9 hip.py inject_hidden_prompt presentation.pptx powerpoint slide1 "Your hidden prompt here" --encode base85 --encode rot13 --url-encode
   ```

2. **Compression + XOR + HTML Entity Encoding**
   ```
   python3.9 hip.py inject_hidden_prompt spreadsheet.xlsx excel sharedStrings "Your hidden prompt here" --compress zlib --encrypt xor --encode html_entity --key ComplexXORKey
   ```

3. **Multi-Layer Encryption**: AES + XOR
   ```
   python3.9 hip.py inject_hidden_prompt document.docx word document "Your hidden prompt here" --encrypt aes --encrypt xor --password AES_Pass --key XOR_Key
   ```

4. **Base64 + Gzip Compression**
   ```
   python3.9 hip.py inject_hidden_prompt spreadsheet.xlsx excel sheet1 "Your hidden prompt here" --encode base64 --compress gzip
   ```

5. **URL Encode + ROT13 + Gzip Compression**
   ```
   python3.9 hip.py inject_hidden_prompt presentation.pptx powerpoint notesSlide "Your hidden prompt here" --url-encode --encode rot13 --compress gzip
   ```
## Contributing

We welcome contributions from the community. Please follow the standard GitHub flow:

1. Fork the repository.
2. Create a feature branch.
3. Commit your changes.
4. Create a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
