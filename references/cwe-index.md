# CWE index

Every distinct `cwe` label in `reports.sqlite`, deduplicated and grouped by bug class. The column stores human-readable names, not CWE numbers.

Snapshot: **208 distinct labels**, 5923 classified reports, 564 unclassified, 6487 total. Report IDs 1-4093443.

Regenerate after scraping more data with `make cwe-index` (or `python3 scripts/gen_cwe_index.py`). Counts shift; labels rarely disappear.

## Contents

- [Families](#families) - filter one bug class across all its spellings
- [All labels A-Z](#all-labels-a-z) - exhaustive lookup
- [Known near-duplicates](#known-near-duplicates)
- [Copy-paste filters](#copy-paste-filters)

## Families

Use the `IN (...)` list to catch every variant. Labels are exact database values, so copy them verbatim.

| Family | Reports | Exact labels |
| --- | ---: | --- |
| **XSS** | 890 | `Cross-site Scripting (XSS) - Reflected` (405)<br>`Cross-site Scripting (XSS) - Stored` (286)<br>`Cross-site Scripting (XSS) - Generic` (99)<br>`Cross-site Scripting (XSS) - DOM` (76)<br>`Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)` (18)<br>`Improper Neutralization of HTTP Headers for Scripting Syntax` (3)<br>`Cross-Site Scripting (XSS)` (2)<br>`Reflected XSS` (1) |
| **Access control** | 806 | `Improper Access Control - Generic` (559)<br>`Privilege Escalation` (171)<br>`Improper Authorization` (36)<br>`Incorrect Authorization` (12)<br>`Missing Authorization` (7)<br>`Improper Privilege Management` (6)<br>`Incorrect Permission Assignment for Critical Resource` (4)<br>`Execution with Unnecessary Privileges` (3)<br>`Improper Handling of Insufficient Permissions or Privileges` (3)<br>`Incorrect Default Permissions` (2)<br>`Incorrect Privilege Assignment` (2)<br>`Improper Preservation of Permissions` (1) |
| **Information disclosure** | 769 | `Information Disclosure` (539)<br>`Cleartext Storage of Sensitive Information` (61)<br>`Insecure Storage of Sensitive Information` (38)<br>`Cleartext Transmission of Sensitive Information` (33)<br>`Information Exposure Through Sent Data` (25)<br>`Information Exposure Through Directory Listing` (20)<br>`Information Exposure Through Debug Information` (18)<br>`Information Exposure Through an Error Message` (16)<br>`File and Directory Information Exposure` (6)<br>`User Interface (UI) Misrepresentation of Critical Information` (4)<br>`Exposure of Sensitive Information Due to Incompatible Policies` (2)<br>`Information Exposure Through Timing Discrepancy` (2)<br>`Cleartext Storage in a File or on Disk` (1)<br>`Improper Removal of Sensitive Information Before Storage or Transfer` (1)<br>`Inclusion of Sensitive Information in an Include File` (1)<br>`Insertion of Sensitive Information into Log File` (1)<br>`Use of Cache Containing Sensitive Information` (1) |
| **Authentication / session** | 450 | `Improper Authentication - Generic` (219)<br>`Improper Restriction of Authentication Attempts` (66)<br>`Insufficiently Protected Credentials` (35)<br>`Insufficient Session Expiration` (24)<br>`Authentication Bypass Using an Alternate Path or Channel` (21)<br>`Authentication Bypass by Primary Weakness` (18)<br>`Session Fixation` (10)<br>`Plaintext Storage of a Password` (8)<br>`Authentication Bypass` (6)<br>`Weak Password Recovery Mechanism for Forgotten Password` (6)<br>`Exposure of Data Element to Wrong Session` (5)<br>`Password in Configuration File` (5)<br>`Unverified Password Change` (5)<br>`Missing Authentication for Critical Function` (4)<br>`Storing Passwords in a Recoverable Format` (4)<br>`Weak Cryptography for Passwords` (4)<br>`Missing Critical Step in Authentication` (3)<br>`Authentication Bypass by Capture-replay` (1)<br>`Authentication Bypass by Spoofing` (1)<br>`Brute Force` (1)<br>`Key Exchange without Entity Authentication` (1)<br>`Reusing Session IDs (aka Session Replay)` (1)<br>`Use of Default Credentials` (1)<br>`Weak Password Requirements` (1) |
| **Injection / code execution** | 382 | `Code Injection` (151)<br>`Command Injection - Generic` (73)<br>`CRLF Injection` (44)<br>`OS Command Injection` (41)<br>`Deserialization of Untrusted Data` (32)<br>`Resource Injection` (23)<br>`LDAP Injection` (4)<br>`Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)` (3)<br>`XML Injection` (3)<br>`Improper Neutralization of Escape, Meta, or Control Sequences` (2)<br>`Improper Neutralization of Value Delimiters` (2)<br>`File Content Injection` (1)<br>`Improper Neutralization of Formula Elements in a CSV File` (1)<br>`Improper Neutralization of Whitespace` (1)<br>`Improper Output Neutralization for Logs` (1) |
| **Memory safety** | 343 | `Use After Free` (55)<br>`Classic Buffer Overflow` (41)<br>`Buffer Over-read` (36)<br>`Heap Overflow` (30)<br>`Out-of-bounds Read` (27)<br>`Integer Overflow` (23)<br>`Stack Overflow` (22)<br>`Memory Corruption - Generic` (18)<br>`NULL Pointer Dereference` (18)<br>`Double Free` (14)<br>`Array Index Underflow` (13)<br>`Improper Null Termination` (8)<br>`Incorrect Calculation of Buffer Size` (7)<br>`Buffer Underflow` (6)<br>`Type Confusion` (6)<br>`Use of Externally-Controlled Format String` (6)<br>`Off-by-one Error` (4)<br>`Buffer Under-read` (2)<br>`Integer Underflow` (2)<br>`Free of Memory not on the Heap` (1)<br>`Integer Overflow to Buffer Overflow` (1)<br>`Missing Release of Memory after Effective Lifetime` (1)<br>`Wrap-around Error` (1)<br>`Write-what-where Condition` (1) |
| **Resource exhaustion / DoS** | 273 | `Uncontrolled Resource Consumption` (242)<br>`Allocation of Resources Without Limits or Throttling` (27)<br>`Uncontrolled Recursion` (2)<br>`Improper Handling of Highly Compressed Data (Data Amplification)` (1)<br>`Uncontrolled Search Path Element` (1) |
| **Business logic** | 235 | `Business Logic Errors` (235) |
| **Configuration / design** | 229 | `Violation of Secure Design Principles` (137)<br>`Misconfiguration` (80)<br>`Use of Hard-coded Credentials` (8)<br>`Use of Hard-coded Password` (3)<br>`Insecure Default Initialization of Resource` (1) |
| **IDOR / BOLA** | 228 | `Insecure Direct Object Reference (IDOR)` (228) |
| **Path traversal / file inclusion** | 179 | `Path Traversal` (154)<br>`Remote File Inclusion` (9)<br>`Path Traversal: '.../...//'` (6)<br>`External Control of File Name or Path` (5)<br>`Relative Path Traversal` (3)<br>`PHP Local File Inclusion` (1)<br>`Path Traversal: 'dir\..\..\filename'` (1) |
| **SSRF** | 169 | `Server-Side Request Forgery (SSRF)` (168)<br>`Server Side Request Forgery` (1) |
| **Cryptography / randomness** | 149 | `Improper Certificate Validation` (45)<br>`Cryptographic Issues - Generic` (33)<br>`Man-in-the-Middle` (11)<br>`Use of a Broken or Risky Cryptographic Algorithm` (10)<br>`Missing Encryption of Sensitive Data` (9)<br>`Missing Required Cryptographic Step` (8)<br>`Improper Validation of Certificate with Host Mismatch` (5)<br>`Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)` (5)<br>`Use of Insufficiently Random Values` (5)<br>`Inadequate Encryption Strength` (4)<br>`Use of Hard-coded Cryptographic Key` (4)<br>`Improper Verification of Cryptographic Signature` (3)<br>`Reusing a Nonce, Key Pair in Encryption` (3)<br>`Improper Check for Certificate Revocation` (2)<br>`Improper Following of a Certificate's Chain of Trust` (1)<br>`Improper Validation of Certificate Expiration` (1) |
| **CSRF** | 145 | `Cross-Site Request Forgery (CSRF)` (145) |
| **Other** | 139 | `Phishing` (23)<br>`Modification of Assumed-Immutable Data (MAID)` (17)<br>`Client-Side Enforcement of Server-Side Security` (14)<br>`Forced Browsing` (8)<br>`Externally Controlled Reference to a Resource in Another Sphere` (7)<br>`Security Through Obscurity` (6)<br>`Reliance on Untrusted Inputs in a Security Decision` (5)<br>`Cache Poisoning` (4)<br>`Improper Check or Handling of Exceptional Conditions` (4)<br>`Use of Incorrectly-Resolved Name or Reference` (4)<br>`Expected Behavior Violation` (3)<br>`Exposed Dangerous Method or Function` (3)<br>`External Control of Critical State Data` (3)<br>`Inclusion of Functionality from Untrusted Control Sphere` (3)<br>`Insecure Temporary File` (3)<br>`Exploiting Incorrectly Configured SSL/TLS` (2)<br>`Insufficient Verification of Data Authenticity` (2)<br>`Leftover Debug Code (Backdoor)` (2)<br>`Malware` (2)<br>`Use of Inherently Dangerous Function` (2)<br>`Using Components with Known Vulnerabilities` (2)<br>`Acceptance of Extraneous Untrusted Data With Trusted Data` (1)<br>`Content Spoofing` (1)<br>`Download of Code Without Integrity Check` (1)<br>`File Manipulation` (1)<br>`Improper Export of Android Application Components` (1)<br>`Improper Handling of Exceptional Conditions` (1)<br>`Improper Initialization` (1)<br>`Improper Link Resolution Before File Access ('Link Following')` (1)<br>`Improper Resource Shutdown or Release` (1)<br>`Improper Synchronization` (1)<br>`Inconsistency Between Implementation and Documented Design` (1)<br>`Incorrect Comparison` (1)<br>`Loop with Unreachable Exit Condition ('Infinite Loop')` (1)<br>`Misinterpretation of Input` (1)<br>`Reachable Assertion` (1)<br>`Reliance on Reverse DNS Resolution for a Security-Critical Action` (1)<br>`Reversible One-Way Hash` (1)<br>`Unchecked Error Condition` (1)<br>`Untrusted Search Path` (1)<br>`Use of a Key Past its Expiration Date` (1) |
| **SQL injection** | 132 | `SQL Injection` (130)<br>`Blind SQL Injection` (1)<br>`NoSQL Injection` (1) |
| **Open redirect** | 107 | `Open Redirect` (107) |
| **Input validation / encoding** | 76 | `Improper Input Validation` (60)<br>`Reliance on Cookies without Validation and Integrity Checking in a Security Decision` (5)<br>`Improper Handling of URL Encoding (Hex Encoding)` (4)<br>`ASI05: Unexpected Code Execution (RCE)` (1)<br>`Encoding Error` (1)<br>`Improper Handling of Case Sensitivity` (1)<br>`Improper Handling of Unexpected Data Type` (1)<br>`Improper Handling of Unicode Encoding` (1)<br>`Improper Validation of Syntactic Correctness of Input` (1)<br>`Origin Validation Error` (1) |
| **HTTP smuggling / splitting** | 66 | `HTTP Request Smuggling` (56)<br>`HTTP Response Splitting` (10) |
| **Logging / privacy** | 60 | `Privacy Violation` (36)<br>`Insufficient Logging` (24) |
| **Race condition / concurrency** | 32 | `Time-of-check Time-of-use (TOCTOU) Race Condition` (17)<br>`Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')` (14)<br>`Leveraging Race Conditions` (1) |
| **Clickjacking** | 30 | `UI Redressing (Clickjacking)` (30) |
| **XXE** | 12 | `XML External Entities (XXE)` (12) |
| **AI / LLM** | 11 | `LLM06: Sensitive Information Disclosure` (5)<br>`LLM01: Prompt Injection` (3)<br>`LLM04: Model Denial of Service` (1)<br>`LLM05: Supply Chain Vulnerabilities` (1)<br>`LLM09:2025 Misinformation` (1) |
| **File upload / extensions** | 11 | `Unrestricted Upload of File with Dangerous Type` (11) |

## All labels A-Z

| Reports | Label | Family |
| ---: | --- | --- |
| 1 | `Acceptance of Extraneous Untrusted Data With Trusted Data` | Other |
| 27 | `Allocation of Resources Without Limits or Throttling` | Resource exhaustion / DoS |
| 13 | `Array Index Underflow` | Memory safety |
| 1 | `ASI05: Unexpected Code Execution (RCE)` | Input validation / encoding |
| 6 | `Authentication Bypass` | Authentication / session |
| 1 | `Authentication Bypass by Capture-replay` | Authentication / session |
| 18 | `Authentication Bypass by Primary Weakness` | Authentication / session |
| 1 | `Authentication Bypass by Spoofing` | Authentication / session |
| 21 | `Authentication Bypass Using an Alternate Path or Channel` | Authentication / session |
| 1 | `Blind SQL Injection` | SQL injection |
| 1 | `Brute Force` | Authentication / session |
| 36 | `Buffer Over-read` | Memory safety |
| 2 | `Buffer Under-read` | Memory safety |
| 6 | `Buffer Underflow` | Memory safety |
| 235 | `Business Logic Errors` | Business logic |
| 4 | `Cache Poisoning` | Other |
| 41 | `Classic Buffer Overflow` | Memory safety |
| 1 | `Cleartext Storage in a File or on Disk` | Information disclosure |
| 61 | `Cleartext Storage of Sensitive Information` | Information disclosure |
| 33 | `Cleartext Transmission of Sensitive Information` | Information disclosure |
| 14 | `Client-Side Enforcement of Server-Side Security` | Other |
| 151 | `Code Injection` | Injection / code execution |
| 73 | `Command Injection - Generic` | Injection / code execution |
| 14 | `Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')` | Race condition / concurrency |
| 1 | `Content Spoofing` | Other |
| 44 | `CRLF Injection` | Injection / code execution |
| 145 | `Cross-Site Request Forgery (CSRF)` | CSRF |
| 2 | `Cross-Site Scripting (XSS)` | XSS |
| 76 | `Cross-site Scripting (XSS) - DOM` | XSS |
| 99 | `Cross-site Scripting (XSS) - Generic` | XSS |
| 405 | `Cross-site Scripting (XSS) - Reflected` | XSS |
| 286 | `Cross-site Scripting (XSS) - Stored` | XSS |
| 33 | `Cryptographic Issues - Generic` | Cryptography / randomness |
| 32 | `Deserialization of Untrusted Data` | Injection / code execution |
| 14 | `Double Free` | Memory safety |
| 1 | `Download of Code Without Integrity Check` | Other |
| 1 | `Encoding Error` | Input validation / encoding |
| 3 | `Execution with Unnecessary Privileges` | Access control |
| 3 | `Expected Behavior Violation` | Other |
| 2 | `Exploiting Incorrectly Configured SSL/TLS` | Other |
| 3 | `Exposed Dangerous Method or Function` | Other |
| 5 | `Exposure of Data Element to Wrong Session` | Authentication / session |
| 2 | `Exposure of Sensitive Information Due to Incompatible Policies` | Information disclosure |
| 3 | `External Control of Critical State Data` | Other |
| 5 | `External Control of File Name or Path` | Path traversal / file inclusion |
| 7 | `Externally Controlled Reference to a Resource in Another Sphere` | Other |
| 3 | `Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)` | Injection / code execution |
| 6 | `File and Directory Information Exposure` | Information disclosure |
| 1 | `File Content Injection` | Injection / code execution |
| 1 | `File Manipulation` | Other |
| 8 | `Forced Browsing` | Other |
| 1 | `Free of Memory not on the Heap` | Memory safety |
| 30 | `Heap Overflow` | Memory safety |
| 56 | `HTTP Request Smuggling` | HTTP smuggling / splitting |
| 10 | `HTTP Response Splitting` | HTTP smuggling / splitting |
| 559 | `Improper Access Control - Generic` | Access control |
| 219 | `Improper Authentication - Generic` | Authentication / session |
| 36 | `Improper Authorization` | Access control |
| 45 | `Improper Certificate Validation` | Cryptography / randomness |
| 2 | `Improper Check for Certificate Revocation` | Cryptography / randomness |
| 4 | `Improper Check or Handling of Exceptional Conditions` | Other |
| 1 | `Improper Export of Android Application Components` | Other |
| 1 | `Improper Following of a Certificate's Chain of Trust` | Cryptography / randomness |
| 1 | `Improper Handling of Case Sensitivity` | Input validation / encoding |
| 1 | `Improper Handling of Exceptional Conditions` | Other |
| 1 | `Improper Handling of Highly Compressed Data (Data Amplification)` | Resource exhaustion / DoS |
| 3 | `Improper Handling of Insufficient Permissions or Privileges` | Access control |
| 1 | `Improper Handling of Unexpected Data Type` | Input validation / encoding |
| 1 | `Improper Handling of Unicode Encoding` | Input validation / encoding |
| 4 | `Improper Handling of URL Encoding (Hex Encoding)` | Input validation / encoding |
| 1 | `Improper Initialization` | Other |
| 60 | `Improper Input Validation` | Input validation / encoding |
| 1 | `Improper Link Resolution Before File Access ('Link Following')` | Other |
| 2 | `Improper Neutralization of Escape, Meta, or Control Sequences` | Injection / code execution |
| 1 | `Improper Neutralization of Formula Elements in a CSV File` | Injection / code execution |
| 3 | `Improper Neutralization of HTTP Headers for Scripting Syntax` | XSS |
| 18 | `Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)` | XSS |
| 2 | `Improper Neutralization of Value Delimiters` | Injection / code execution |
| 1 | `Improper Neutralization of Whitespace` | Injection / code execution |
| 8 | `Improper Null Termination` | Memory safety |
| 1 | `Improper Output Neutralization for Logs` | Injection / code execution |
| 1 | `Improper Preservation of Permissions` | Access control |
| 6 | `Improper Privilege Management` | Access control |
| 1 | `Improper Removal of Sensitive Information Before Storage or Transfer` | Information disclosure |
| 1 | `Improper Resource Shutdown or Release` | Other |
| 66 | `Improper Restriction of Authentication Attempts` | Authentication / session |
| 1 | `Improper Synchronization` | Other |
| 1 | `Improper Validation of Certificate Expiration` | Cryptography / randomness |
| 5 | `Improper Validation of Certificate with Host Mismatch` | Cryptography / randomness |
| 1 | `Improper Validation of Syntactic Correctness of Input` | Input validation / encoding |
| 3 | `Improper Verification of Cryptographic Signature` | Cryptography / randomness |
| 4 | `Inadequate Encryption Strength` | Cryptography / randomness |
| 3 | `Inclusion of Functionality from Untrusted Control Sphere` | Other |
| 1 | `Inclusion of Sensitive Information in an Include File` | Information disclosure |
| 1 | `Inconsistency Between Implementation and Documented Design` | Other |
| 12 | `Incorrect Authorization` | Access control |
| 7 | `Incorrect Calculation of Buffer Size` | Memory safety |
| 1 | `Incorrect Comparison` | Other |
| 2 | `Incorrect Default Permissions` | Access control |
| 4 | `Incorrect Permission Assignment for Critical Resource` | Access control |
| 2 | `Incorrect Privilege Assignment` | Access control |
| 539 | `Information Disclosure` | Information disclosure |
| 16 | `Information Exposure Through an Error Message` | Information disclosure |
| 18 | `Information Exposure Through Debug Information` | Information disclosure |
| 20 | `Information Exposure Through Directory Listing` | Information disclosure |
| 25 | `Information Exposure Through Sent Data` | Information disclosure |
| 2 | `Information Exposure Through Timing Discrepancy` | Information disclosure |
| 1 | `Insecure Default Initialization of Resource` | Configuration / design |
| 228 | `Insecure Direct Object Reference (IDOR)` | IDOR / BOLA |
| 38 | `Insecure Storage of Sensitive Information` | Information disclosure |
| 3 | `Insecure Temporary File` | Other |
| 1 | `Insertion of Sensitive Information into Log File` | Information disclosure |
| 24 | `Insufficient Logging` | Logging / privacy |
| 24 | `Insufficient Session Expiration` | Authentication / session |
| 2 | `Insufficient Verification of Data Authenticity` | Other |
| 35 | `Insufficiently Protected Credentials` | Authentication / session |
| 23 | `Integer Overflow` | Memory safety |
| 1 | `Integer Overflow to Buffer Overflow` | Memory safety |
| 2 | `Integer Underflow` | Memory safety |
| 1 | `Key Exchange without Entity Authentication` | Authentication / session |
| 4 | `LDAP Injection` | Injection / code execution |
| 2 | `Leftover Debug Code (Backdoor)` | Other |
| 1 | `Leveraging Race Conditions` | Race condition / concurrency |
| 3 | `LLM01: Prompt Injection` | AI / LLM |
| 1 | `LLM04: Model Denial of Service` | AI / LLM |
| 1 | `LLM05: Supply Chain Vulnerabilities` | AI / LLM |
| 5 | `LLM06: Sensitive Information Disclosure` | AI / LLM |
| 1 | `LLM09:2025 Misinformation` | AI / LLM |
| 1 | `Loop with Unreachable Exit Condition ('Infinite Loop')` | Other |
| 2 | `Malware` | Other |
| 11 | `Man-in-the-Middle` | Cryptography / randomness |
| 18 | `Memory Corruption - Generic` | Memory safety |
| 80 | `Misconfiguration` | Configuration / design |
| 1 | `Misinterpretation of Input` | Other |
| 4 | `Missing Authentication for Critical Function` | Authentication / session |
| 7 | `Missing Authorization` | Access control |
| 3 | `Missing Critical Step in Authentication` | Authentication / session |
| 9 | `Missing Encryption of Sensitive Data` | Cryptography / randomness |
| 1 | `Missing Release of Memory after Effective Lifetime` | Memory safety |
| 8 | `Missing Required Cryptographic Step` | Cryptography / randomness |
| 17 | `Modification of Assumed-Immutable Data (MAID)` | Other |
| 1 | `NoSQL Injection` | SQL injection |
| 18 | `NULL Pointer Dereference` | Memory safety |
| 4 | `Off-by-one Error` | Memory safety |
| 107 | `Open Redirect` | Open redirect |
| 1 | `Origin Validation Error` | Input validation / encoding |
| 41 | `OS Command Injection` | Injection / code execution |
| 27 | `Out-of-bounds Read` | Memory safety |
| 5 | `Password in Configuration File` | Authentication / session |
| 154 | `Path Traversal` | Path traversal / file inclusion |
| 6 | `Path Traversal: '.../...//'` | Path traversal / file inclusion |
| 1 | `Path Traversal: 'dir\..\..\filename'` | Path traversal / file inclusion |
| 23 | `Phishing` | Other |
| 1 | `PHP Local File Inclusion` | Path traversal / file inclusion |
| 8 | `Plaintext Storage of a Password` | Authentication / session |
| 36 | `Privacy Violation` | Logging / privacy |
| 171 | `Privilege Escalation` | Access control |
| 1 | `Reachable Assertion` | Other |
| 1 | `Reflected XSS` | XSS |
| 3 | `Relative Path Traversal` | Path traversal / file inclusion |
| 5 | `Reliance on Cookies without Validation and Integrity Checking in a Security Decision` | Input validation / encoding |
| 1 | `Reliance on Reverse DNS Resolution for a Security-Critical Action` | Other |
| 5 | `Reliance on Untrusted Inputs in a Security Decision` | Other |
| 9 | `Remote File Inclusion` | Path traversal / file inclusion |
| 23 | `Resource Injection` | Injection / code execution |
| 3 | `Reusing a Nonce, Key Pair in Encryption` | Cryptography / randomness |
| 1 | `Reusing Session IDs (aka Session Replay)` | Authentication / session |
| 1 | `Reversible One-Way Hash` | Other |
| 6 | `Security Through Obscurity` | Other |
| 1 | `Server Side Request Forgery` | SSRF |
| 168 | `Server-Side Request Forgery (SSRF)` | SSRF |
| 10 | `Session Fixation` | Authentication / session |
| 130 | `SQL Injection` | SQL injection |
| 22 | `Stack Overflow` | Memory safety |
| 4 | `Storing Passwords in a Recoverable Format` | Authentication / session |
| 17 | `Time-of-check Time-of-use (TOCTOU) Race Condition` | Race condition / concurrency |
| 6 | `Type Confusion` | Memory safety |
| 30 | `UI Redressing (Clickjacking)` | Clickjacking |
| 1 | `Unchecked Error Condition` | Other |
| 2 | `Uncontrolled Recursion` | Resource exhaustion / DoS |
| 242 | `Uncontrolled Resource Consumption` | Resource exhaustion / DoS |
| 1 | `Uncontrolled Search Path Element` | Resource exhaustion / DoS |
| 11 | `Unrestricted Upload of File with Dangerous Type` | File upload / extensions |
| 1 | `Untrusted Search Path` | Other |
| 5 | `Unverified Password Change` | Authentication / session |
| 55 | `Use After Free` | Memory safety |
| 10 | `Use of a Broken or Risky Cryptographic Algorithm` | Cryptography / randomness |
| 1 | `Use of a Key Past its Expiration Date` | Other |
| 1 | `Use of Cache Containing Sensitive Information` | Information disclosure |
| 5 | `Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)` | Cryptography / randomness |
| 1 | `Use of Default Credentials` | Authentication / session |
| 6 | `Use of Externally-Controlled Format String` | Memory safety |
| 8 | `Use of Hard-coded Credentials` | Configuration / design |
| 4 | `Use of Hard-coded Cryptographic Key` | Cryptography / randomness |
| 3 | `Use of Hard-coded Password` | Configuration / design |
| 4 | `Use of Incorrectly-Resolved Name or Reference` | Other |
| 2 | `Use of Inherently Dangerous Function` | Other |
| 5 | `Use of Insufficiently Random Values` | Cryptography / randomness |
| 4 | `User Interface (UI) Misrepresentation of Critical Information` | Information disclosure |
| 2 | `Using Components with Known Vulnerabilities` | Other |
| 137 | `Violation of Secure Design Principles` | Configuration / design |
| 4 | `Weak Cryptography for Passwords` | Authentication / session |
| 6 | `Weak Password Recovery Mechanism for Forgotten Password` | Authentication / session |
| 1 | `Weak Password Requirements` | Authentication / session |
| 1 | `Wrap-around Error` | Memory safety |
| 1 | `Write-what-where Condition` | Memory safety |
| 12 | `XML External Entities (XXE)` | XXE |
| 3 | `XML Injection` | Injection / code execution |

## Known near-duplicates

Same class, different spelling - always filter both sides:

| Class | Label | Variant |
| --- | --- | --- |
| SSRF | `Server-Side Request Forgery (SSRF)` | `Server Side Request Forgery` |
| XSS | `Cross-site Scripting (XSS) - {Reflected,Stored,DOM,Generic}` | `Cross-Site Scripting (XSS)` |
| Path traversal | `Path Traversal` | `Path Traversal: '.../...//'` |
| Access control | `Insecure Direct Object Reference (IDOR)` | `Improper Access Control - Generic` |
| Auth | `Improper Authentication - Generic` | `Authentication Bypass by {Spoofing,Capture-replay,Primary Weakness}` |
| Info disclosure | `Information Disclosure` | `Information Exposure Through ...` (many) |

## Copy-paste filters


IDOR / BOLA:

```sql
SELECT report_id, program, title FROM reports WHERE cwe IN ('Insecure Direct Object Reference (IDOR)');
```

XSS:

```sql
SELECT report_id, program, title FROM reports WHERE cwe IN ('Cross-site Scripting (XSS) - Reflected', 'Cross-site Scripting (XSS) - Stored', 'Cross-site Scripting (XSS) - Generic', 'Cross-site Scripting (XSS) - DOM', 'Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)', 'Improper Neutralization of HTTP Headers for Scripting Syntax', 'Cross-Site Scripting (XSS)', 'Reflected XSS');
```

SSRF:

```sql
SELECT report_id, program, title FROM reports WHERE cwe IN ('Server-Side Request Forgery (SSRF)', 'Server Side Request Forgery');
```

SQL injection:

```sql
SELECT report_id, program, title FROM reports WHERE cwe IN ('SQL Injection', 'Blind SQL Injection', 'NoSQL Injection');
```

Access control:

```sql
SELECT report_id, program, title FROM reports WHERE cwe IN ('Improper Access Control - Generic', 'Privilege Escalation', 'Improper Authorization', 'Incorrect Authorization', 'Missing Authorization', 'Improper Privilege Management', 'Incorrect Permission Assignment for Critical Resource', 'Execution with Unnecessary Privileges', 'Improper Handling of Insufficient Permissions or Privileges', 'Incorrect Default Permissions', 'Incorrect Privilege Assignment', 'Improper Preservation of Permissions');
```
