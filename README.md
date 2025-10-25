# File-Integrity-Checker
*COMPANY NAME* : CODTECH IT SOLUTIONS

*NAME* : PAWAN K C

*INTERN ID* : CT08DR264

*DOMAIN* : CYBERSECURITY

*DURATION* : 8 WEEKS

*MENTOR* : NEELA SANTHOSH

*DESCRIPTION*:
              Project Name: File Integrity Checker Language: Python

Purpose: This is a security and file monitoring tool that helps verify whether files have been modified or tampered with. It does this by creating and comparing cryptographic hashes (SHA-256) of files.

Key Features:

#1.File Hash Generation:
Uses SHA-256 hashing algorithm
Processes files in chunks (4096 bytes) to handle large files efficiently

#2.Baseline Management:
Stores file hashes in a JSON file (baseline.json)
Records timestamps of when files were added or updated
Maintains a history of file states

#3.File Integrity Verification:
Compares current file hash with stored baseline
Detects if files have been modified
Shows detailed comparison with timestamps
