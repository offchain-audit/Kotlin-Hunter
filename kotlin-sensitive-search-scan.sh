#!/bin/bash

# Define the directory to scan (default is the current directory)
CODEBASE_DIR=${1:-.}

# Define the file extension to search (Kotlin files)
FILE_EXT="*.kt"

# Output files
OUTPUT_FILE="kotlin_sensitive_scan_results.txt"
DIRECTORIES_FILE="traversed_directories.txt"

# Clear previous results
echo "Kotlin Sensitive Data Scan Results" > "$OUTPUT_FILE"
echo "==================================" >> "$OUTPUT_FILE"

echo "Traversed Directories" > "$DIRECTORIES_FILE"
echo "=====================" >> "$DIRECTORIES_FILE"

# Function to search for sensitive patterns
search_sensitive() {
  local PATTERN="$1"
  local DESCRIPTION="$2"

  echo "Searching for: $DESCRIPTION" | tee -a "$OUTPUT_FILE"
  echo "Pattern: $PATTERN" | tee -a "$OUTPUT_FILE"
  echo "----------------------------------------" | tee -a "$OUTPUT_FILE"

  grep -r --include="$FILE_EXT" -n "$PATTERN" "$CODEBASE_DIR" >> "$OUTPUT_FILE"
  echo >> "$OUTPUT_FILE"
}

# Record the directory traversal
echo "Recording all directories traversed into $DIRECTORIES_FILE..."
find "$CODEBASE_DIR" -type d >> "$DIRECTORIES_FILE"
echo "Directory traversal recorded successfully."

# Start scanning for sensitive patterns
echo "Starting sensitive data scan..."

## 1. Sensitive equality comparisons (narrowed to specific sensitive keywords)
search_sensitive "== " "Equality comparisons with sensitive data" "privateKey|publicKey|mnemonic|token|password|secret|key"

## 2. Array and byte equality checks (e.g., contentEquals with sensitive data)
search_sensitive ".contentEquals(" "Array equality checks with sensitive data" "privateKey|mnemonic|token|password"

## 3. References to cryptographic keys and sensitive data
search_sensitive "privateKey" "References to private keys"
search_sensitive "publicKey" "References to public keys"
search_sensitive "mnemonic" "References to mnemonic phrases"
search_sensitive "token" "References to tokens or sensitive values"
search_sensitive "password" "References to passwords"
search_sensitive "keySpec" "Key specifications (potential cryptographic use)"

## 4. Cryptographic operations (general patterns)
search_sensitive "Cipher" "Use of Cipher (check for secure implementation)"
search_sensitive "Mac" "Use of MAC (message authentication code)"
search_sensitive "Signature" "Use of Signature (check for misuse)"
search_sensitive "getInstance(" "Potential insecure cryptographic algorithm"

# Completion message
echo "Sensitive data scan complete. Results saved to $OUTPUT_FILE"
echo "Traversed directories saved to $DIRECTORIES_FILE"
