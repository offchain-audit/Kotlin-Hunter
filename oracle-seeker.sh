#!/bin/bash

# Define the directory to scan (default is the current directory)
CODEBASE_DIR=${1:-.}

# Define the file extension to search (Kotlin files)
FILE_EXT="*.kt"

# Output files
RESULTS_FILE="oracle_seeker_results.txt"
DIRECTORIES_FILE="oracle_seeker_directories.txt"

# Clear previous results
echo "Oracle Seeker Results" > "$RESULTS_FILE"
echo "======================" >> "$RESULTS_FILE"

echo "Traversed Directories" > "$DIRECTORIES_FILE"
echo "=====================" >> "$DIRECTORIES_FILE"

# Function to search for potential bugs, excluding irrelevant directories/files
search_vulnerability() {
  local PATTERN="$1"
  local DESCRIPTION="$2"

  echo "Searching for: $DESCRIPTION" | tee -a "$RESULTS_FILE"
  echo "Pattern: $PATTERN" | tee -a "$RESULTS_FILE"
  echo "----------------------------------------" | tee -a "$RESULTS_FILE"

  # Perform the search, excluding irrelevant directories/files and specific contexts
  grep -r --include="$FILE_EXT" -n "$PATTERN" "$CODEBASE_DIR" | \
  grep -v -E "/(presentation|design|colors|fonts|themes|styles|navigation|images)/" | \
  grep -v -E "\.(png|jpg|jpeg)" | \
  grep -v -E "http[s]?://|www\." >> "$RESULTS_FILE"
  echo >> "$RESULTS_FILE"
}

# Specialized function for logging sensitive data
search_sensitive_logging() {
  local LOGGER="$1" # Logger type (e.g., Timber or Log)
  local DESCRIPTION="$2"

  echo "Searching for: $DESCRIPTION (filtered for sensitive data)" | tee -a "$RESULTS_FILE"
  echo "Logger: $LOGGER" | tee -a "$RESULTS_FILE"
  echo "----------------------------------------" | tee -a "$RESULTS_FILE"

  # Find logging instances and filter for sensitive keywords, excluding navigation, images, and URLs
  grep -r --include="$FILE_EXT" -n "$LOGGER" "$CODEBASE_DIR" | \
  grep -v -E "/(presentation|design|colors|fonts|themes|styles|navigation|images)/" | \
  grep -v -E "\.(png|jpg|jpeg)" | \
  grep -v -E "http[s]?://|www\." | \
  grep -E "privateKey|publicKey|mnemonic|token|password|secret" >> "$RESULTS_FILE"
  echo >> "$RESULTS_FILE"
}

# Record the directory traversal, excluding irrelevant directories
echo "Recording all directories traversed into $DIRECTORIES_FILE..."
find "$CODEBASE_DIR" -type d | grep -v -E "/(presentation|design|colors|fonts|themes|styles|navigation|images)/" >> "$DIRECTORIES_FILE"
echo "Directory traversal recorded successfully."

# Start scanning for vulnerabilities
echo "Starting Oracle Seeker scan..."

## 1. Sensitive equality comparisons
search_vulnerability "== " "Equality comparisons involving sensitive data (e.g., privateKey, mnemonic, etc.)" "privateKey|publicKey|mnemonic|token|password|secret|key"
search_vulnerability ".equals(" "Non-constant-time comparisons with sensitive data"

## 2. Array and byte equality checks
search_vulnerability ".contentEquals(" "Array and byte equality checks (timing vulnerabilities)"

## 3. References to cryptographic keys and sensitive data
search_vulnerability "privateKey" "References to private keys (check for improper handling)"
##search_vulnerability "publicKey" "References to public keys"
search_vulnerability "mnemonic" "References to mnemonic phrases"
##search_vulnerability "token" "References to tokens or sensitive values"
search_vulnerability "password" "References to passwords"

## 4. Cryptographic operations
search_vulnerability "Cipher" "Use of Cipher (check for secure implementation)"
search_vulnerability "Mac" "Use of MAC (message authentication code)"
search_vulnerability "Signature" "Use of Signature (check for misuse)"
search_vulnerability "getInstance(" "Potential insecure cryptographic algorithm"
search_vulnerability "keySpec" "Key specifications (potential misuse of cryptographic keys)"

## 5. Timing-based logic
search_vulnerability "System.nanoTime" "Use of System.nanoTime (potential timing attacks)"
search_vulnerability "System.currentTimeMillis" "Use of System.currentTimeMillis (potential timing attacks)"

## 6. Error messages and exception handling
search_vulnerability "throw" "Throwing exceptions (may reveal sensitive information)"
search_vulnerability "catch" "Catching exceptions (check for oracle bugs)"
search_vulnerability "Exception" "General exception handling (check for side-channel risks)"

## 7. Encoding/decoding sensitive data
search_vulnerability "Base64.encode" "Encoding sensitive data"
search_vulnerability "Base64.decode" "Decoding sensitive data"

## 8. Logging sensitive data (filtered for keywords)
search_sensitive_logging "Timber" "Logging potentially sensitive data with Timber"
search_sensitive_logging "Log." "Logging potentially sensitive data with Log"

## 9. Potential Hardcoded secrets
search_vulnerability "const val " "Potential hardcoded sensitive constants"

# Completion message
echo "Oracle Seeker scan complete. Results saved to $RESULTS_FILE"
echo "Traversed directories saved to $DIRECTORIES_FILE"
