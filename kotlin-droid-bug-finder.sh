#!/bin/bash

# Define the directory to scan (default is the current directory)
CODEBASE_DIR=${1:-.}

# Define the file extension to search (Kotlin files)
FILE_EXT="*.kt"

# Output files
RESULTS_FILE="bug_finder_results.txt"
DIRECTORIES_FILE="traversed_directories.txt"

# Clear previous results
echo "Bug Finder Results" > "$RESULTS_FILE"
echo "=================" >> "$RESULTS_FILE"

echo "Traversed Directories" > "$DIRECTORIES_FILE"
echo "=====================" >> "$DIRECTORIES_FILE"

# Record all traversed directories
find "$CODEBASE_DIR" -type d >> "$DIRECTORIES_FILE"
echo "Directory traversal recorded successfully."

# Function to search for patterns
search_pattern() {
  local PATTERN="$1"
  local DESCRIPTION="$2"

  echo "Searching for: $DESCRIPTION" | tee -a "$RESULTS_FILE"
  echo "Pattern: $PATTERN" | tee -a "$RESULTS_FILE"
  echo "----------------------------------------" | tee -a "$RESULTS_FILE"

  grep -r --include="$FILE_EXT" -n "$PATTERN" "$CODEBASE_DIR" | \
  grep -v -E "/(presentation|design|colors|fonts|themes|styles|navigation|images)/" | \
  grep -v -E "\.(png|jpg|jpeg)" | \
  grep -v -E "http[s]?://|www\." >> "$RESULTS_FILE"
  echo >> "$RESULTS_FILE"
}

# 1. Equality checks for sensitive data
search_pattern "== " "Equality comparisons involving sensitive data (e.g., privateKey, mnemonic, etc.)"
search_pattern "\.equals(" "Non-constant-time comparisons"

# 2. Array and byte equality checks
search_pattern "\.contentEquals(" "Array/byte equality checks (timing vulnerabilities)"

# 3. References to cryptographic keys and sensitive data
search_pattern "privateKey" "References to private keys"
search_pattern "publicKey" "References to public keys"
search_pattern "mnemonic" "References to mnemonic phrases"
search_pattern "token" "References to tokens or sensitive values"
search_pattern "password" "References to passwords"
search_pattern "secret" "References to secret data"

# 4. Cryptographic operations
search_pattern "Cipher" "Use of Cipher (check for secure implementation)"
search_pattern "Mac" "Use of MAC"
search_pattern "Signature" "Use of Signature"
search_pattern "getInstance(" "Potential insecure cryptographic algorithm"
search_pattern "keySpec" "Key specifications"

# 5. Timing-based logic
search_pattern "System\.nanoTime" "Use of System.nanoTime"
search_pattern "System\.currentTimeMillis" "Use of System.currentTimeMillis"

# 6. Error messages and exception handling
search_pattern "throw" "Throwing exceptions"
search_pattern "catch" "Catching exceptions"
search_pattern "Exception" "General exception handling"

# 7. Encoding/decoding sensitive data
search_pattern "Base64\.encode" "Encoding sensitive data"
search_pattern "Base64\.decode" "Decoding sensitive data"

# 8. Logging sensitive data (filtered for keywords)
search_pattern "Timber" "Logging potentially sensitive data with Timber"
search_pattern "Log\." "Logging potentially sensitive data with Log"

# 9. Hardcoded secrets
search_pattern "val " "Potential hardcoded sensitive values"
search_pattern "const val " "Potential hardcoded sensitive constants"

# 10. Insecure network communication
search_pattern "http://" "Plain HTTP URLs (insecure network communication)"
search_pattern "\.addRequestHeader\(" "Adding custom headers to requests"

# 11. Permissions
search_pattern "checkSelfPermission" "Runtime permission checks"
search_pattern "requestPermissions" "Requesting runtime permissions"

# 12. Memory management
search_pattern "companion object" "Potential static references causing memory leaks"
search_pattern "var .*: Activity" "Static references to Activity objects"

# 13. Input validation
search_pattern "Intent\.getStringExtra" "Potentially unvalidated input from Intent"
search_pattern "Intent\.getExtras" "Potentially unvalidated input from Intent"
search_pattern "Uri\.parse" "Unvalidated input from URIs"
search_pattern "setJavaScriptEnabled(true)" "Potentially unsafe WebView JavaScript settings"

# Completion message
echo "Bug Finder scan complete. Results saved to $RESULTS_FILE"
echo "Traversed directories saved to $DIRECTORIES_FILE"
