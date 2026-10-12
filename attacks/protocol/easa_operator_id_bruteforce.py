import itertools
import time

def easa_luhn_mod36_checksum(operator_payload: str, secret_code: str) -> str:
    """
    Executes the legally mandated Luhn mod 36 checksum under EN 4709-002.
    Processes ONLY the 12-char payload and 3-char secret (skips country code).
    """
    # 1. Official EASA Mapping Array: Digits 0-9 (0-9), then lowercase a-z (10-35)
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    
    # Concatenate the 12 characters and 3 secret characters (15 chars total)
    full_payload = (operator_payload + secret_code).lower()
    
    total_sum = 0
    
    # 2. Iterate from right to left over the 15-character string
    for i, char in enumerate(reversed(full_payload)):
        if char not in alphabet:
            raise ValueError(f"Invalid character '{char}' per EASA standards.")
            
        value = alphabet.index(char)
        
        # In this 15-character alignment, even indices from the right are doubled
        if i % 2 == 0:
            value *= 2
            # Add the digits in base 36 (equivalent to standard Luhn digit summing)
            value = (value // 36) + (value % 36)
                
        total_sum += value

    # 3. Calculate the final check digit index
    check_index = (36 - (total_sum % 36)) % 36
    return alphabet[check_index]


def verify_easa_operator_string(full_string: str) -> bool:
    """
    Parses a full registration string, extracts the required components,
    skips the country code, and performs the consistency check.
    """
    # Normalize and split the registration string from the secret key
    clean_string = full_string.strip().replace(" ", "")
    public_id, secret_code = clean_string.split("-")
    
    # Slice the public ID components based on strict EASA layout:
    # Characters 0-3: Country Code (Skipped)
    # Characters 3-15: The 12-character operator payload
    # Character 15: The 16th character (The Check Digit)
    country_code = public_id[:3]
    operator_payload = public_id[3:15]
    expected_check_digit = public_id[15].lower()
    
    # Run the compliant algorithm
    calculated_digit = easa_luhn_mod36_checksum(operator_payload, secret_code)
    
    print(f"Parsing Registration String: {full_string}")
    print(f" -> Country Code (Skipped):  {country_code.upper()}")
    print(f" -> Math Input Payload:      {operator_payload} + {secret_code}")
    print(f" -> Expected Check Digit:    {expected_check_digit}")
    print(f" -> Calculated Check Digit:  {calculated_digit}")
    
    success = calculated_digit == expected_check_digit
    print(f" -> [RESULT]: {'PASS (Valid EASA ID)' if success else 'FAIL (Inconsistent String)'}\n")
    return success

def calculate_all_valid_secrets(public_id: str) -> list:
    """
    Takes a public EASA ID (e.g., 'FIN87astrdge12k8'), 
    skips the country prefix, and calculates all 1,296 matching secret keys.
    """
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    
    # Parse the public ID components
    clean_public = public_id.strip().replace(" ", "")
    operator_payload = clean_public[3:15]      # Isolate the 12-char middle payload
    target_check_digit = clean_public[15].lower() # Isolate the expected 16th digit
    
    valid_secrets = []
    
    print(f"Targeting Payload: '{operator_payload}' with Check Digit: '{target_check_digit}'")
    print("Computing all 46,656 combinations...")
    
    # Generate every single possible 3-character combination in Base-36
    for combo in itertools.product(alphabet, repeat=3):
        secret_guess = "".join(combo)
        
        # Run the official check on the guess
        if easa_luhn_mod36_checksum(operator_payload, secret_guess) == target_check_digit:
            valid_secrets.append(secret_guess)
            
    return valid_secrets

# --- RUNNING THE LEGISLATIVE TEST CASE ---

print("=== OFFICIAL EASA COMPLIANCE VERIFICATION ===\n")

# Testing the exact text example from EASA Guidelines
verify_easa_operator_string("FIN87astrdge12k8-xyz")

# Use the official EASA example. The known original secret is 'xyz'.
target_id = "FIN87astrdge12k8" 
start_time = time.time()
all_matching_secrets = calculate_all_valid_secrets(target_id)
end_time = time.time()
print(f"Calculation completed in {end_time - start_time} seconds")

# --- DISPLAY RESULTS ---
print(f"\nCalculation Complete!")
print(f"Total valid private parts found: {len(all_matching_secrets)}")
print(f"Does the official 'xyz' exist in the list? {'YES' if 'xyz' in all_matching_secrets else 'NO'}")

print("\nFirst 20 valid secret codes generated:")
print(all_matching_secrets[:20])

print("\nLast 20 valid secret codes generated:")
print(all_matching_secrets[-20:])