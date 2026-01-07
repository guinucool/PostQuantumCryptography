# Full BIKE-L1 parameters
#R_BITS = 12323  # Prime r for the ring F_2[x]/(x^r - 1)
#D = 71          # Weight of each half of the secret key (h0, h1)
#T = 134         # Weight of the error vector

# Better for testing
R_BITS = 587
D = 21 
T = 19


N0 = 2          # Number of circulant blocks
M_BITS = 256    # Message size in bits (256 bits = 32 bytes)
SS_BITS = 256   # Shared secret size in bits

# Decoder parameters
MAX_IT = 30     # Maximum decoder iterations (BGF decoder)
DELTA = 3       # Gray decoder parameter

print(f"BIKE-L1 Parameters:")
print(f"  r (ring size) = {R_BITS}")
print(f"  d (key weight) = {D}")
print(f"  t (error weight) = {T}")
print(f"  m (message bits) = {M_BITS}")

# ============================================================================
# Ring Definition:  F_2[x]/(x^r - 1)
# ============================================================================

# Define the polynomial ring over F_2
F2 = GF(2)
R_poly.<x> = PolynomialRing(F2)

# The modulus for our ring
modulus = x^R_BITS - 1

print(f"\nRing:  F_2[x] / (x^{R_BITS} - 1)")

# ============================================================================
# Matrix Representation for Ring Arithmetic
# ============================================================================

def poly_to_vector(p, n=R_BITS):
    """Convert a polynomial to a coefficient vector of length n."""
    coeffs = p.list()
    if len(coeffs) < n:
        coeffs.extend([F2(0)] * (n - len(coeffs)))
    return vector(F2, coeffs[: n])

def vector_to_poly(v):
    """Convert a coefficient vector to a polynomial."""
    return R_poly(list(v))

def circulant_matrix(v, n=R_BITS):
    """
    Create a circulant matrix from a vector. 
    """
    n = len(v)
    M = matrix(F2, n, n)
    for i in range(n):
        for j in range(n):
            M[i, j] = v[(i - j) % n]
    return M

def poly_mul_matrix(a, b):
    """
    Multiply two polynomials using matrix multiplication. 
    This demonstrates the circulant matrix approach from the lecture notes. 
    """
    v_a = poly_to_vector(a)
    v_b = poly_to_vector(b)
    M_a = circulant_matrix(v_a)
    result = M_a * v_b
    return vector_to_poly(result)

def poly_mul_fast(a, b):
    """
    Fast polynomial multiplication modulo (x^r - 1).
    Uses SageMath's built-in polynomial arithmetic.
    """
    product = a * b
    return product % modulus

def poly_add(a, b):
    """Add two polynomials in F_2[x]/(x^r - 1). Addition is XOR in F_2."""
    return (a + b) % modulus

# ============================================================================
# Random Sampling Functions
# ============================================================================

def sample_sparse_poly(weight, n=R_BITS):
    """
    Sample a random polynomial with exactly 'weight' non-zero coefficients. 
    Corresponds to generate_sparse_rep_for_sk in sampling.c
    """
    if weight > n:
        raise ValueError(f"Weight {weight} exceeds polynomial degree {n}")
    
    # Use Fisher-Yates style sampling for uniform distribution
    positions = set()
    while len(positions) < weight:
        pos = secrets.randbelow(n)
        positions.add(pos)
    
    coeffs = [F2(0)] * n
    for pos in positions:
        coeffs[pos] = F2(1)
    
    return R_poly(coeffs)

def sample_error_vector():
    """
    Sample an error vector e = (e0, e1) with total weight T.
    The error is split across two polynomials.
    Corresponds to generate_error_vector in sampling.c
    """
    # Sample T positions across the full 2*R_BITS space
    positions = set()
    while len(positions) < T:
        pos = secrets.randbelow(2 * R_BITS)
        positions.add(pos)
    
    # Split into e0 (positions 0 to R_BITS-1) and e1 (positions R_BITS to 2*R_BITS-1)
    e0_coeffs = [F2(0)] * R_BITS
    e1_coeffs = [F2(0)] * R_BITS
    
    for pos in positions:
        if pos < R_BITS:
            e0_coeffs[pos] = F2(1)
        else:
            e1_coeffs[pos - R_BITS] = F2(1)
    
    return R_poly(e0_coeffs), R_poly(e1_coeffs)

def random_message():
    """Generate a random 256-bit message."""
    return secrets. token_bytes(M_BITS // 8)

# ============================================================================
# Hash Functions
# ============================================================================

def sha384(data):
    """SHA-384 hash function."""
    if isinstance(data, (list, tuple)):
        data = b''.join(d if isinstance(d, bytes) else bytes(d) for d in data)
    return hashlib.sha384(data).digest()

def poly_to_bytes(p, n_bytes=None):
    """Convert a polynomial to bytes (coefficient vector as bits)."""
    coeffs = p.list()
    if n_bytes is None: 
        n_bytes = (R_BITS + 7) // 8
    
    # Pad coefficients to full length
    while len(coeffs) < R_BITS: 
        coeffs. append(F2(0))
    
    # Convert bits to bytes
    result = bytearray(n_bytes)
    for i, c in enumerate(coeffs[: R_BITS]):
        if c == 1:
            result[i // 8] |= (1 << (i % 8))
    
    return bytes(result)

def bytes_to_poly(data, n_bits=R_BITS):
    """Convert bytes to a polynomial."""
    coeffs = []
    for i in range(n_bits):
        byte_idx = i // 8
        bit_idx = i % 8
        if byte_idx < len(data):
            bit = (data[byte_idx] >> bit_idx) & 1
            coeffs.append(F2(bit))
        else:
            coeffs.append(F2(0))
    return R_poly(coeffs)

def function_H(m, pk=None):
    """
    H:  message -> error vector
    Corresponds to function_h in kem.c
    Generates an error vector from a message (seed).
    """
    # In the real implementation, this uses the message as a seed for PRF
    # Here we use a deterministic derivation
    seed = sha384(m)
    
    # Use seed to generate deterministic error positions
    import random
    rng = random.Random(seed)
    
    positions = set()
    while len(positions) < T:
        pos = rng. randrange(2 * R_BITS)
        positions.add(pos)
    
    e0_coeffs = [F2(0)] * R_BITS
    e1_coeffs = [F2(0)] * R_BITS
    
    for pos in sorted(positions):
        if pos < R_BITS:
            e0_coeffs[pos] = F2(1)
        else:
            e1_coeffs[pos - R_BITS] = F2(1)
    
    return R_poly(e0_coeffs), R_poly(e1_coeffs)

def function_L(e0, e1):
    """
    L: error vector -> mask
    Corresponds to function_l in kem.c
    L(e) = SHA384(e0 || e1) truncated to 256 bits
    """
    e0_bytes = poly_to_bytes(e0)
    e1_bytes = poly_to_bytes(e1)
    
    digest = sha384(e0_bytes + e1_bytes)
    return digest[:M_BITS // 8]  # Truncate to 256 bits (32 bytes)

def function_K(m, c0, c1):
    """
    K: (message, ciphertext) -> shared secret
    Corresponds to function_k in kem.c
    K(m, c0, c1) = SHA384(m || c0 || c1) truncated to 256 bits
    """
    c0_bytes = poly_to_bytes(c0)
    
    digest = sha384(m + c0_bytes + c1)
    return digest[:SS_BITS // 8]  # Truncate to 256 bits

# ============================================================================
# Polynomial Inversion in F_2[x]/(x^r - 1)
# ============================================================================

def poly_inverse(a):
    """
    Compute the multiplicative inverse of a in F_2[x]/(x^r - 1).
    Uses extended Euclidean algorithm.
    
    This corresponds to gf2x_mod_inv in gf2x_inv.c, which uses
    Itoh-Tsujii inversion based on Fermat's little theorem.
    
    For educational purposes, we use SageMath's built-in inverse. 
    """
    # Create the quotient ring
    R_quot = R_poly. quotient(modulus, 'y')
    
    # Convert polynomial to quotient ring element
    a_quot = R_quot(a)
    
    try:
        # Compute inverse
        a_inv_quot = ~a_quot
        # Convert back to polynomial
        return R_poly(a_inv_quot. lift())
    except ZeroDivisionError:
        raise ValueError("Polynomial is not invertible in this ring")

# ============================================================================
# BIKE Key Generation
# ============================================================================

def keygen():
    """
    BIKE Key Generation
    Corresponds to crypto_kem_keypair in kem. c
    
    Returns:
        pk: public key h = h0^(-1) * h1 mod (x^r - 1)
        sk: secret key (h0, h1, sigma, pk)
    """
    print("Generating BIKE keypair...")
    
    # Generate secret key polynomials h0, h1 with weight D each
    h0 = sample_sparse_poly(D)
    h1 = sample_sparse_poly(D)
    
    # Verify weights
    h0_weight = sum(1 for c in h0.list() if c == 1)
    h1_weight = sum(1 for c in h1.list() if c == 1)
    print(f"  h0 weight:  {h0_weight}")
    print(f"  h1 weight: {h1_weight}")
    
    # Compute h0^(-1) mod (x^r - 1)
    print("  Computing h0 inverse...")
    h0_inv = poly_inverse(h0)
    
    # Compute public key:  h = h0^(-1) * h1 mod (x^r - 1)
    print("  Computing public key h = h0^(-1) * h1...")
    h = poly_mul_fast(h0_inv, h1)
    
    # Generate sigma (random value for implicit rejection)
    sigma = random_message()
    
    # Public key is just h
    pk = h
    
    # Secret key contains (h0, h1), sigma, and a copy of pk
    sk = {
        'h0': h0,
        'h1':  h1,
        'sigma': sigma,
        'pk':  pk
    }
    
    print("  Key generation complete!")
    return pk, sk

# ============================================================================
# BIKE Encapsulation
# ============================================================================

def encapsulate_bike(pk):
    """
    BIKE Encapsulation
    Corresponds to crypto_kem_enc in kem.c
    
    Args:
        pk:  public key polynomial h
    
    Returns: 
        ct: ciphertext (c0, c1)
        ss: shared secret (256 bits)
    """
    print("Encapsulating...")
    
    # Generate random message m
    m = random_message()
    
    # Generate error vector e = (e0, e1) = H(m)
    e0, e1 = function_H(m, pk)
    
    e0_weight = sum(1 for c in e0.list() if c == 1)
    e1_weight = sum(1 for c in e1.list() if c == 1)
    print(f"  Error vector weights: e0={e0_weight}, e1={e1_weight}, total={e0_weight + e1_weight}")
    
    # Compute ciphertext c0 = e0 + e1 * h mod (x^r - 1)
    # This corresponds to:  ct = pk * e1 + e0 in kem.c encrypt function
    e1_h = poly_mul_fast(e1, pk)
    c0 = poly_add(e0, e1_h)
    
    # Compute c1 = m XOR L(e0, e1)
    L_e = function_L(e0, e1)
    c1 = bytes(int(a).__xor__(int(b)) for a, b in zip(m, L_e))
    
    # Compute shared secret K(m, c0, c1)
    ss = function_K(m, c0, c1)
    
    ct = {'c0': c0, 'c1': c1}
    
    print("  Encapsulation complete!")
    return ct, ss

# ============================================================================
# Bit-Flipping Decoder (BGF - Black-Gray-Flip)
# ============================================================================

def compute_syndrome(c0, h0):
    """
    Compute syndrome s = c0 * h0 mod (x^r - 1)
    Corresponds to compute_syndrome in decode.c
    """
    return poly_mul_fast(c0, h0)

def hamming_weight(p):
    """Compute the Hamming weight of a polynomial."""
    return sum(1 for c in p. list() if c == 1)

def get_threshold(syndrome, iteration=0):
    """
    Compute the threshold for bit-flipping.  
    """
    s_weight = hamming_weight(syndrome)
    
    if R_BITS < 1000: 
        noise_floor = float((s_weight * D) / R_BITS)
        threshold = max(int(D * 0.7), int(noise_floor) + 2)
    else:
        threshold = max(36, int(13.53 + 0.00069722 * s_weight))
    
    return threshold
    
def count_unsatisfied_parity_checks(pos, syndrome, h_indices):
    """
    Count the number of unsatisfied parity checks for a bit position.
    """
    count = 0
    s_coeffs = syndrome.list()
    if len(s_coeffs) < R_BITS: 
        s_coeffs.extend([F2(0)] * (R_BITS - len(s_coeffs)))
    
    for idx in h_indices: 
        check_pos = (pos + idx) % R_BITS  # ADDITION
        if s_coeffs[check_pos] == 1:
            count += 1
    
    return count

def get_sparse_positions(p):
    """Get the positions of non-zero coefficients."""
    coeffs = p.list()
    return [i for i, c in enumerate(coeffs) if c == 1]

def bgf_decode(syndrome, h0, h1, max_iterations=MAX_IT):
    """
    Improved Black-Gray-Flip (BGF) Decoder with adaptive thresholding.  
    """
    print(f"  Running BGF decoder (max {max_iterations} iterations)...")
    
    # Work with coefficient lists for efficiency
    s_coeffs = list(syndrome. list())
    while len(s_coeffs) < R_BITS:
        s_coeffs.append(F2(0))
    
    e0_coeffs = [F2(0)] * R_BITS
    e1_coeffs = [F2(0)] * R_BITS
    
    h0_positions = get_sparse_positions(h0)
    h1_positions = get_sparse_positions(h1)
    
    threshold_delta = 0  # Will decrease threshold when stuck
    
    for iteration in range(max_iterations):
        s_weight = sum(1 for c in s_coeffs if c == 1)
        print(f"    Iteration {iteration}:   syndrome weight = {s_weight}")
        
        if s_weight == 0:
            print("    Syndrome is zero - decoding successful!")
            break
        
        noise_floor = float((s_weight * D) / R_BITS)
        
        # Compute all UPCs for both e0 and e1
        all_candidates = []
        
        for j in range(R_BITS):
            upc0 = sum(1 for hp in h0_positions if s_coeffs[(j + hp) % R_BITS] == 1)
            all_candidates.append((upc0, 'e0', j))
            
            upc1 = sum(1 for hp in h1_positions if s_coeffs[(j + hp) % R_BITS] == 1)
            all_candidates.append((upc1, 'e1', j))
        
        # Sort by UPC (highest first)
        all_candidates.sort(reverse=True, key=lambda x:  x[0])
        
        max_upc = all_candidates[0][0] if all_candidates else 0
        
        # Base threshold with adaptive reduction
        base_threshold = max(int(D * 0.7), int(noise_floor) + 2)
        threshold = max(base_threshold - threshold_delta, int(noise_floor) + 1, 3)
        
        print(f"    Using threshold = {threshold} (noise floor ≈ {noise_floor:.1f}, top UPCs:  {[c[0] for c in all_candidates[:10]]})")
        
        # Select positions above threshold, limited to T total
        flips_e0 = []
        flips_e1 = []
        total_flips = 0
        
        for (upc, vec, j) in all_candidates:
            if upc < threshold:
                break
            if total_flips >= T:
                break
            
            if vec == 'e0':
                flips_e0.append(j)
            else:
                flips_e1.append(j)
            total_flips += 1
        
        # If no flips, progressively lower threshold
        if total_flips == 0:
            threshold_delta += 1
            new_threshold = max(base_threshold - threshold_delta, int(noise_floor) + 1, 3)
            print(f"    No flips - lowering threshold to {new_threshold}")
            
            for (upc, vec, j) in all_candidates:
                if upc < new_threshold:
                    break
                if total_flips >= T:
                    break
                
                if vec == 'e0':
                    flips_e0.append(j)
                else: 
                    flips_e1.append(j)
                total_flips += 1
        else:
            # Reset threshold delta on successful flip
            threshold_delta = max(0, threshold_delta - 1)
        
        print(f"    Flipping {len(flips_e0)} bits in e0, {len(flips_e1)} bits in e1 (total: {total_flips})")
        
        if total_flips == 0:
            print("    Decoder stuck - no progress possible")
            break
        
        # Apply flips and update syndrome
        for j in flips_e0:
            e0_coeffs[j] = e0_coeffs[j] + F2(1)
            for hp in h0_positions:
                pos = (j + hp) % R_BITS
                s_coeffs[pos] = s_coeffs[pos] + F2(1)
        
        for j in flips_e1:
            e1_coeffs[j] = e1_coeffs[j] + F2(1)
            for hp in h1_positions:
                pos = (j + hp) % R_BITS
                s_coeffs[pos] = s_coeffs[pos] + F2(1)
    
    return R_poly(e0_coeffs), R_poly(e1_coeffs)

# ============================================================================
# BIKE Decapsulation
# ============================================================================

def decapsulate(ct, sk):
    """
    BIKE Decapsulation
    Corresponds to crypto_kem_dec in kem.c
    
    Args: 
        ct: ciphertext {'c0': polynomial, 'c1': bytes}
        sk:  secret key {'h0': poly, 'h1': poly, 'sigma': bytes, 'pk': poly}
    
    Returns:
        ss: shared secret (256 bits)
    """
    print("Decapsulating...")
    
    c0 = ct['c0']
    c1 = ct['c1']
    h0 = sk['h0']
    h1 = sk['h1']
    sigma = sk['sigma']
    pk = sk['pk']
    
    # Step 1: Compute syndrome s = c0 * h0 mod (x^r - 1)
    syndrome = compute_syndrome(c0, h0)
    s_weight = hamming_weight(syndrome)
    print(f"  Initial syndrome weight: {s_weight}")
    
    # Step 2: Decode to find error vector e' = (e0', e1')
    e0_prime, e1_prime = bgf_decode(syndrome, h0, h1)
    
    # Step 3: Recompute message m' = c1 XOR L(e0', e1')
    L_e_prime = function_L(e0_prime, e1_prime)
    m_prime = bytes(int(a).__xor__(int(b)) for a, b in zip(c1, L_e_prime))
    
    # Step 4: Re-derive error vector from m' and check consistency
    e0_check, e1_check = function_H(m_prime, pk)
    
    # Verify that re-derived error matches decoded error
    e0_prime_bytes = poly_to_bytes(e0_prime)
    e1_prime_bytes = poly_to_bytes(e1_prime)
    e0_check_bytes = poly_to_bytes(e0_check)
    e1_check_bytes = poly_to_bytes(e1_check)
    
    success = (e0_prime_bytes == e0_check_bytes) and (e1_prime_bytes == e1_check_bytes)
    
    if success:
        print("  Decapsulation verification:  SUCCESS")
        # Use the recovered message
        ss = function_K(m_prime, c0, c1)
    else:
        print("  Decapsulation verification: FAILED (using sigma for implicit rejection)")
        # Implicit rejection:  use sigma instead of m'
        ss = function_K(sigma, c0, c1)
    
    print("  Decapsulation complete!")
    return ss

# ============================================================================
# Demonstration:  Matrix Multiplication for Polynomial Arithmetic
# ============================================================================

def demo_matrix_multiplication():
    """
    Demonstrate that polynomial multiplication in F_2[x]/(x^r-1) can be
    done via circulant matrix multiplication, as mentioned in the lecture notes.
    """
    print("\n" + "="*70)
    print("DEMONSTRATION: Matrix Multiplication for Ring Arithmetic")
    print("="*70)
    
    # Use a smaller ring for demonstration
    small_r = 7  # Small prime for illustration
    F2_small = GF(2)
    R_small.<y> = PolynomialRing(F2_small)
    mod_small = y^small_r - 1
    
    # Create two random polynomials
    a = R_small([1, 0, 1, 1, 0, 0, 1])  # y^6 + y^3 + y^2 + 1
    b = R_small([0, 1, 1, 0, 1, 0, 0])  # y^4 + y^2 + y
    
    print(f"\nRing:  F_2[y] / (y^{small_r} - 1)")
    print(f"a(y) = {a}")
    print(f"b(y) = {b}")
    
    # Method 1: Direct polynomial multiplication
    c_poly = (a * b) % mod_small
    print(f"\nMethod 1 (Polynomial): a*b mod (y^r-1) = {c_poly}")
    
    # Method 2: Circulant matrix multiplication
    v_a = vector(F2_small, a. list() + [0]*(small_r - len(a.list())))
    v_b = vector(F2_small, b.list() + [0]*(small_r - len(b.list())))
    
    # Build circulant matrix for a
    M_a = matrix(F2_small, small_r, small_r)
    for i in range(small_r):
        for j in range(small_r):
            M_a[i, j] = v_a[(i - j) % small_r]

    
    print(f"\nCirculant matrix M_a for a(y):")
    print(M_a)
    
    # Multiply matrix by vector
    v_c = M_a * v_b
    c_matrix = R_small(list(v_c))
    print(f"\nMethod 2 (Matrix): M_a * vec(b) = {c_matrix}")
    
    # Verify they match
    print(f"\nResults match: {c_poly == c_matrix}")
    
    return c_poly == c_matrix

# ============================================================================
# Main Test
# ============================================================================

def test_bike_kem():
    """
    Test the BIKE KEM implementation with a small example.
    Note: Using full parameters (R_BITS=12323) is slow in pure Python/Sage.
    For a quick test, you may want to reduce R_BITS. 
    """
    print("\n" + "="*70)
    print("BIKE KEM TEST")
    print("="*70)
    
    # Generate keypair
    print("\n--- KEY GENERATION ---")
    pk, sk = keygen()
    
    # Encapsulation
    print("\n--- ENCAPSULATION ---")
    ct, ss_enc = encapsulate_bike(pk)
    print(f"Shared secret (encaps): {ss_enc. hex()}")
    
    # Decapsulation
    print("\n--- DECAPSULATION ---")
    ss_dec = decapsulate(ct, sk)
    print(f"Shared secret (decaps): {ss_dec.hex()}")
    
    # Verify
    print("\n--- VERIFICATION ---")
    if ss_enc == ss_dec: 
        print("SUCCESS: Shared secrets match!")
    else:
        print("FAILURE: Shared secrets do not match!")
    
    return ss_enc == ss_dec

# ============================================================================
# Run Tests
# ============================================================================

def test_decoder_only():
    """
    Test the decoder in isolation to verify correctness.
    Creates a known error vector and checks if decoder recovers it.
    """
    print("\n" + "="*70)
    print("DECODER VERIFICATION TEST")
    print("="*70)
    
    # Generate keys
    h0 = sample_sparse_poly(D)
    h1 = sample_sparse_poly(D)
    
    # Generate a known error vector
    e0_true, e1_true = sample_error_vector()
    
    e0_weight = sum(1 for c in e0_true. list() if c == 1)
    e1_weight = sum(1 for c in e1_true. list() if c == 1)
    print(f"True error weights: e0={e0_weight}, e1={e1_weight}, total={e0_weight + e1_weight}")
    
    # Compute syndrome directly:  s = e0*h0 + e1*h1
    syndrome = poly_add(poly_mul_fast(e0_true, h0), poly_mul_fast(e1_true, h1))
    s_weight = hamming_weight(syndrome)
    print(f"Syndrome weight:  {s_weight}")
    
    # Try to decode
    e0_decoded, e1_decoded = bgf_decode(syndrome, h0, h1)
    
    # Check if decoded error matches true error
    e0_match = (poly_to_bytes(e0_true) == poly_to_bytes(e0_decoded))
    e1_match = (poly_to_bytes(e1_true) == poly_to_bytes(e1_decoded))
    
    print(f"\ne0 matches:  {e0_match}")
    print(f"e1 matches: {e1_match}")
    print(f"Decoding SUCCESS: {e0_match and e1_match}")
    
    # Also verify the syndrome is zero after decoding
    final_syndrome = poly_add(
        poly_mul_fast(e0_decoded, h0), 
        poly_mul_fast(e1_decoded, h1)
    )
    print(f"Final syndrome weight:  {hamming_weight(final_syndrome)}")
    
    return e0_match and e1_match


# Run the decoder test first
if __name__ == "__main__":
    print("\n" + "="*70)
    print("BIKE KEM FULL SYSTEM TEST")
    print("="*70)
    print(f"Parameters: R_BITS={R_BITS}, D={D}, T={T}")
    
    # Run KEM tests
    kem_results = []
    for i in range(20):
        result = test_bike_kem()
        kem_results.append(result)
    
    # Print summary
    print("\n" + "="*70)
    print("FINAL RESULTS")
    print("="*70)
    print(f"Success:  {sum(kem_results)}/{len(kem_results)} ({float(100*sum(kem_results)/len(kem_results)):.1f}%)") 
    print(f"Results: {kem_results}")