### Understanding the HMAC Implementation
HMAC BASE CODE SOURCE : https://github.com/python/cpython/blob/main/Lib/hmac.py 
This Python code implements the HMAC (Hash-based Message Authentication Code) algorithm as specified in RFC 2104. HMAC is used to verify both the data integrity and the authenticity of a message.

**Core Concepts:**

1.  **Hash Function (`digestmod`):**
    *   HMAC relies on an underlying cryptographic hash function (e.g., SHA-256, MD5).
    *   The `digestmod` parameter allows you to specify which hash function to use. It can be a string name (like `"sha256"`), a hash constructor from `hashlib` (like `hashlib.sha256`), or a PEP 247 compliant hash module.
    *   The `_get_digest_constructor` function standardizes the `digestmod` input into a callable constructor that produces hash objects.

2.  **Secret Key (`key`):**
    *   A secret key, shared between the sender and receiver, is crucial for HMAC.
    *   **Key Processing:**
        *   If the key is longer than the hash function's block size, the key is first hashed to fit.
        *   If the key is shorter than the block size, it's padded with zero bytes.

3.  **HMAC Algorithm (RFC 2104):**
    The formula is `H(K XOR opad || H(K XOR ipad || message))`, where:
    *   `H` is the chosen hash function.
    *   `K` is the (processed) secret key.
    *   `ipad` (inner pad) is `0x36` repeated to fill one block of the hash function.
    *   `opad` (outer pad) is `0x5C` repeated to fill one block.
    *   `||` denotes concatenation.

    **Implementation Details:**
    *   `trans_36` and `trans_5C`: These are precomputed translation tables. `key.translate(trans_36)` effectively calculates `K XOR ipad`, and `key.translate(trans_5C)` calculates `K XOR opad`.
    *   **Inner Hash:** `H(K XOR ipad || message)`
        *   The `_inner` hash object is initialized.
        *   It's updated with `key.translate(trans_36)`.
        *   Then, it's updated with the message (`msg`).
    *   **Outer Hash:** `H(K XOR opad || result_of_inner_hash)`
        *   The `_outer` hash object is initialized.
        *   It's updated with `key.translate(trans_5C)`.
        *   Then, it's updated with the digest (output) of the `_inner` hash.
    *   The final result of the `_outer.digest()` is the HMAC value.

4.  **Optimization Attempts:**
    *   The code first tries to use optimized HMAC implementations if available:
        *   `_hashopenssl`: A C extension using OpenSSL's HMAC functions (usually faster).
        *   `_hmac`: Python's internal C implementation of HMAC.
    *   If these are not found or don't support the given `digestmod`, it falls back to the pure Python implementation (`_init_old` for the class, `_compute_digest_fallback` for the one-shot `digest` function).

5.  **`HMAC` Class:**
    *   `__init__`: Initializes the HMAC object. It now uses the `HmacConfig` Pydantic model to validate input parameters (`key`, `msg`, `digestmod`) before proceeding with the internal initialization logic (`_internal_init`).
    *   `update(msg_chunk)`: Allows the message to be processed in chunks.
    *   `digest()`: Returns the HMAC as bytes.
    *   `hexdigest()`: Returns the HMAC as a hexadecimal string.
    *   `copy()`: Creates a copy of the HMAC object.
    *   `name`: Provides a name for the HMAC instance, like "hmac-sha256".

6.  **Utility Functions:**
    *   `new(key, msg, digestmod)`: A factory function to create `HMAC` objects. It also benefits from the Pydantic validation within the `HMAC` class constructor.
    *   `digest(key, msg, digestmod)`: A function for a one-shot HMAC calculation, useful when the entire message is available at once. It also uses `HmacConfig` for input validation.

**Pydantic Integration:**
Your `HmacConfig` Pydantic model is used at the entry points (`HMAC.__init__`, `new`, `digest`) to ensure that the `key`, `msg`, and `digestmod` parameters conform to the expected types and constraints (e.g., `digestmod` being a valid hash identifier or callable) before the core HMAC logic proceeds. This enhances type safety and provides clear error messages for invalid inputs.
