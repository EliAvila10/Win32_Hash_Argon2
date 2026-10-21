# Win32_Hash_Argon2

Cryptographically secure Argon2id password hashing and verification library for Windows, written in Ada/SPARK.

 ## Features
 - Formal Verification (GNATprove): 100% of verification conditions (VCs) proved.
 - Fail-Closed / Fail-Stop Architecture: Any anomaly, constraint violation, entropy failure, or internal DLL error triggers an immediate,
   safe termination of execution, preventing any state corruption or bypass attempts. 
 - Memory Sanitization: Custom memory wiping wrappers leveraging Windows native primitives (SecureZeroMemory)
   ensure that passwords, salts, and intermediate hashes are aggressively wiped from RAM across all normal and exceptional exit paths.
 - Native Windows Cryptographic Primitives: Leverages high entropy system providers (ProcessPrng with automatic fallback to BCryptGenRandom)
   for cryptographically secure salt generation.

 ## Exception Handling & Fault Isolation
 
 Designed under a zero trust internal model, the library explicitly classifies and intercepts failure vectors:

- Entropy Failures (Entropy_Salt_Error): Triggers immediate fallback mechanisms 
  or total memory sanitization if cryptographic randomness cannot be securely acquired.
- Constraint & Memory Violations (Constraint_Error): Intercepts unexpected memory state modifications or boundary faults as
  potential indicators of tampering or environment corruption, forcing a fail-stop.
- Argon2 API Faults (Argon2_Failed): Wraps and isolates low-level C library errors, mapping clear diagnostic codes while purging sensitive buffers.

 ## Build and run
 alr build
 alr run

 - alr run executes the win32_hash_argon2 executable declared in alire.toml,
  the demo in win32_hash_argon2.adb, which hashes a password and then verifies it twice:
  once with a different password (it must fail) and once with the same password (it must succeed).



