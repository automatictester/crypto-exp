# Cryptography

### Theory

Goals of cryptography:
- Confidentiality:
  - Encryption
- Authentication:
  - MACs
  - Public key cryptography
- Integrity:
  - Hash functions
  - MACs
- Non-repudiation:
  - Digital signatures

Kerckhoff's principle:
- Cryptosystem should remain secure even if everything about the system, except the key, is public knowledge
- Therefore, system may be stolen by the enemy, not causign any problems if key remains secret

Ciphers:
- Secure cipher - brute force is the best possible attack
- Broken cipher - an attack substantially better than brute force exists

Confusion and diffusion:
- Two properties of a secure cipher
- Confusion - relationship between plaintext, ciphertext and the key are difficult to spot
- Diffusion - changing single bit of plaintext changes half of the bits in ciphertext and vice versa

Security goals:
- IND (indistinguishability) - ciphertext should be indistinguishable from random sequence
- NM (non-malleability) - ciphertext cannot be transformed into another ciphertext, which decrypts to related plaintext

Semantic security:
- Also known as IND-CPA (indistinguishability - chosen plaintext attack)
- Ciphertext should reveal nothing about plaintext as long as key remains secret
- Requires encrypting the same plaintext twice to produce different ciphertext

Information-theoretic security:
- Defines purely theoretical concept of trully unbreakable cryptographic system
- Attacker, even with unlimited time and processing power, cannot get to know anything except plaintext length
- Only one such system exists - only one time pad, random key, len ( K ) >= len ( P )
- Simple, although not non-malleable example: C = P ⊕ K

Computational security:
- Attacker with limited time and processing power cannot break the cipher
- Even if you know P and C, this is still computationally secure because testing 2<sup>n</sup>, e.g. 2<sup>128</sup>
  keys would take too much time

Provable security:
- Refers to the situation when breaking the cipher is proved to be at least as hard as solving some other mathematical
  or statistical problem

Heuristic security:
- Although there is no direct relation to another hard problem, but others were unable to break the cipher
- Example: AES

### Randomness

Overview:
- Non-cryptographic PRNGs shouldn't be used in cryptography, because the focus on distribution, not predictability
- Statistical tests are useless in determining cryptographic suitability (non-predictability) of a PRNG

RNG:
- Trully random/non-deterministic
- Slow
- Based on analog resources
- Don't guarantee high levels of entropy

PRNG:
- Based on RNG (digital sources)
- Deterministic
- Offer maximum entropy
- Can be either software or hardware

PRNG types:
- Cryptographic:
  - Python `os.urandom()` and `secrets.SystemRandom` class
  - OS-level `/dev/random` and `/dev/urandom`
- Non-cryptographic:
  - Very often based on Mersenne Twister
  - Python `random`

/dev/random vs /dev/urandom:
- Both are secure, although `urandom` is stronger
- `random` blocks if its estimate of entropy is too low
- For that reason, implementations based on `random` are prone to DoS
- `random` is based on entropy estimation, which is generally a challenge

PRNG algorithms:
- Yarrow:
  - Based on SHA-1 and 3DES
  - Used in iOS and macOS
  - Used by FreeBSD until they migrated to Fortune
- Fortuna:
  - Successor to Yarrow
  - Used by Windows and (currently) FreeBSD

### Symmetric-key cryptography

Overview:
- Uses same key for encryption and decryption
- Key length = level of security, 128 bit key = 128 bit security
- For a 128 bit key, every single of 2<sup>128</sup> keys is valid

Sub-categories:
- Block ciphers
- Stream ciphers

### Block Ciphers

Overview:
- Encryption function converting block size input into same size output
- Characterized by block size and key length
- Common features of current generation of block ciphers:
  - Block size of 128 bits
  - Key sizes between 128 and 256 bits
- Consist of multiple rounds of relatively simple operations
- Block cipher with 3 rounds:
  - C = E<sub>RK3</sub> ( E<sub>RK2</sub> ( E<sub>RK1</sub> ( P ) ) )
- Each round uses the same algorithm, but different round key, derived from main key
- Require padding, except streaming modes and CTS. In theory, any padding scheme that is reversible is acceptable 
- Derivation of round key is called key schedule
- Key schedule is required to avoid sliding attacks
- Consequences of too large block size:
  - Longer ciphertext, due to longer padding
  - Higher memory utilisation and slower speed, if it doesn't fit into CPU register
- Too small block size = risk of code book attack

Types:
- Feistel network: early design, e.g. DES, Blowfish, Twofish
- SP network, modern design, e.g. AES

Secure:
- AES
- 3DES
- Blowfish
- Twofish

Insecure:
- DES
- GOST

### DES

- Key length: 56 bits, hence insecure from day one
- Block size: 64 bits
- Type: Feistel network
- Rounds: 16
- Each 48 bit round key is formed by selecting 48 bits from 56 bit key
- Optimized for dedicated hardware, not modern CPUs
- Introduced also the following modes of operations: ECB, CBC, CFB, OFB

### 3DES

- Secure by current standards, but slower than AES, hence no reason to use in new designs
- It inherits certain properties of DES. This includes its block size, which places certain restrictions 
  on the number of blocks that can be encrypted using single key
- C = E<sub>K3</sub> ( D<sub>K2</sub> ( E<sub>K1</sub> ( P ) ) )

Keying options:
- K<sub>1</sub> ≠ K<sub>2</sub> ≠ K<sub>3</sub> - 3x 56 bit key gives 168 bits total key length, however only 112 bits
  of security due to meet-in-the-middle attacks
- K<sub>1</sub> ≠ K<sub>2</sub>, K<sub>1</sub> = K<sub>3</sub> - 2x 56 bits gives 112 bits total key length, 
  however only <= 80 bits of security
- K<sub>1</sub> = K<sub>2</sub> = K<sub>3</sub> - same as original DES, only for compatibility reasons

### Serpent

- AES finalist, 2nd place
- Conservative approach to security with large security margin
- 1/3 the speed of AES and nearly as fast as DES, which is most likely the reason it didn't win the competition
- Key length: 128, 192 or 256 bits
- Block size: 128 bits
- Type: SP network
- Rounds: 32

### Blowfish

- Key length: 32-448 bits
- Block size: 64 bits
- Type: Feistel network
- Rounds: 16

### Twofish

- Designed as a successor to Blowfish
- AES finalist, 3rd place
- Key length: 128, 192 or 256 bits
- Block size: 128 bits
- Type: Feistel network
- Rounds: 16

### GOST

- Original name: Magma
- Developed in 1970's in Soviet Union. Initially Top Secret, downgraded to Secret in 1990, published in 1994
- Insecure, with nearly feasible attack at 2<sup>101</sup>
- Design based on Feistel network and similar to DES

| |DES|GOST|
|---|---|---|
|Key length|56 bits|256 bits|
|Block size|64 bits|64 bits|
|Rounds|16 rounds|32 rounds|

### AES competition

Finalists:
- Rijndael (winner)
- Serpent
- Twofish
- RC6
- MARS

Overview:
- Each cipher had attacks which can successfully handle (only) up to a certain number of its rounds
- These attacks were known at the time of the competition and some of them might have been improved since then

### AES

- Original name: Rijndael
- Type: SP network
- Block size: 128 bits, or 16 bytes (matrix of 4x4 bytes)
- Operates on bytes, not bits
- Key length / rounds: 128 bit with 10 rounds, 196 bit with 12 rounds, 256 bit with 14 rounds
- With AES being a standard, AES-NI (AES New Instructions) is currently implemented by vast majority of CPUs in
  desktops, laptops, tables and mobile phones, includingIntel and AMD CPUs
- AES-NI gives 10x boost; 2 GHz CPU with AES-NI offers over 0.7 GB/s throughput (per single thread) - with 4 threads
  that would be 3 GB/s throughput 
- Used in Microsoft BitLocker and Apple FileVault 2 disc encryption
- Particular weakness - having a round key, attacker can get other round keys and main key

AES, CBC and padding:
- There are multiple padding mechanisms available:
  - PKCS#5:
    - Currently most popular, sometimes also referred to as PKCS#7 (RFC 5652) - these are synonyms today  
    - Padding length: between 1 byte and 1 block
    - Padding depends on the number of empty bytes (not bits) in the last block:
      - 1 - 1 (decimal) is added
      - 2 - 2x 2 (decimal) is added
      - ...
      - 15 - 15x 15 (decimal) is added
      - If there are no empty bytes in the last block, i.e. when P length is a multiple of block size, another block
        filled with 16x 16 (decimal) is added. This is required to distibguish between last block ending with decimal 1
        being a padding vs part of actual plaintext
  - Zero byte padding:
    - Should not be used any more
    - Appends zero bytes
    - Dangerous if the original plaintext ends with zero byte
- Problems with padding:
  - Increased ciphertext length
  - Prone to padding oracle attacks

CTS:
- Ciphertext stealing, an alternative to padding
- Requires plaintext to be of at least block size length 
- Less elegant, more complex (standard defines 3 possible implementations) and less popular
- Having said that, from developer point of view, if the library you are using supports it, it's just an option to use
- Not prone to padding oracle attacks

### Block cipher modes

|Mode|Encryption|Notes|
|---|---|---|
|ECB|C = E ( P )|see <sup>2</sup>; not semantically secure|
|CBC|C = E ( P ⊕ C<sub>i-1</sub> )|see <sup>1</sup> and <sup>2</sup>|
|CFB|C = E ( C<sub>i-1</sub> ) ⊕ P|see <sup>1</sup>|
|OFB|C<sub>0</sub> = E ( IV ) ⊕ P<br> C<sub>1</sub> = E ( E ( IV ) ) ⊕ P<br>...|see <sup>1</sup>|
|CTR|C = E ( N + C ) ⊕ P|uses nonce and counter, see <sup>3</sup> and <sup>4<sup>|

<sup>1</sup> - in first iteration IV is used, as there is no C<sub>i-1</sub> yet 

<sup>2</sup> - requires padding

<sup>3</sup> - amount of space to the counter determines how many blocks the cipher can process safely;
  e.g. 8 bit counter only allows for 265 blocks

<sup>4</sup> - nonce and counter can be combined using any invertible operation: concatenation, addition and XOR;
               e.g. 64 bit nonce (48 bit message number + 16 bit additional nonce data) + 64 bit counter

|Mode|Encryption parallelizable|Decryption parallelizable|Random access|Requires padding|
|---|---|---|---|---|
|ECB|yes|yes|yes|yes|
|CBC|no|yes|yes|yes|
|CFB|no|yes|yes|no|
|OFB|no|no|no|no|
|CTR|yes|yes|yes|no|

Block cipher mode recommendations:
- Don't use ECB, it is insecure
- Don't use OFB, as it is not as good as either CBC or CTR
- Use either CBC or CTR, unless you need AE

### Initialization vector (IV)

Types:
- Fixed IV:
  - Shouldn't bt used as it introduces ECB problem for the first block of the message
- Counter IV:
  - IV = 0 for first message, IV = 1 for second message - which differ only with LSB in binary representation
  - Shouldn't be used - if leading plaintext blocks of first two messages also differ only in LSB, ciphertexts 
    will be identical
- Random IV:
  - Only disadvantage is significant message expansion for short messages
- Nonce-generated IV:
  - Each message to be encrypted is given a nonce
  - IV is generated by encrypting the nonce
  - Encrypt plaintext using the IV
  - Add enough information to the ciphertext to ensure receiver can reconstruct the nonce - IV doesn't need to be sent
  - Main benefit is reduced message expansion than with random IV

### Nonce

Overview:
- Number used once
- Often a message number, optionally combined with another information (depending on context)
- Requirements:
  - Unique
  - Can't be reused with the same key - block mode doesn't matter, although for some modes this is more disastrous
    than for the others
  - Doesn't have to be secret
  - Can't wrap around as that would destroy uniqness property
  - As large as block size
- If nonce generation might be a problem, don't use either CTR or CBC/CFB/OFB with nonce-generated IV

### Stream ciphers

Overview:
- In the past, weaker than block ciphers and cheaper to implement in hardware
- They are closer to DRBG (Deterministic Random Bit Generators) than PRNG because they need to be deterministic
- While DRBG takes one input: initial value / seed, stream ciphers take two: initial value and a key
- Key is usually 128-256 bits, initial value 64-128 bits
- Initial value is similar to nonce - doesn't have to be secret but has to be unique
- General form: C = E ( K, N ) ⊕ P
- Almost all stream ciphers are based on FSR (Feedback Stream Register)
- Software stream ciphers operate on bytes or 32/64 bit words, which is more efficient on modern CPUs, which can execute
  arithmetic instructions on words as quickly as on bits

Types:
- Stateful, e.g. RC4
- Counter-based, e.g. Salsa20

Types:
- Hardware:
  - A5/1 - insecure, used in 2G telecommunications
  - Grain - secure, eSTREAM portfolio
- Software:
  - RC4 - insecure, doesn't use a nonce (!)
  - Salsa20 - secure, eSTREAM portfolio
  
### Feedback Shift Register

Overview:
- Focussed on hardware implementations
- Non-linear FSRs are more secure and contain not only XOR, but also AND and OR

Example of Linear FSR:
- Initial value: 1100
- Shift all bits one to the left
- Apply linear function f XORing all bits from previous values to calculate value of right-most bit
- Iterations:
  - 1100
  - 1000
  - 0001
  - 0011
  - 0110

### Salsa20

- Modern, counter-based stream cipher created by D. Bernstein
- State size: 512 bits (4x4 matrix of 32 bit words), including:
  - Key size: 256 bits
  - Nonce: 64 bits
  - Counter: 64 bits
- 20 rounds, hence its name
- Other variants: Salsa20/12, Salsa20/8, where 20 and 8 refer to number of rounds respectively
- Improved version is called ChaCha, with most popular variant called ChaCha20

### Hash Functions

Overview:
- Hash function is a one-way function that takes an input of arbitrary length and produces fixed-size output
- Output of a hash function is called hash, message digest or fingerprint
- Hash function is indistinguishable from a random mapping
- Common pre-SHA-3 hash functions (MD5, SHA-1, SHA-2) are iterative hash functions. They split the message into 
  a sequence of fixed-sized blocks (with padding), and then process them sequentially using, each time using output from
  hashing previous block as an input
- Hash functions are used for data integrity verification, in HMACs and digital signatures
- Hash functions are never collision-free, but need to be collision-resistant, i.e. the collisions cannot be easily found
- Secure hash function has collision-resistance of 2<sup>n/2</sup> and preimage attack resistance of 2<sup>n</sup>
- Should not be used to store masked passwords, due to ranbow table attacks

Design considerations:
- See design considerations for MAC

Insecure hash functions:
- All non-cryptographic hash functions, e.g. CRC
- MD5
- SHA-1

Secure hash functions:
- SHA-2
- SHA-3
- BLAKE

Digest size:
- MD5: 128 bit (32 hex)
- SHA-1: 160 bit (40 hex)
- SHA-256 - 256 bit (64 hex)

Types:
- Based on Davies-Mayer compression function with Merkle-Damgard construction - majority of hash functions
- Based on sponge function, e.g. SHA-3

Merkle-Damgard construction:
- Apply compression function to all blocks
- Finalise
- Hash

Davies-Meyer compression function:
- H<sub>i</sub> = F ( M<sub>i</sub>, H<sub>i-1</sub> ) ⊕ H<sub>i-1</sub>
- Use IV in first iteration

### MD5

- Hash size: 128 bits

### SHA-1

- Based on SHA-0 (at that time called just SHA)
- Hash size: 160 bits
- Block size: 512 bits
- Padding: `[1010101|1000...0000111]`, where:
  - `101010101` is actual message
  - followed by `1`
  - followed by number of `0`'s
  - followed by `111` defining actual length of actual data in this block

### SHA-2

Overview:
- SHA-256 and SHA-512 are base algorithms, from which SHA-224 and SHA-384 are derived with only minor modifications.
- Rounds: 
  - SHA-256 (and SHA-224) - 64 rounds
  - SHA-512 (and SHA-384) - 80 rounds

Family of 6 functions:
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA512/224
- SHA512/256

SHA-384, SHA-512, SHA512/224 and SHA512/256 are faster than SHA-224 and SHA-256 for long messages on 64-bit platforms.
In particular, SHA512/224 and SHA512/256 are faster than SHA-224 and SHA-256 while maintaining the same hash size and security level.
SHA512/224 and SHA512/256 are not prone to length extension attacks.

### SHA-3

- Designed as a futur ealternative if SHA-2 gets broken one day
- Alternative, not a successor to SHA-2 family, because SHA-2 hasn't been broken yet
- New structure, purposefully different from SHA-2 to keep it secure even if SHA-2 gets broken one day
- Based on Keccak algorithm (sponge function)
- In contrary to older hash algorithms, not prone to length extension attacks

Similarly to SHA-2, family of 4 algorithms:
- SHA3-224
- SHA3-256
- SHA3-384
- SHA3-512
- SHAKE128
- SHAKE256

### MAC

- MAC is a one-way function that takes in key and message as input and produces fixed-size output called 
  MAC code or tag
- To a degree similar to hash function, but MAC uses a secret key while hash function does not
- Secret key is shared between party creating and validating MAC
- Benefits of MAC:
  - Integrity - without key, data cannot be changed in a way that attached tag remains valid
  - Authenticity - only party with access to the key could have generated valid tag
- MAC itself doesn't protect against:
  - Malicious message deletion
  - Replay attacks
- T = MAC ( K, M ), where T stands for tag
- Types of MACs:
  - HMAC - Hash-based Message Authentication Code or Keyed-Hash Message Authentication Code
    - Very popular
    - Most agree, that collision attack on HMAC in impractical, as it would require collection of 2<sup>n/2</sup>
      pairs of messages and corresponding HMAC values.
      Source: [NIST SP 800-107 Revision 1](https://csrc.nist.gov/publications/detail/sp/800-107/rev-1/final)
      section 5.3.4.
    - E.g. HMAC-SHA256
  - Dedicated MAC constucts, e.g.:
    - Poly1305:
      - Initially designed as Poly1305-AES, later decoupled
      - Optimised for modern CPUs and large messages
      - Secure, but not as much as other types of MACs - focus on performance
      - Used by Google in Chrome, Android and Google's websites
    - SipHash:
      - Designed to prevent DoS attacks against hash tables (hash flooding)
      - Optimised for short messages
      - SipHash-x-y, e.g. SipHash-2-4 (default) - 2 is the number of rounds per message block and 4 is the number of 
        finalization rounds
      - SipHash-4-8 is 2x slower but is a good choice for conservative security

**Design considerations**

Q: Would it make sense to use hash function H with secret key K concatenated with message M as follows: H ( K || M ) 
   instead of MAC?

A: This shouldn't be done using hash functions prone to length extension attacks, i.e. non-truncated versions of SHA-2
   and earlier functions.
   This theoretically could be done using hash functions not prone to length extension attacks, i.e. truncated versions
   of SHA-2 or any version of SHA-3. However, it doesn't make sense for performance reasons.
   HMAC-SHA256 offers 256 bit strength and should be faster than SHA3-512 offering comparable level of security.
   Sources: [Wikipedia](https://en.wikipedia.org/wiki/SHA-2#Comparison_of_SHA_functions) and
            [Jackson Dunstan](https://www.jacksondunstan.com/articles/3206).

Q: Would it make sense to use hash function H with secret key K concatenated with message M as follows: H ( M || K) 
   instead of MAC?

A: It is not as bad as the previous example. However, such hash function could still be a subject to collision attack,
   which are not practical for HMACs. Also see previously stated performance reasons.

Q: What key length should be used with HMAC?

A: As a rule of thumb, use key length equal output size of the underlying hash function.
   Using shorter key would reduce HMAC strength. Using longer key doesn't improve security, as 
   `HMAC strength = min(key length, preimage resistance of underlying hash function, length of HMAC output)`.
   When using untruncated HMAC output, which is a typical scenario, 3rd parameter is irrelevant as it is same as 2nd.
   Sources: [RFC 2104](https://tools.ietf.org/html/rfc2104) sections 2 and 3, and 
            [NIST SP 800-107 Revision 1](https://csrc.nist.gov/publications/detail/sp/800-107/rev-1/final)
            sections 4.1, 5.3.1 and 5.3.4.

Q: What are CBC-MAC security limitations?

A: These include:
- Limited strength equal to half of the underlying block cipher's block size, e.g. only 2<sup>64</sup> for AES. 
  This is due to collision attacks.
- Cannot be securely used with the same key to authenticate messages of different length.
  Source: [Wikipedia](https://en.wikipedia.org/wiki/CBC-MAC). 

Q: How to use MAC to prevent replay attacks?

A: Options include:
  - Apply MAC to ( additional data || message ), where additional data include:
    - Message number, so that already processed messages can be rejected
    - Timestamp, introducing message validity time window as an alternative to message numbering scheme
    - Direction indicator, if applicable, so that the same message cannot be send in opposite direction
    - Separators between elements of additional data and message itself, to authenticate what was meant,
      not what was said

Q: What are GMAC security limitations?

A: See design considerations for authenticated encryption.

### Authenticated encryption

- Approaches:
  - Encrypt-and-MAC (E&M):
    - Least secure:
      - MAC validation requires decrypting C
      - There is a risk that MAC will leak information about P
  - MAC-then-Encrypt (MtE):
    - Security in between the other two:
      - MAC validation requires decrypting C
      - Hiding MAC inside C prevents it leaking information about P
  - Encrypt-then-MAC (EtM):
    - Most secure:
      - MAC validation doesn't require decrypting C

Authenticated Encryption with Associated Data (AEAD):
  - Currently all AE ciphers support AAD
  - All use IV
  - Special cases:
    - Blank AAD - AE
    - Blank P - MAC
  - Ciphers:
    - ChaCha20-Poly1305
    - AES-GCM:
      - Most popular
      - EtM type
      - Based on CTR, hence parallelisable both ways
      - MAC calculation is not parallelisable
      - Entire computation is parallelisable, because MAC doesn't require entire C to start calculations
      - Recommended IV length is 96 bits (12 bytes), although using arbitrary lengths is technically possible
      - Sensitive to IV reuse
      - GCM mode can work with any block cipher, but vast majority use it only in combination with AES
      - GCM stands for Galois Counter Mode
      - Resulting variant of AES-GCM with AAD but blank P is called GMAC
    - AES-CCM:
      - CCM stands for Counter with CBC-MAC
      - One of very few ciphers allowed in TLS 1.3 - alongside AES-GCM and ChaCha20-Poly1305
      - MtE type
      - Based on CTR
    - AES-EAX:
      - EtM type
      - Based on CTR
    - AES-OCB:
      - Offset Codebook
      - Older, faster and more simple than GCM
      - Requires a license, however since 2013 licenses are granted free of charge for non-military use
      - Less sensitive to IV reuse (but still)
    - AES-GCM-SIV:
      - Synthetic IV
      - Less sensitive to IV reuse
      - Almost as fast as pure AES-GCM
      - Cannot process streams - requires entire P to be encrypted to C

**Design considerations**

Q: What are AES-GCM security limitations?

A: AES GCM produces authentication tags of 128, 120, 112, 104 or 96 bits. However, using tags below 128 bits
   is discouraged, because bit strength reduction is worse than linear. Same applies to subsequent tag truncation.

### Key Stretching

- Key stretching algorithms convert weak keys (usually passwords) into strong keys
- Key stretching algorithm takes secret input (password) as well as some public values (salt and iteration count) 
  and returns symmetric key
- Most popular examples:
  - PBKDF2
  - bcrypt
- The more CPU- and memory-intensive, the better
- Salt:
  - Random bytes
  - Can be of any length but should be at least as long as the size of output produced by PRF the algorithm is based on
  - Prevents rainbow table attacks
  
### Pre-Shared Key

- Secret which was previously shared between the two parties before it needs to be used

### Public Key Cryptography

- Slower, but more secure than symmetric cryptography. For this reason frequently used to establish a shared secret
  which is then used to encrypt actual communication
- Level of security < key length
- Key length < key size on disk
- In contrary to symmetric keys, not every combination of 2<sup>n</sup> bits results in a valid value which can be used 
  in public key cryptography
- Keys used in publik key cryptography are composed of a set of integers, not random sequence of bytes
- Encrypt with recipient's public key to guarantee only he can decrypt it
- Encrypt with your private key to prove authenticity

### Digital Signatures

- Use hybrid schemes with a signature calculated over hash of the data
- Main variants:
  - Deterministic, e.g. RSA
  - Non-deterministic, e.g. typical variants of DSA
- Signature strength depends on the strength of the component parts, i.e. public key algorithm, key size and 
  message digest
- Rule of thumb: make the public key algorithm the weakest part

### Key Transport

- Process of getting a symmetric key to another party after generating it locally
- RSA and ElGamal are the only algorithms that directly offer this ability

### DSA

- Has multiple very different variants
- Security of non-EC (including non-Ed) variants of DSA is based on difficulty of DLP (discreet logarithm problem) 
  \- similarly to DH
- Signature consists of R and S - two signed integers
- Signatures may vary slightly in length, due to presence, or lack, of a sign byte
- Random value K is needed in non-deterministic variants of DSA for signing only and needs to remain secret
- Signing: Signature = Sign ( MessageDigest, RandomValue, PrivateKey )
- Verification: ( True, False ) = Verify ( MessageDigest, Signature, PublicKey )
- Security of DSA depends on randomness of K. Weak RNG can compromise security of DSA
- Variants:
  - DSA
  - ECDSA - DSA over Elliptic Curve
  - DDSA - Deterministic DSA
  - ECDDSA - Deterministic DSA over Elliptic Curve
  - EdDSA - DSA with Edwards Curves (deterministic only):
    - Ed25519 - 128 bits of security, combined only with SHA-512
    - Ed448 - 224 bits of security, combined only with SHAKE256

### RSA

Security of RSA:
- Security of RSA is based on difficulty of factoring problem, factoring the product of two large prime numbers: 
  n = p * q
- Fundamental theorem of arithmetic says that every integer greater than 1 either is a prime number itself,
  or can be represented as the product of (2 or more) prime numbers and that, this representation is unique
- Factoring problem is a NP (nondeterministic polynomial) problem - solution can be verified, but not found, in
  polynomial time, i.e. has a complexity of O(n<sup>c</sup>)
- Prime numbers p and q must be carefully chosen to avoid numbers of certain characteristics, which could have
  catastrophical consequences for security
- RSA keys can directly process input of size just under the key length, hence the typical use cases:
  - RSA signature takes hash of original message as an input
  - RSA key is used to encrypt symmetric key which is used to encrypt original message, not the message itself

Operations:
- Signing:
  - S = PAD ( H ( M ) )<sup>d</sup> mod n
- Verification:
  - ( True, False ) = S<sup>e</sup> mod n
- Encryption:
  - C = PAD ( M )<sup>e</sup> mod n
- Decryption:
  - P = C<sup>d</sup> mod n
- Naive implementations based on power-then-modulo are slow. Optimised implementations are significantly faster, 
  and could include:
  - SageMath's power_mod(x, e, n)
  - Python's pow(x, e, n)

Signing with RSA-PSS:
- PPS - Probabilistic Signature Scheme
- PSS is an equivalent of OAEP for signing
- More secure than plain RSA
- Non-deterministic and standardized as part of PKCS#1 v2.1, which is a replacement for deterministic PKCS#1 v1.5
- No known attacks against PKCS#1 v1.5 exist, however PKCS#1 v2.1 has provable security which PKCS#1 v1.5 has not

Encryption with RSA-OAEP:
- OAEP - Optimal Asymmetric Encryption Padding
- More secure than plain RSA
- Based on PRNG
- Non-deterministic

RSA keys:
- Both public and private keys consist of sets of integers
- Private key is contains more integers than public key
- Most important of them, shared between public and private keys, is modulus (n)
- Length of RSA key is defined by the bit length of its modulus
- Keys can be used for encryption (encryption using recipient's public key) or signing (signing with sender's
  private key)

Key generation:
- For a given key size, choose 2 random strong prime numbers p and q (matching certain criteria) 
  of bit length equal to key size / 2 each
- Verify p ≠ q
- Calculate n = p * q
- Verify bit lenght of n == key size. This should be the case if p and q are strong primes
- Calculate phi ( n ) = ( p - 1 ) * ( q - 1 )
- Use public exponent e = 65537. If not, calculate prime number e, such that 1 < e < phi ( n )
- Calculate private exponent d = xgcd ( e, phi ) \[ 1 ]
  - Function xgcd, sometimes called egcd, is extended greatest common divisor
  - Depending on the implementation, sometimes d calculated this way may be negative.
    In such case use d = d + phi instead 
  - Python's Crypto.Util.number.inverse(e, phi) is free from this inconvenience
  - Verify d is less than but close to n
- Optionally verify ( e * d ) mod phi = 1
- Please note phi is the only calculated value which isn't persisted in a private key

Private key:
- Modulus n
- Private exponent d
- Public exponent e
- Prime numbers p and q - also referred to as prime1 and prime2
- exponent1, exponent2, coefficient - used in chinese remainder theorem to speed up operations 
  involving private key (signing and decryption)

Public key:
- Modulus n
- Public exponent e

Why public exponent e is usually 65537 (hex value 0x10001):
- Small valid values of public exponent e include: 3, 5, 17, 257 or 65537
- Early RSA implementations without proper padding were vulnerable to small exponents
- Large enough to be secure and significantly more secure than 3, small enough to be efficient in public key 
  (signature verification and encryption)
- Having small private exponent could cause security issues
- With such e, private exponent d is close to n, which then makes sense to speed up private key operations with
  chinese remainder theorem

Inspecting RSA keys with OpenSSL:
- openssl rsa -in rsa -text -noout
- openssl rsa -in rsa.pub -text -pubin -noout

### Diffie-Hellman Key Exchange

Overview:
- Security of DH is based on difficulty of DLP (discreet logarithm problem) - computing secret g<sup>ab</sup> from
  public g<sup>a</sup> and g<sup>b</sup>
- Anonymous DH is prone to man-in-the-middle attacks
- Authenticated DH uses PK cryptography, e.g. RSA-PSS, to avoid man-in-the-middle attacks

Sequence:

|Alice|Public|Bob|
|:---:|:---:|:---:|
|a|p, g|b|
|A = g<sup>a</sup> mod p|<==>|B = g<sup>b</sup> mod p|
|A, B| |A, B|
|s = B<sup>a</sup> mod p| |s = A<sup>b</sup> mod p|

Where:
- p - prime modulus, of certain characteristics
- g - prime base

### Elliptic Curve Cryptography

Benefits:
- Significantly shorter key length for the same level of key strength
- Public and private key operations offer similar performance, which implies:
  - In comparison to RSA - faster private key operations
  - In comparison to RSA - slower public key operations
- Reduced storage and transmission requirements
- Key strength is 2<sup>n/2</sup>, i.e. 128 bit security for 256 bit key
- Alternative for DLP problem-based systems, like DH

Applications:
- ECDH
- ECDSA

Popular curves:
- P-256 - designed by NSA, part of NIST standard, 256 bit length
- Curve25519 - designed for use with ECDH, fast, more trusted than NSA-designed curves, not part of NIST standard, 
  256 bit length

### Security strength comparison

Comparable security strength (bits), according to common understanding:

|Symmetric|RSA / DSA / DH|EC / SHA|
|---|---|---|
|80|1024|160|
|112|2048|224|
|128|3072|256|
|192|7680|384|
|256|15360|512|

CNSA Suite, successor to NSA Suite B, includes the following:
- AES-256
- ECDSA 384 bit
- ECDH 384 bit
- SHA-384
- DH 3072 bit
- RSA 3072 bit
- All of the above match Top Secret requirements
- The list is clearly **not** in line with the common understanding

### Key usage recommendations

Opinions might wary:
- Use keys giving at least 112 bit of security
- In general don't use a single key to encrypt more than 2 <sup>block size / 2</sup> blocks
- In particular, don't use a single key to encrypt more than:
  - CBC mode - up to 2<sup>32</sup> blocks
  - CTR mode - up to 2<sup>60</sup> blocks

### (Perfect) Forward Secrecy

- Compromising K<sub>x</sub> allows to decrypt messages encrypted using K<sub>x...n</sub>
  but doesn't allow to decrypt messages encrypted K<sub>0...x-1</sub> 
- DH key exchange - Forward Secrecy
- DHE key exchange (Ephemeral) - Perfect Forward Secrecy
- Doesn't allow for decrypting traffic using static symmetric encryption keys, e.g. in a bank
- Enforced with TLS 1.3

### Transport Layer Security

Overview:
- Build upon 2 protocols:
  - Record protocol
  - Handshake protocol
- Server makes a final decision on cipher suite to use
- Cipher suite defines:
  - Protocol: TLS 1.3, TLS 1.2, or no longer secure TLS 1.1, TLS 1.0, SSL 3.0, SSL 2.0
  - Key exchange: TLS 1.3 allows only variants of DHE
  - Authentication: TLS 1.3 allows only RSA, ECDSA, EdDSA and PSK
  - Cipher: TLS 1.3 allows only AES-GCM, AES-CCM and ChaCha20-Poly1305
  - Hash: TLS 1.3 allows only SHA256 and SHA384

TLS 1.3:
- Reimplementation with security, performance and simplicity in mind
- Support for only 5 cipher suites (previously 37) - dropped support for less secure options
- Allows only AEAD ciphers
- Sample TLS 1.3 cipher suite: TLS_AES_256_GCM_SHA384 vs sample TLS 1.2 cipher suite: 
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- Handshake reduced to 1 instead of 2 rounds
- Requires PFS (hence RSA cannot be used for key exchange)

TLS 1.3 handshake:

|Step|Client|Server|
|---|---|---|
|1|Client sends Client Hello with: cipher suites, public DH key| |
|2| |Server generates DH keys, calculates DH shared secret, derives symmetric key|
|3| |Server responds with Server Hello with selected cipher suite, public DH key, signature, MAC|
|4|Client verifies certificate, signature, calculates DH shared secret, derives symmetric key, verifies MAC using that key| |

### X.509

Certificates:
- X.509 is a standard defining the format of public key certificates
- Certificate levels:
  - Root certificate:
    - Self-signed
    - Represent a CA
  - Intermediate certificate:
    - Signed by CA
    - Represent a CA
  - End-entity certificate:
    - Signed by CA
    - Represent the end of teh certificate chain
- Certificate versions:
  - v1 - in use
  - v2 - very rare
  - v3 - most popular, introduced certificate extensions
- Trust anchor:
  - Authoritative entity for which trust is assumed and not derived
  - Typical example is a root certificate

Certificate Revocation Lists:
- Allow the issuer to withdraw its signature from a certificate
- Through the use of InvalidityDate extension, it is possible to revoke a certificate with past date
- Obtaining CRLs:
  - Issuers provide URL from which a CRL can be downloaded
  - Online Certificate Status Protocol:
    - Details can be included in the CRL Distribution Point certificate extension
    - Client gets server certificate, then checks revocation by calling OCSP responder
    - Solves one problem, but creates another - clients need to broadcast their traffic habits to CAs
    - OCSP stapling resolves this problem, by making the server obtain the OCSP response and send it to the client
      together with the certificate

Certificate path validation:
- Questions:
  - Is the certificate signed by a CA we trust?
  - Are we sure the CA didn't withdraw their signature?
  - Has the certificate been used in line with its intended usage?
- All certificates in a path, except trust anchor which is being accepted at a face value, need to satisfy these criteria

### OpenPGP

- PGP stores keys and certificates in key rings
- Master key in a key ring is always a signing key
- Simplest case is a master key with an encryption subkey
- Message types:
  - PGP PUBLIC KEY BLOCK
  - PGP PRIVATE KEY BLOCK
  - PGP SIGNATURE
  - PGP MESSAGE
  - PGP SIGNED MESSAGE
- Public key encryption using PGP:
  - Generate symmetric key
  - Use this key to encrypt the data
  - Use the recipient’s public key to encrypt the symmetric key
  - Optional integrity protection relies on SHA-1

### Attacks

- Most common attacks against encryption schemes (from the least powerful):
  - Ciphertext-only attack:
    - Only ciphertext is known
  - Known-plaintext attack:
    - Plaintext and ciphertext are known
    - Plaintext may be known only partially
  - Chosen-plaintext attack
    - Attacker can chose any number of plaintexts and get corresponding ciphertexts
    - Offline attack: plaintexts are prepared before getting first ciphertext
    - Online attach: plaintextx are chosen based on ciphertexts already received
  - Chosen-ciphertext attack:
    - Attacker gets plaintext for any chosen ciphertext and ciphertext for any chosen plaintext
- Other attacks against block ciphers:
  - Related-key attack - different keys have some relationship that the attacker knows about (e.g. increment by one)
  - Chosen-key attack - attacker specifies some part of the key and then performs a related-key attack on
    the rest of the key
- Attacks against hash functions:
  - Preimage attack:
    - Tries to find a message with a specific hash
    - Strong n-bit hash function should be preimage attack-resistant to the level of 2<sup>n</sup>, i.e. there is
      no better attack than brute force attack
    - Still, strong n-bit hash function will be collision attack-resistant to the level of 2<sup>n/2</sup>
- Birthday paradox:
  - If you have 23 people in the room, the chance that 2 of them will have the same birthday exceeds 50%
- Collision attacks:
  - Attacks that depend on the fact that duplicate values (collisions) appear much faster than you would expect
  - In general, if element can take N different values, you can expect first collision 
    after approx. square root of N random elements
  - Square root of 365 is approx. 19
  - While talking about n-bit values, this translates into 2<sup>n/2</sup>, e.g. 2<sup>128/2</sup> = 2<sup>64<sup>
  - Common types:
    - Birthday attack - attacker waits for the single value to occur twice
    - Meet-in-the-middle (MITM) attack - attacker computes a total of square root of N of MAC codes or ciphertexts
      and waits for an overlap between eavesdropped communication and what they computed

### Traffic analysis

Overview:
- Encryption provides confidentiality, however attacker can still find out:
  - You are communicating
  - When you are communicating
  - How much you are communicating
  - Whom you are communicating with
- Analysis of the above is called traffic analysis
- Preventing traffic analysis is possible, but too bandwidth-expensive for anyone but military

### Testing Checklist

- Are keys of correct size?
- Are keys of correct type (e.g. RSA vs EC)?
- Are HKDFs supplied with correct input?
- Are PRNGs suitable for use in cryptography?
- Are DH shared secrets used as symmetric keys without KFD?
- Are calculated digests of correct type (digest vs hexdigest)?
