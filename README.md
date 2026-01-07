# Smartphone V2P (Vehicle-to-Pedestrian) Secure Communication System

## Project Overview

This project implements a **secure communication protocol** that enables Vulnerable Road Users (VRUs) - pedestrians, cyclists, and other non-vehicle road users - to safely connect with smart city infrastructure through their smartphones. The system establishes a trusted, encrypted channel between a pedestrian's device and roadside units (RSUs) that can coordinate with traffic signals to enhance pedestrian safety.

### The Vision

Imagine walking up to a busy intersection. Your smartphone automatically detects nearby smart infrastructure, securely authenticates your identity, and establishes a protected communication channel. This allows the traffic system to know you're there, alerting vehicles to your presence, all while maintaining your privacy and security.

---

## Architecture Overview

The system follows a **4-step secure communication protocol** as illustrated in the project documentation:

```
Step 1: Initial Authentication & Rough Positioning
Step 2: Certificate Generation & RSU Discovery  
Step 3: Precise Positioning & RSU Connection (Coming Soon)
Step 4: Signal Control Integration (Coming Soon)
```

---

## 🔐 Security & Cryptographic Design

### Why Security Matters

In a world where personal devices communicate with critical infrastructure, security isn't optional but essential. Our system ensures:

| Security Property | What It Means | How We Achieve It |
|------------------|---------------|-------------------|
| **Privacy** | Your location and identity stay private | End-to-end encryption (RSA + AES) |
| **Authentication** | Only authorized users can access | Encrypted API keys + validation |
| **Integrity** | Messages can't be tampered with | Digital signatures (SHA-256 hash) |
| **Non-Repudiation** | Sender can't deny sending | Cryptographic signatures |


### Why Hybrid Encryption?

We use **hybrid encryption** (RSA + AES) because RSA alone has limitations:

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE PROBLEM WITH RSA ALONE                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   RSA-2048 can only encrypt ~245 bytes directly                 │
│                                                                 │
│   Our RSU list response = 500+ bytes  ❌ Too big!               │
│                                                                 │
│   RSA is also slow for large data                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    HYBRID ENCRYPTION SOLUTION                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. Generate random AES-256 key (32 bytes)                     │
│   2. Encrypt DATA with AES key (fast, unlimited size)           │
│   3. Encrypt AES KEY with RSA (secure key exchange)             │
│   4. Send: [RSA-encrypted AES key] + [AES-encrypted data]       │
│                                                                 │
│   Result: Security of RSA + Speed of AES ✅                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation: CryptoManager

All cryptographic operations are handled by `shared/crypto_utils.py`:

```python
# Encryption: Uses recipient's PUBLIC key
encrypted = crypto.encrypt(message, recipient_public_key)
# → Generates AES key, encrypts message, RSA-encrypts AES key

# Decryption: Uses own PRIVATE key  
decrypted = crypto.decrypt(encrypted_message)
# → RSA-decrypts AES key, then AES-decrypts message

# Signing: Uses own PRIVATE key
signature = crypto.sign(message)
# → Hashes message (SHA-256), encrypts hash with private key

# Verification: Uses sender's PUBLIC key
is_valid = crypto.verify_signature(message, signature, sender_public_key)
# → Decrypts signature to get hash, compares with fresh hash of message
```

---

## 📋 Step 1: Secure Authentication & Rough Positioning

### What Happens (Simple Explanation)

When a pedestrian approaches an intersection:

1. **Your smartphone** detects you're near smart infrastructure
2. **You send** your identity and approximate location (like a postcode) to the authentication cloud
3. **Your credentials** are encrypted so only the cloud can read them
4. **The cloud verifies** you're a legitimate user
5. **The cloud responds** with nearby infrastructure locations

### Technical Details

**VRU Smartphone → Authentication Cloud:**

```python
# The smartphone sends:
{
    "user_id": "VRU_USER_001",                    # Your unique identifier
    "encrypted_api_key": "<encrypted>",           # Your credentials (RSA encrypted)
    "vru_public_key": "<public_key>",            # Your public key for verification
    "rough_position": {                          # Approximate location
        "postcode": "4000",
        "suburb": "Brisbane CBD",
        "state": "QLD"
    },
    "signature": "<digital_signature>",          # Cryptographic proof of authenticity
    "timestamp": "2024-01-15T10:30:00Z"         # Request timestamp
}
```

**Security Features:**

- ✅ **End-to-End Encryption**: API key encrypted with Auth Cloud's public key (RSA-2048)
- ✅ **Digital Signatures**: Request signed with VRU's private key (proves authenticity)
- ✅ **Public Key Exchange**: VRU's public key sent for future verification
- ✅ **Timestamp Validation**: Prevents replay attacks

**Authentication Cloud Processing:**

1. **Receives VRU's public key** and loads it into memory
2. **Verifies the digital signature** using VRU's public key (see below)
3. **Decrypts the API key** using Auth Cloud's private key
4. **Validates credentials** against user database
5. **Identifies nearby RSUs** based on postcode

**How Signature Verification Works:**

The signature ensures the request hasn't been tampered with and came from the real VRU. Here's the verification process:

```
┌─────────────────────────────────────────────────────────────────┐
│                  SIGNATURE VERIFICATION                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Received: user_id, encrypted_api_key, timestamp               │
│                          ↓                                      │
│                  Hash these values (SHA-256)                    │
│                          ↓                                      │
│                       Hash A                                    │
│                                                                 │
│   Received: signature                                           │
│                          ↓                                      │
│           Decrypt with VRU's PUBLIC key                         │
│                          ↓                                      │
│                       Hash B                                    │
│                                                                 │
│                  Hash A == Hash B ?                             │
│                          ↓                                      │
│               YES → Signature valid ✅                          │
│               NO  → Signature invalid ❌                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Why This Works:**
- Only the VRU possesses the private key that created the signature
- If an attacker modifies `user_id`, `encrypted_api_key`, or `timestamp`, Hash A will change
- Hash B (from the signature) remains the original hash
- Mismatch = tampering detected → request rejected

---

## 📋 Step 2: Certificate Generation & RSU Discovery

### What Happens (Simple Explanation)

After successful authentication:

1. **The cloud generates** a temporary access certificate (session token)
2. **The cloud finds** all nearby roadside units in your area
3. **The cloud encrypts** this information specifically for your device
4. **The cloud signs** the response so you know it's authentic
5. **Your smartphone receives** the list of nearby infrastructure

### Technical Details

**Authentication Cloud → VRU Smartphone:**

```python
# The cloud sends (encrypted):
{
    "success": True,
    "user_id": "VRU_USER_001",
    "session_token": "<temporary_access_certificate>",  # Valid for this session
    "timestamp": "2024-01-15T10:30:01Z",
    "rough_position": {...},
    "nearby_rsus": [                                    # List of nearby infrastructure
        {
            "rsu_id": "RSU_BNE_001",
            "name": "Queen St & Adelaide St",
            "location": {"lat": -27.4698, "lon": 153.0251},
            "ip": "203.123.45.10",
            "port": 5000
        },
        ...
    ],
    "rsu_count": 2
}
```

**Security Features:**

- ✅ **Encrypted Response**: Response encrypted with VRU's public key (only VRU can decrypt)
- ✅ **Digital Signature**: Response signed with Auth Cloud's private key (proves authenticity)
- ✅ **Session Token**: Temporary access certificate for subsequent communications
- ✅ **RSU Discovery**: Location-based infrastructure identification

**VRU Smartphone Processing:**

1. Decrypts response using VRU's private key
2. Verifies signature using Auth Cloud's public key
3. Stores session token for future use
4. Caches nearby RSU list for Step 3

---

## 🛠️ Project Structure

```
smartphone_v2p/
├── auth/
│   └── auth_cloud_server_secure.py    # Authentication Cloud server (Flask)
├── ru/
│   └── vru_client_secure.py            # VRU Smartphone client
├── shared/
│   ├── crypto_utils.py                 # Cryptographic utilities (RSA/AES)
│   ├── generate_keys.py                # Key pair generation script
│   └── requirements.txt                # Python dependencies
└── keys/                               # RSA key pairs (not in repo)
    ├── auth_cloud_private_key.pem
    ├── auth_cloud_public_key.pem
    ├── vru_client_private_key.pem
    └── vru_client_public_key.pem
```

### Components

| Component | File | Description |
|-----------|------|-------------|
| **Auth Cloud Server** | `auth/auth_cloud_server_secure.py` | Flask REST API handling authentication |
| **VRU Client** | `ru/vru_client_secure.py` | Smartphone client implementation |
| **CryptoManager** | `shared/crypto_utils.py` | All encryption/signing operations |
| **Key Generator** | `shared/generate_keys.py` | RSA-2048 key pair generation |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd smartphone_v2p
   ```

2. **Install dependencies:**
   ```bash
   cd shared
   pip install -r requirements.txt
   ```

3. **Generate cryptographic keys:**
   ```bash
   cd shared
   python generate_keys.py
   ```
   
   This creates:
   - `keys/auth_cloud_private_key.pem` & `keys/auth_cloud_public_key.pem`
   - `keys/vru_client_private_key.pem` & `keys/vru_client_public_key.pem`

4. **Configure the system:**
   - Update `AUTH_CLOUD_URL` in `ru/vru_client_secure.py` with your server address
   - Ensure key paths are correct relative to your execution directory

### Running the System

#### Start Authentication Cloud Server

```bash
cd auth
python auth_cloud_server_secure.py
```

Server starts on `http://0.0.0.0:8443`

#### Run VRU Client

```bash
cd ru
python vru_client_secure.py
```

The client will:
1. Request Auth Cloud's public key
2. Authenticate with encrypted credentials
3. Receive and decrypt nearby RSU list
4. Display connection status

### Example Output

```
============================================================
SECURE VRU SMARTPHONE - V2P SAFETY SYSTEM
Using RSA-2048 Encryption
============================================================

[STEP 0] Requesting Auth Cloud's public key...
✅ Received Auth Cloud's public key

[STEP 1] Encrypting API key with Auth Cloud's public key...
🔒 API key encrypted: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...

✍️  Signing request with VRU's private key...
✅ Request signed: X7kP9mN2vL5qR8tW3yZ6aB1cD4eF7gH0jK3mN6pQ9sT2...

📤 Sending VRU's public key: -----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...

[STEP 1] Sending secure authentication request...
User ID: VRU_USER_001
Location: Brisbane CBD, QLD 4000

[STEP 2] 🔓 Decrypting response with VRU's private key...
🔍 Verifying response signature with Auth Cloud's public key...
✅ Response signature verified

✅ Authentication successful!
Session Token: abc123xyz789def456...

[STEP 2] Received 2 nearby RSUs:
  - RSU_BNE_001: Queen St & Adelaide St
    Location: (-27.4698, 153.0251)
  - RSU_BNE_002: George St & Elizabeth St
    Location: (-27.4705, 153.0235)

============================================================
✅ SECURE TRUSTED CONNECTION ESTABLISHED
🔒 All data encrypted end-to-end
✍️  All messages cryptographically signed
============================================================
```

---

## 📚 API Reference

### Endpoints

#### `GET /api/v1/public_key`
Returns Auth Cloud's public key for encryption.

**Response:**
```json
{
    "success": true,
    "public_key": "-----BEGIN PUBLIC KEY-----\n...",
    "key_type": "RSA-2048",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### `POST /api/v1/authenticate`
Handles secure authentication (Steps 1 & 2).

**Request:**
```json
{
    "user_id": "VRU_USER_001",
    "encrypted_api_key": "<base64_encrypted>",
    "vru_public_key": "<pem_string>",
    "rough_position": {
        "postcode": "4000",
        "suburb": "Brisbane CBD",
        "state": "QLD"
    },
    "signature": "<base64_signature>",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response:**
```json
{
    "encrypted_response": "<base64_encrypted>",
    "signature": "<base64_signature>"
}
```

**Decrypted Response:**
```json
{
    "success": true,
    "user_id": "VRU_USER_001",
    "session_token": "<token>",
    "timestamp": "2024-01-15T10:30:01Z",
    "rough_position": {...},
    "nearby_rsus": [...],
    "rsu_count": 2
}
```