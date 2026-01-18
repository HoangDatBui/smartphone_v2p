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
Step 3: Precise Positioning & RSU Connection ✅
Step 4: Signal Control Integration (Coming Soon)
```

---

## Security & Cryptographic Design

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

## Step 1: Secure Authentication & Rough Positioning

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

**Authentication Cloud Processing:**

1. **Receives VRU's public key** and loads it into memory
2. **Verifies the digital signature** using VRU's public key (see below)
3. **Validates timestamp** - request must be within 20 minutes (prevents replay attacks)
4. **Decrypts the API key** using Auth Cloud's private key
5. **Validates credentials** against user database
6. **Identifies nearby RSUs** based on postcode

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

**Timestamp Expiration:**
- Authentication requests expire after **20 minutes** from the timestamp
- Prevents replay attacks (old intercepted requests cannot be reused)
- Clock skew tolerance: up to 5 minutes for future timestamps

---

## Step 2: Certificate Generation & RSU Discovery

### What Happens (Simple Explanation)

After successful authentication:

1. **The cloud generates** a temporary access certificate (session token) **valid for 20 minutes**
2. **The cloud finds** all nearby roadside units in your area
3. **The cloud encrypts** this information specifically for your device
4. **The cloud signs** the response so you know it's authentic
5. **Your smartphone receives** the list of nearby infrastructure and certificate expiration time

### Technical Details

**Authentication Cloud → VRU Smartphone:**

```python
# The cloud sends (encrypted):
{
    "success": True,
    "user_id": "VRU_USER_001",
    "temporary_cert": "<temporary_access_certificate>",  # Valid for 20 minutes
    "cert_expires_at": "2024-01-15T10:50:01Z",          # Expiration timestamp
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

**VRU Smartphone Processing:**

1. Decrypts response using VRU's private key
2. Verifies signature using Auth Cloud's public key
3. Stores temporary certificate and expiration time for Step 3
4. Caches nearby RSU list for RSU connection

**Certificate Expiration:**
- Temporary certificates are valid for **20 minutes** from issuance
- After expiration, VRU must re-authenticate with Auth Cloud to get a new certificate

---

## Step 3: Precise Positioning & RSU Connection

### What Happens (Simple Explanation)

After receiving the temporary certificate and RSU list:

1. **Your smartphone** obtains your precise GPS location
2. **You connect** to the nearest Roadside Unit (RSU)
3. **You send** your precise position encrypted with the RSU's public key
4. **The RSU validates** your temporary certificate
5. **The RSU registers** your position for intersection signal control

### Technical Details

**VRU Smartphone → RSU:**

```python
# The smartphone sends:
{
    "encrypted_data": "<encrypted>",           # Position encrypted with RSU's public key
    "temporary_cert": "<certificate>",         # From Step 2 authentication
    "cert_expires_at": "2024-01-15T10:50:01Z", # Certificate expiration timestamp
    "vru_public_key": "<public_key>",         # VRU's public key for signature verification
    "signature": "<digital_signature>",        # Cryptographic proof of authenticity
    "timestamp": "2024-01-15T10:30:02Z"       # Request timestamp
}

# The encrypted_data contains:
{
    "user_id": "VRU_USER_001",
    "precise_position": {
        "lat": -27.4695,                      # GPS latitude
        "lon": 153.0253,                      # GPS longitude
        "speed": 1.2                          # Speed in m/s
    }
}
```

**RSU Processing:**

1. **Loads VRU's public key** from the request
2. **Verifies the digital signature** using VRU's public key
3. **Validates temporary certificate** (see below)
4. **Decrypts position data** using RSU's private key
5. **Registers VRU position** for intersection signal control
6. **Returns HTTP 200** (acknowledgment only, no data)

**How RSU Validates Temporary Certificate:**

The RSU validates the certificate through multiple checks:

```
┌─────────────────────────────────────────────────────────────────┐
│              TEMPORARY CERTIFICATE VALIDATION                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   1. Format Check                                               │
│      └─ Certificate length ≥ 20 characters?                    │
│         ❌ Too short → Invalid format → Reject                  │
│                                                                 │
│   2. Expiration Check                                           │
│      └─ Current time < cert_expires_at?                        │
│         ❌ Expired → Certificate invalid → Reject               │
│         ✅ Valid → Continue                                     │
│                                                                 │
│   3. Signature Verification                                     │
│      └─ Request signed with VRU's private key?                 │
│         ❌ Invalid signature → Reject                           │
│         ✅ Valid signature → Accept                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Important Notes:**

- **Current Implementation**: RSU trusts certificates that pass format and expiration checks. The certificate itself is a random token generated by Auth Cloud.
- **Production Recommendation**: RSU should verify certificates with Auth Cloud or use a distributed cache (Redis) to check if the certificate was actually issued and hasn't been revoked.
- **Why This Works**: The certificate is encrypted and signed by Auth Cloud in Step 2, so only authenticated users receive valid certificates. The 20-minute expiration limits the window for potential misuse.

---

## Project Structure

```
smartphone_v2p/
├── auth/                              # Auth Cloud instance
│   └── auth_cloud_server_secure.py    
├── ru/                                # VRU Smartphone instance
│   └── vru_client_secure.py           
├── rsu/                               # RSU instance
│   └── rsu_server.py                  
├── shared/
│   ├── crypto_utils.py                # Cryptographic utilities (RSA/AES)
│   ├── database.py                    # PostgreSQL database module
│   ├── migrate.py                     # Database migration script
│   ├── generate_keys.py               # Key pair generation script
│   └── requirements.txt               # Python dependencies
└── keys/                              # RSA key pairs (generated per instance)
```

### Components

| Component | File | Description |
|-----------|------|-------------|
| **Auth Cloud Server** | `auth/auth_cloud_server_secure.py` | Flask REST API handling authentication |
| **RSU Server** | `rsu/rsu_server.py` | Roadside Unit server receiving VRU positions |
| **VRU Client** | `ru/vru_client_secure.py` | Smartphone client implementation |
| **CryptoManager** | `shared/crypto_utils.py` | All encryption/signing operations |
| **Database** | `shared/database.py` | PostgreSQL connection & user verification |
| **Migration** | `shared/migrate.py` | Creates tables & inserts test data |

---

## Database (PostgreSQL)

User credentials are stored in PostgreSQL. When Auth Cloud receives an authentication request, it decrypts the API key and compares its SHA-256 hash against the stored hash in the database.

**Table: `vru_users`**

| Column | Type |
|--------|------|
| user_id | VARCHAR(50) |
| api_key_hash | VARCHAR(255) |
| username | VARCHAR(100) |
| password | VARCHAR(255) |
| active | BOOLEAN |

**Setup (run once on Auth Cloud instance):**

```bash
# Install PostgreSQL
sudo apt install postgresql postgresql-contrib -y

# Create database & user
sudo -u postgres psql -c "CREATE DATABASE v2p_auth;"
sudo -u postgres psql -c "CREATE USER v2p_user WITH ENCRYPTED PASSWORD 'V2P_Secure_2024!';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE v2p_auth TO v2p_user;"

# Run migration (creates tables + test user)
cd shared
python3 migrate.py
```

---

## Getting Started

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
   - `keys/rsu_client_private_key.pem` & `keys/rsu_client_public_key.pem`

4. **Configure the system:**
   - Update `AUTH_CLOUD_URL` in `ru/vru_client_secure.py` with your server address
   - Ensure key paths are correct relative to your execution directory

### Running the System

#### 0. Run Database Migration (first time only)

```bash
cd shared
python3 migrate.py
```

#### 1. Start Authentication Cloud Server

```bash
cd auth
python3 auth_cloud_server_secure.py
```

Server starts on `http://0.0.0.0:8443`

#### 2. Start RSU Server

```bash
cd rsu
python rsu_server.py
```

Server starts on `http://0.0.0.0:5000`

#### 3. Run VRU Client

```bash
cd ru
python vru_client_secure.py
```

The client will:
1. Request Auth Cloud's public key (Step 0)
2. Authenticate with encrypted credentials (Step 1)
3. Receive and decrypt nearby RSU list with temporary certificate (Step 2)
4. Connect to RSU with precise position using temporary certificate (Step 3)
5. Display connection and registration status

### Example Output

```
============================================================
SECURE VRU SMARTPHONE - V2P SAFETY SYSTEM
============================================================

[STEP 1] 🔒 API key encrypted & ✍️ request signed
[STEP 1] Sending authentication: VRU_USER_001 @ Brisbane CBD, QLD 4000

[STEP 2] 🔓 Response decrypted & ✅ signature verified
✅ Authentication successful! Temporary certificate received.
   Nearby RSUs: RSU_BNE_001 (Queen St & Adelaide St), RSU_BNE_002 (George St & Elizabeth St)

[STEP 3] 📡 Connecting to RSU_BNE_001...
[STEP 3] 🔒 Position encrypted & ✍️ request signed
📍 Position: (-27.4695, 153.0253) | Speed: 1.2 m/s
✅ Position sent to RSU (one-way communication)

============================================================
✅ ALL STEPS COMPLETE - VRU registered with intersection
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
    "temporary_cert": "<certificate>",
    "timestamp": "2024-01-15T10:30:01Z",
    "rough_position": {...},
    "nearby_rsus": [...],
    "rsu_count": 2
}
```

### RSU Server Endpoints

#### `GET /api/v1/public_key`
Returns RSU's public key for encryption.

**Response:**
```json
{
    "success": true,
    "public_key": "-----BEGIN PUBLIC KEY-----\n...",
    "rsu_id": "RSU_BNE_001",
    "rsu_name": "Queen St & Adelaide St",
    "key_type": "RSA-2048",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

#### `POST /api/v1/register_position`
Handles Step 3 - VRU precise position registration (ONE-WAY communication).

**Request:**
```json
{
    "encrypted_data": "<base64_encrypted>",
    "temporary_cert": "<certificate_from_auth_cloud>",
    "vru_public_key": "<pem_string>",
    "signature": "<base64_signature>",
    "timestamp": "2024-01-15T10:30:02Z"
}
```

**Encrypted Data (before encryption):**
```json
{
    "user_id": "VRU_USER_001",
    "precise_position": {
        "lat": -27.4695,
        "lon": 153.0253,
        "speed": 1.2
    }
}
```

**Response:**
- `HTTP 200` - Position registered successfully (empty body)
- `HTTP 400` - Bad request (missing fields or decryption failed)
- `HTTP 401` - Unauthorized (invalid signature or certificate)

#### `GET /api/v1/active_vrus`
Returns list of active VRUs near this RSU (for intersection signal control).

**Response:**
```json
{
    "success": true,
    "rsu_id": "RSU_BNE_001",
    "active_vrus": 3,
    "vrus": ["VRU_USER_001", "VRU_USER_002", "VRU_USER_003"],
    "timestamp": "2024-01-15T10:30:05Z"
}
```

#### `GET /api/v1/health`
RSU health check.

**Response:**
```json
{
    "status": "healthy",
    "service": "RSU Server - RSU_BNE_001",
    "name": "Queen St & Adelaide St",
    "location": {"lat": -27.4698, "lon": 153.0251},
    "encryption": "RSA-2048",
    "active_vrus": 3,
    "timestamp": "2024-01-15T10:30:00Z"
}
```