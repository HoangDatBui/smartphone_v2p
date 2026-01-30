"""
RSU (Roadside Unit) Server - Step 3 Implementation
Receives precise position from VRU using temporary certificate
"""

from flask import Flask, request, jsonify
from datetime import datetime
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from shared.crypto_utils import CryptoManager
import json

app = Flask(__name__)

# Initialize crypto manager with RSU's keys
crypto = CryptoManager(
    private_key_path='../keys/rsu_private_key.pem',
    public_key_path='../keys/rsu_public_key.pem'
)

# Store VRU public keys for session validation
VRU_SESSIONS = {}

# Store active VRU positions (for intersection signal control - Step 4)
ACTIVE_VRU_POSITIONS = {}

# RSU Information
RSU_INFO = {
    "rsu_id": "RSU_BNE_001",
    "name": "Queen St & Adelaide St",
    "location": {"lat": -27.4698, "lon": 153.0251}
}


@app.route('/api/v1/public_key', methods=['GET'])
def get_public_key():
    """Step 3a: VRU Client requests RSU's public key"""
    return jsonify({
        "success": True,
        "public_key": crypto.get_public_key_string(),
        "rsu_id": RSU_INFO["rsu_id"],
        "rsu_name": RSU_INFO["name"],
        "key_type": "RSA-2048",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200


@app.route('/api/v1/register_position', methods=['POST'])
def register_position():
    """
    Step 3: Receive VRU precise position with temporary certificate
    
    This is a ONE-WAY communication (VRU -> RSU only, no response back)
    
    The VRU sends:
    - encrypted_data: Contains precise position (encrypted with RSU's public key)
    - temporary_cert: The temporary access certificate from Auth Cloud
    - vru_public_key: VRU's public key for signature verification
    - signature: Digital signature proving authenticity
    """
    try:
        data = request.get_json()
        
        encrypted_data = data.get('encrypted_data')
        temporary_cert = data.get('temporary_cert')
        cert_expires_at = data.get('cert_expires_at')
        vru_public_key_pem = data.get('vru_public_key')
        signature = data.get('signature')
        timestamp = data.get('timestamp')
        
        # Validate required fields
        if not all([encrypted_data, temporary_cert, vru_public_key_pem, signature, timestamp]):
            missing = []
            if not encrypted_data: missing.append("encrypted_data")
            if not temporary_cert: missing.append("temporary_cert")
            if not vru_public_key_pem: missing.append("vru_public_key")
            if not signature: missing.append("signature")
            if not timestamp: missing.append("timestamp")
            
            print(f"[RSU] ❌ Missing required fields: {', '.join(missing)}")
            return '', 400
        
        # Load VRU's public key
        try:
            vru_crypto = CryptoManager()
            vru_crypto.load_public_key_from_string(vru_public_key_pem)
        except Exception as e:
            print(f"[RSU] ❌ Failed to load VRU public key: {e}")
            return '', 400
        
        # Verify signature (proves the request came from the VRU)
        message_to_verify = f"{encrypted_data}{temporary_cert}{timestamp}"
        
        try:
            is_valid = vru_crypto.verify_signature(message_to_verify, signature)
            if not is_valid:
                print(f"[RSU] ❌ Signature verification failed")
                return '', 401
        except Exception as e:
            print(f"[RSU] ❌ Signature verification error: {e}")
            return '', 401
        
        # Validate temporary certificate
        # Check certificate format
        if len(temporary_cert) < 20:
            print(f"[RSU] ❌ Invalid temporary certificate")
            return '', 401
        
        # Check expiration (certificate valid for 20 minutes)
        if cert_expires_at:
            try:
                expiry_time = datetime.fromisoformat(cert_expires_at.replace('Z', '+00:00'))
                current_time = datetime.utcnow().replace(tzinfo=expiry_time.tzinfo)
                
                if current_time > expiry_time:
                    print(f"[RSU] ❌ Temporary certificate expired")
                    return '', 401
            except Exception as e:
                # Continue validation if expiration parsing fails (backward compatibility)
                pass
        
        # Decrypt the position data
        try:
            decrypted_data = crypto.decrypt(encrypted_data)
            position_data = json.loads(decrypted_data)
        except Exception as e:
            print(f"[RSU] ❌ Decryption failed: {e}")
            return '', 400
        
        # Extract precise position
        precise_position = position_data.get('precise_position', {})
        user_id = position_data.get('user_id')
        
        # Store the VRU position for intersection signal control (Step 4)
        ACTIVE_VRU_POSITIONS[user_id] = {
            "position": precise_position,
            "timestamp": timestamp,
            "temporary_cert": temporary_cert,
            "last_update": datetime.utcnow().isoformat() + "Z"
        }
        
        print(f"[RSU] ✅ Position registered: {user_id} ({precise_position.get('lat')}, {precise_position.get('lon')})")
        
        # One-way communication - just acknowledge receipt with HTTP 200
        return '', 200
        
    except Exception as e:
        print(f"[RSU] ❌ Error: {e}")
        return '', 500


@app.route('/api/v1/active_vrus', methods=['GET'])
def get_active_vrus():
    """Get list of active VRUs near this RSU (for intersection signal control)"""
    return jsonify({
        "success": True,
        "rsu_id": RSU_INFO["rsu_id"],
        "active_vrus": len(ACTIVE_VRU_POSITIONS),
        "vrus": list(ACTIVE_VRU_POSITIONS.keys()),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200


@app.route('/api/v1/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "service": f"RSU Server - {RSU_INFO['rsu_id']}",
        "name": RSU_INFO["name"],
        "location": RSU_INFO["location"],
        "encryption": "RSA-2048",
        "active_vrus": len(ACTIVE_VRU_POSITIONS),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200


if __name__ == '__main__':
    print("=" * 60)
    print(f"RSU SERVER - {RSU_INFO['rsu_id']}")
    print(f"Location: {RSU_INFO['name']}")
    print("Using RSA-2048 encryption")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)

