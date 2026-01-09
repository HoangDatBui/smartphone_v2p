"""
Database Migration Script for V2P Authentication System
Run this ONCE before starting the Auth Cloud server

Usage:
    python3 migrate.py
"""

import os
import hashlib
import psycopg2
from dotenv import load_dotenv

load_dotenv()

# Database connection settings
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'database': os.environ.get('DB_NAME', 'v2p_auth'),
    'user': os.environ.get('DB_USER', 'v2p_user'),
    'password': os.environ.get('DB_PASSWORD', 'V2P_Secure_2024!'),
    'port': os.environ.get('DB_PORT', 5432)
}

def create_tables(cur):
    """Create the vru_users table"""
    print("Creating tables...")
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vru_users (
            id SERIAL PRIMARY KEY,
            user_id VARCHAR(50) UNIQUE NOT NULL,
            api_key_hash VARCHAR(255) NOT NULL,
            username VARCHAR(100),
            password VARCHAR(255),
            active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_users_user_id ON vru_users(user_id);
    """)
    
    print("✅ Tables created")

def insert_test_user(cur):
    """Insert test user if not exists"""
    print("Inserting test user...")
    
    # Test user credentials
    test_user_id = "VRU_USER_001"
    test_api_key = "sk_live_51234567890abcdef"
    
    # Hash the API key
    api_key_hash = hashlib.sha256(test_api_key.encode()).hexdigest()
    
    # Check if user already exists
    cur.execute("SELECT user_id FROM vru_users WHERE user_id = %s", (test_user_id,))
    if cur.fetchone():
        print(f"⚠️  Test user '{test_user_id}' already exists, skipping...")
        return
    
    # Insert test user
    cur.execute("""
        INSERT INTO vru_users (user_id, api_key_hash, username, password, active)
        VALUES (%s, %s, NULL, NULL, TRUE)
    """, (test_user_id, api_key_hash))
    
    print(f"✅ Test user '{test_user_id}' created")
    print(f"   API Key: {test_api_key}")

def migrate():
    """Run all migrations"""
    print("=" * 60)
    print("V2P DATABASE MIGRATION")
    print("=" * 60)
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        cur = conn.cursor()
        
        print(f"\n✅ Connected to database: {DB_CONFIG['database']}")
        
        # Run migrations
        create_tables(cur)
        insert_test_user(cur)
        
        cur.close()
        conn.close()
        
        print("\n" + "=" * 60)
        print("✅ MIGRATION COMPLETE")
        print("=" * 60)
        print("\nYou can now start the Auth Cloud server:")
        print("  cd auth && python3 auth_cloud_server_secure.py")
        
    except psycopg2.OperationalError as e:
        print(f"\n❌ Database connection failed: {e}")
        print("\nMake sure PostgreSQL is running and the database exists:")
        print("  sudo -u postgres psql -c \"CREATE DATABASE v2p_auth;\"")
        print("  sudo -u postgres psql -c \"CREATE USER v2p_user WITH ENCRYPTED PASSWORD 'V2P_Secure_2024!';\"")
        print("  sudo -u postgres psql -c \"GRANT ALL PRIVILEGES ON DATABASE v2p_auth TO v2p_user;\"")
        return False
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    migrate()
