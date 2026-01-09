"""
Database module for V2P Authentication System
Handles PostgreSQL connections for user authentication
"""

import os
import hashlib
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load environment variables from .env file if exists
load_dotenv()

class Database:
    """PostgreSQL database handler for user authentication"""
    
    def __init__(self):
        self.conn = None
        self.connect()
    
    def connect(self):
        """Establish database connection"""
        try:
            self.conn = psycopg2.connect(
                host=os.environ.get('DB_HOST', 'localhost'),
                database=os.environ.get('DB_NAME', 'v2p_auth'),
                user=os.environ.get('DB_USER', 'v2p_user'),
                password=os.environ.get('DB_PASSWORD', 'V2P_Secure_2024!'),
                port=os.environ.get('DB_PORT', 5432)
            )
            self.conn.autocommit = True
            print("✅ Database connection established")
        except Exception as e:
            print(f"❌ Database connection failed: {e}")
            raise
    
    def get_user(self, user_id):
        """Get user by user_id"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT user_id, api_key_hash, username, password, active FROM vru_users WHERE user_id = %s",
                    (user_id,)
                )
                return cur.fetchone()
        except Exception as e:
            print(f"❌ Error fetching user: {e}")
            return None
    
    def verify_api_key(self, user_id, api_key):
        """
        Verify API key against stored hash
        
        Args:
            user_id: The user's ID
            api_key: The plaintext API key to verify
            
        Returns:
            bool: True if valid, False otherwise
        """
        user = self.get_user(user_id)
        
        if not user:
            print(f"❌ User not found: {user_id}")
            return False
        
        if not user['active']:
            print(f"❌ User inactive: {user_id}")
            return False
        
        # Hash the provided API key and compare
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        if api_key_hash == user['api_key_hash']:
            print(f"✅ API key verified for user: {user_id}")
            return True
        else:
            print(f"❌ API key mismatch for user: {user_id}")
            return False
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("Database connection closed")


# Singleton instance
_db_instance = None

def get_db():
    """Get database singleton instance"""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
