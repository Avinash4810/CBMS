from flask_login import UserMixin
import sqlite3

class User(UserMixin):
    def __init__(self, id_, name, email, profile_pic):
        self.id = id_
        self.name = name
        self.email = email
        self.profile_pic = profile_pic

def init_user_db():
    """Initialize the users database"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            profile_pic TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_user(user_id):
    """Retrieve a user from the database"""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    user = c.execute(
        'SELECT id, name, email, profile_pic FROM users WHERE id = ?', 
        (user_id,)
    ).fetchone()
    conn.close()
    
    if not user:
        return None
        
    return User(
        id_=user[0],
        name=user[1],
        email=user[2],
        profile_pic=user[3]
    )