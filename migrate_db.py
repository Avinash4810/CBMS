import sqlite3
import os

def migrate_database():
    DATABASE = "files.db"
    
    # Backup existing database
    if os.path.exists(DATABASE):
        backup_name = "files_backup.db"
        with open(DATABASE, 'rb') as source, open(backup_name, 'wb') as backup:
            backup.write(source.read())
        print(f"Created backup at: {backup_name}")
    
    # Connect to database and recreate schema
    with sqlite3.connect(DATABASE) as conn:
        # Drop existing table
        conn.execute("DROP TABLE IF EXISTS files")
        
        # Create new table with updated schema
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_file_id INTEGER,
                user_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                storage_path TEXT NOT NULL,
                mimetype TEXT NOT NULL,
                filesize INTEGER NOT NULL,
                upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, user_file_id)
            )
        """)
        conn.commit()
        print("Database schema updated successfully")

if __name__ == "__main__":
    migrate_database()