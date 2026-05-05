import sqlite3

conn = sqlite3.connect('data/kms-iam.db')
cursor = conn.cursor()

# List all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print("=== Tables in database ===")
for table in tables:
    print(f"  - {table[0]}")

# Check users table structure
print("\n=== Users table schema ===")
cursor.execute("PRAGMA table_info(users)")
for col in cursor.fetchall():
    print(f"  {col[1]} ({col[2]})")

conn.close()
