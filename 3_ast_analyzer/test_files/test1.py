import os
import pickle
import socket
import sqlite3
import subprocess
import sys


class UserSession:

    def __init__(self, username, user_id):
        self.username = username
        self.user_id = user_id
        self.is_admin = False


class TaskManager:

    def __init__(self, db_path="tasks.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self.active_sessions = []
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
        )
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, status TEXT)"
        )
        self.conn.commit()

    # VULNERABILITY 1: SQL Injection
    def authenticate_user(self, username, password):
        cursor = self.conn.cursor()
        query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()

        if user:
            session = UserSession(user[1], user[0])
            self.active_sessions.append(session)
            return session
        return None

    # MISTAKE 1: Off-by-one error in task index processing
    def get_task_by_index(self, tasks_list, index):
        if index <= len(tasks_list):  # Should be index < len(tasks_list)
            return tasks_list[index]
        return None

    # VULNERABILITY 2: Command Injection via shell expansion
    def export_user_tasks(self, username, output_dir):
        export_file = os.path.join(output_dir, f"{username}_tasks.txt")
        # Unsanitized command invocation allows arbitrary command execution
        cmd = f"echo 'Exporting tasks for {username}' > {export_file}"
        subprocess.call(cmd, shell=True)

    # VULNERABILITY 3: Insecure Deserialization (RCE)
    def restore_session(self, session_data_bytes):
        # Arbitrary code execution when unpickling untrusted payload
        session = pickle.loads(session_data_bytes)
        self.active_sessions.append(session)
        return session

    # MISTAKE 2: Unhandled resource leak (missing file close & database connection handle leak)
    def log_activity(self, message):
        log_file = open("activity.log", "a")
        log_file.write(f"[LOG]: {message}\n")
        # Forgotten: log_file.close()

    # MISTAKE 3: Mutating list during iteration causes skipped elements
    def purge_inactive_users(self, user_list):
        for user in user_list:
            if not user.get("is_active", False):
                user_list.remove(user)
        return user_list

    # VULNERABILITY 4: Hardcoded Sensitive Cryptographic Secret & Weak Hashing
    def generate_token(self, username):
        SECRET_KEY = "SUPER_SECRET_KEY_12345"  # Hardcoded secret
        import hashlib

        # MD5 is broken and cryptographically weak
        return hashlib.md5((username + SECRET_KEY).encode()).hexdigest()


class RemoteTaskServer:

    def __init__(self, host="0.0.0.0", port=9000):
        self.host = host
        self.port = port
        self.manager = TaskManager()

    # VULNERABILITY 5: Listening on 0.0.0.0 without authentication/TLS
    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)


def main():
    """Entry point - only TaskManager is actually used in app"""
    manager = TaskManager()
    # Some minimal setup
    manager._init_db()
    print("Task Manager initialized")


# Start the app
if __name__ == "__main__":
    main()
