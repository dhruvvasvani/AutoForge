from utils.auth import handle_login
import utils.db as db

def main():
    handle_login("u1")
    db.save_record("x")

def dead_entry():
    unused_helper()

def unused_helper():
    return 1
