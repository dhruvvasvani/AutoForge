import os
import pickle

# Entry point function (Executes on startup)
def main():
    user_input = "SELECT * FROM users WHERE username = 'admin'"
    vulnerable_sql_query(user_input)

# REACHABLE VULNERABILITY (Real Threat)
def vulnerable_sql_query(query):
    print(f"Executing SQL: {query}")
    # SAST Scanner marks this as SQL Injection

# UNREACHABLE VULNERABILITY (Dead Code / Noise)
def dead_code_handler():
    # SAST Scanner marks this as Insecure Deserialization
    untrusted_data = b"cos\nsystem\n(S'echo Hacked'\ntR."
    pickle.loads(untrusted_data)

if __name__ == "__main__":
    main()