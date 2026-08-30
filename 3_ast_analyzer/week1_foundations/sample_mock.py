def main():
    result = get_user_profile(1)
    print(result)


def get_user_profile(user_id):
    return handle_login(user_id)


def handle_login(user_id):
    return {"id": user_id}


def dead_function():
    # never called anywhere - noise example
    return "unreachable"
