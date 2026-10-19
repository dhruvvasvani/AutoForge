def handle_login(user_id):
    return get_user_profile(user_id)

def get_user_profile(user_id):
    return {"id": user_id}
