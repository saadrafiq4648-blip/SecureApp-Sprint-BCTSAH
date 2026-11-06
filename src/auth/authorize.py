from flask import abort

def authorize(user, file_obj, action="read"):
    if file_obj.owner_id != user.id and not file_obj.shared_with(user, action):
        abort(404)
