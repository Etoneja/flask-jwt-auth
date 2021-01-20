# project/server/auth/views.py

from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from project.server import bcrypt, db
from project.server.models import User


auth_blueprint = Blueprint("auth", __name__)


class RegisterAPI(MethodView):
    """
    User Registration Resource
    """

    def post(self):
        post_data = request.get_json()
        user = User.query.filter_by(email=post_data.get("email")).first()
        if not user:
            try:
                user = User(
                    email=post_data.get("email"),
                    password=post_data.get("password")
                )
                db.session.add(user)
                db.session.commit()
                auth_token = user.encode_auth_token(user.id)
                response_object = {
                    "status": "success",
                    "message": "Successfully registered.",
                    "auth_token": auth_token
                }
                return make_response(jsonify(response_object)), 201
            except Exception as e:
                response_object = {
                    "success": "fail",
                    "message": "Some error occurred. Please try again."
                }
                return make_response(jsonify(response_object)), 401
        else:
            response_object = {
                "status": "fail",
                "message": "User already exists. Please log in."
            }
            return make_response(jsonify(response_object)), 202


# define the API resources
registration_view = RegisterAPI.as_view("register_api")

auth_blueprint.add_url_rule(
    "/auth/register",
    view_func=registration_view,
    methods=["POST"]
)
