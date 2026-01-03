#!/usr/bin/env python3
# server/app.py
from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User

class Signup(Resource):
    def post(self):
        json = request.get_json()
        try:
            # 1. Create the user instance
            user = User(
                username=json.get('username')
            )
            # 2. Use the setter in models.py to hash the password
            user.password_hash = json.get('password')
            
            db.session.add(user)
            db.session.commit()

            # 3. Log them in automatically by setting the session
            session['user_id'] = user.id
            
            return user.to_dict(), 201
        except (IntegrityError, KeyError):
            return {'error': '422 Unprocessable Entity'}, 422

class CheckSession(Resource):
    def get(self):
        # Check if the user_id exists in the session cookie
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            return user.to_dict(), 200
        
        # If not authenticated, return 204 No Content
        return {}, 204

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        user = User.query.filter(User.username == username).first()

        # Check if user exists and password is correct (using the authenticate method)
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        
        return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        # Clear the user_id from the session
        session['user_id'] = None
        return {}, 204

# Register the resources with the API
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
