from flask import Flask, jsonify, request, session
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
api = Api(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        password_confirmation = data.get('password_confirmation')

        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Username already exists'}), 400

        if password != password_confirmation:
            return jsonify({'message': 'Passwords do not match'}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id

        return jsonify({'id': new_user.id, 'username': new_user.username}), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            return jsonify({'id': user.id, 'username': user.username}), 200
        else:
            return '', 204

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return jsonify({'id': user.id, 'username': user.username}), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return '', 204

api.add_resource(Signup, '/signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')

if __name__ == '__main__':
    app.run(debug=True)
