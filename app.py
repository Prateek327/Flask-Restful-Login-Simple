from flask import Flask

from flask import  request, make_response

from flask.json import jsonify

from flask_restful import Api, Resource

from flask_sqlalchemy import SQLAlchemy

from datetime import datetime

from flask_httpauth import HTTPTokenAuth

from itsdangerous import TimedJSONWebSignatureSerializer as JsonWebToken

import os

import bcrypt

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__)))

SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir,"test.db")

db = SQLAlchemy()

jwt = JsonWebToken("secretToken!", expires_in=3600)

auth = HTTPTokenAuth("Bearer")

INVALID_INPUT_422 = ({"message": "Invalid input."}, 422)

INVALID_CREDENTIALS__422 = ({"message": "Invalid credentials."}, 422)

USER_ALREADY_EXIST = ({"message": "User already exist"}, 202)

USER_NOT_EXIST = ({"message": "User not exist"}, 202)

ERROR_ON_HANDLING = ({"message" : "Error on handling"}, 401)

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(length=80))
    password = db.Column(db.LargeBinary(length=60), nullable=False)
    email = db.Column(db.String(length=80), unique=True, nullable=False)
    created = db.Column(db.DateTime, nullable=False)

    def generate_auth_token(self):    
            return jwt.dumps({"email" : self.email})   

    @staticmethod
    @auth.verify_token
    def verify_auth_token(token):
        try:
            data = jwt.loads(token)
            print("here")
        except:
            return False
        
        if (Blacklist.check_blacklist(token)):
            return False

        if "email" in data:
            return True
        return False
    
    def __repr__(self):
        return "<User(id='%s', name='%s', password='%s', email='%s', created='%s')" % (
            self.id,
            self.username,
            self.password,
            self.email,
            self.created
        )


class Blacklist(db.Model):

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blackisted_on = db.Column(db.DateTime, nullable=False)
    
    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = Blacklist.query.filter_by(token= auth_token).first()
        if res:
            return True  
        else:
            return False
    
    def __repr__(self):
        return "<User(id='%s', status='invalidated.')>" % (
            self.id,
            self.refresh_token,
        )

class Index(Resource):
    @staticmethod
    def get():
        return "Hello World"

class Register(Resource):
    @staticmethod
    def post():
            username, unhashedPassword, email = {
                request.json.get("username").strip(),
                request.json.get("password"),
                request.json.get("email").strip()
            }

            if username is None or unhashedPassword is None or email is None:
                return INVALID_INPUT_422
            password = bcrypt.hashpw(unhashedPassword.strip().encode("utf-8"), bcrypt.gensalt())
            user = User.query.filter_by(email=email).first()

            if not user:
                try:
                    user = User(username=username, password=password, email=email, created=datetime.utcnow())
                    db.session.add(user)
                    db.session.commit()

                    auth_token = user.generate_auth_token()
                    
                    responseObject = {
                        'auth_token' : auth_token.decode()
                    }

                    return make_response(jsonify(responseObject))
                except Exception as why:
                    return ERROR_ON_HANDLING
            else:
                return USER_ALREADY_EXIST        


     
class Login(Resource):
    @staticmethod
    def post():

        userIdentity, password = {
            request.json.get("userIdentity").strip(),
            request.json.get("password").strip()
        }

        if userIdentity is None or password is None:
            return INVALID_INPUT_422

        user = User.query.filter_by(username = userIdentity).first()


        if user is None:
            user = User.query.filter_by(email = userIdentity).first()
            if user is None:
                return USER_NOT_EXIST
            else:
                isPasswordMatched = bcrypt.checkpw(password, user.password)
                if not isPasswordMatched:
                    return INVALID_CREDENTIALS__422

        access_token = user.generate_auth_token()

        responseObject =  {
            "auth_token": access_token.decode(),
        }

        return make_response(jsonify(responseObject))

class Logout(Resource):
    @staticmethod
    @auth.login_required
    def post():
        # get auth token
        auth_token = request.json.get("auth_token")
        blacklist_token = Blacklist(token=auth_token, blackisted_on=datetime.utcnow())
        try:
            # insert the token
            db.session.add(blacklist_token)
            db.session.commit()
            responseObject = {
                'status': 'success',
                'message': 'Successfully logged out.'
            }
            return make_response(jsonify(responseObject))
        except Exception as e:
            responseObject = {
                'status': 'fail',
                'message': e
            }
            return make_response(jsonify(responseObject))
      
       

def generate_routes(app):

    # Create api.
    api = Api(app)

    # Add all routes resources.
    # Index page.
    api.add_resource(Index, "/")

    # Register page.
    api.add_resource(Register, "/v1/auth/register")

    # Login page.
    api.add_resource(Login, "/v1/auth/login")

    # Logout page.
    api.add_resource(Logout, "/v1/auth/logout")

def create_app():
    # Create a flask app.
    app = Flask(__name__)

    # Set debug true for catching the errors.
    app.config['DEBUG'] = True

    # Set database url.
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    
     # Generate routes.
    generate_routes(app)

    # Database initialize with app.
    db.init_app(app)

    # Check if there is no database.
    if not os.path.exists(SQLALCHEMY_DATABASE_URI):

        # New db app if no database.
        db.app = app

        # Create all database tables.
        db.create_all()

    return app


if __name__ == '__main__':

    # Create app.
    app = create_app()

    # Run app. For production use another web server.
    # Set debug and use_reloader parameters as False.
    app.run(port=6000, debug=True, host='localhost', use_reloader=True)