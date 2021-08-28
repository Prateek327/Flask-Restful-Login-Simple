# Flask-Restful-Login-Simple
A flask restful web app which demonstrates login management ( register, login and logout) 

Concepts used :

1. Flash-HTTPAuth for http authentication  on flask routes
2. Json web tokens for secure exchange of authorization credentials
3. Blacklisting method to invalidate tokens
4. Flask-SQLAlchemy 

To start the app go to the app folder and open command prompt from there and type "python  -m app"

Curl commands to test the app : 

Register : 
curl -H "Content-Type: application/json" --data "{\"name\":\"example_name\",\"username\":\"example_username\",\"password\":\"example_password\", \"email\":\"example@example.com\",\"pincode\":\"000000\",\"phoneNumber\":\"8888888888\", \"address\":\"Hogwarts\"}" http://localhost:5000/v1/auth/register

Login : 
curl -H "Content-Type: application/json" --data "{\"userIdentity\":\"example@example.com\", \"password\":\"example_password\"}" http://localhost:5000/v1/auth/login

Logout : 
curl -H "Content-Type: application/json" -H "Authorization: Bearer Access_Token" --data "{\"auth_token\":\" Access_Token \"}" http://localhost:5000/v1/auth/logout