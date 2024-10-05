from flask import Flask
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from flask_cors import CORS
import os
from flask_mongoengine import MongoEngine

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')  

# MongoDB Configuration
app.config['MONGODB_SETTINGS'] = {
    'db': 'audiobooks',  # Replace with your MongoDB database name
    'host': os.getenv('MONGODB_URI')  # MongoDB connection URI from .env
}

db = MongoEngine(app)  # Initialize MongoDB (MongoEngine)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Import and register the blueprint
from routes import routes
app.register_blueprint(routes)

if __name__ == '__main__':
    app.run(debug=True)

