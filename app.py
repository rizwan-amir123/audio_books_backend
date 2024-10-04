from flask import Flask, jsonify, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
import os
import uuid
from flask_cors import CORS  # Import CORS
import time
from sqlalchemy.exc import OperationalError

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)
CORS(app)
# Set configurations using environment variables
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL') + '?timeout=10'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.secret_key = os.getenv('FLASK_APP_SECRET_KEY')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    votes = db.relationship('Vote', backref='user', lazy=True)

# Book Model
class Book(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(150), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    cover_image = db.Column(db.String(200), nullable=False)
    vote_count = db.Column(db.Integer, default=0)
    votes = db.relationship('Vote', backref='book', lazy=True)

# Vote Model
class Vote(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)

# Initialize the database manually
with app.app_context():
    db.create_all()

# Route to create a new user (signup)
@app.route('/signup', methods=['POST'])
def signup():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    for _ in range(5):  # Retry mechanism
        try:
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({"message": "User created successfully"}), 201
        except OperationalError:
            db.session.rollback()  # Rollback if there's an error
            time.sleep(1)  # Wait a bit before retrying
    
    return jsonify({"error": "Database is locked, please try again later."}), 500

# Route to sign in a user
@app.route('/signin', methods=['POST'])
def signin():
    username = request.json.get('username')
    password = request.json.get('password')
    
    print("username:", username)
    print("password:", password)

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

# Route to get all books (protected)
@app.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    books = Book.query.all()
    books_list = [
        {
            "id": book.id,
            "title": book.title,
            "author": book.author,
            "cover_image": book.cover_image,
            "vote_count": book.vote_count
        } for book in books
    ]
    return jsonify(books_list), 200

# Route to vote for a book (protected)
@app.route('/books/<string:book_id>/vote', methods=['PUT'])
@jwt_required()
def update_vote_count(book_id):
    current_user_id = get_jwt_identity()
    
    # Fetch the book using string UUID
    book = Book.query.get_or_404(book_id)

    # Check if the user has already voted (for any book)
    existing_vote = Vote.query.filter_by(user_id=current_user_id).first()

    # Case 1: User already voted for the same book
    if existing_vote and existing_vote.book_id == book_id:
        return jsonify({"error": "You have already voted for this book"}), 400

    # Case 2: User has voted for a different book, update their vote
    if existing_vote and existing_vote.book_id != book_id:
        # Decrement the vote count for the old book
        old_book = Book.query.get(existing_vote.book_id)
        if old_book:
            old_book.vote_count -= 1
        
        # Update the existing vote to the new book
        existing_vote.book_id = book_id

    # Case 3: User has never voted, create a new vote
    else:
        existing_vote = Vote(user_id=current_user_id, book_id=book_id)
        db.session.add(existing_vote)

    # Increment the vote count for the new book
    book.vote_count += 1

    db.session.commit()

    return jsonify({"message": "Vote updated", "vote_count": book.vote_count}), 200



# Route to create a new book
@app.route('/books', methods=['POST'])
#@jwt_required()
def create_book():
    if not request.json or not all(key in request.json for key in ['title', 'author', 'cover_image']):
        abort(400, description="Request must contain 'title', 'author', and 'cover_image' fields.")

    new_book = Book(
        title=request.json['title'],
        author=request.json['author'],
        cover_image=request.json['cover_image'],
        vote_count=request.json.get('vote_count', 0)  # Default vote_count to 0 if not provided
    )

    db.session.add(new_book)
    db.session.commit()

    return jsonify({
        "message": "Book created successfully",
        "book": {
            "id": new_book.id,
            "title": new_book.title,
            "author": new_book.author,
            "cover_image": new_book.cover_image,
            "vote_count": new_book.vote_count
        }
    }), 201

# Route to get the vote row for a specific user (protected)
@app.route('/votes/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user_vote(user_id):
    current_user_id = get_jwt_identity()

    # Ensure the current user is the one being requested or is authorized to view
    if current_user_id != user_id:
        return jsonify({"error": "Unauthorized access"}), 403

    # Fetch the user's vote record
    vote = Vote.query.filter_by(user_id=user_id).first()

    if not vote:
        return jsonify({"error": "No vote found for this user"}), 404

    # Return the vote details
    return jsonify({
        "user_id": vote.user_id,
        "book_id": vote.book_id,
    }), 200


# Run the app
if __name__ == '__main__':
    app.run(debug=True)

