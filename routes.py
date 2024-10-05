from flask import Blueprint, jsonify, request, abort
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token
from flask_bcrypt import Bcrypt
from mongoengine import DoesNotExist
from models import User, Book, Vote  # Assuming models are defined using mongoengine
import time
from bson import ObjectId 

bcrypt = Bcrypt()

# Create a blueprint for routes
routes = Blueprint('routes', __name__)

# Route to create a new user (signup)
@routes.route('/signup', methods=['POST'])
def signup():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        new_user = User(username=username, password=hashed_password)
        new_user.save()  # Save directly to MongoDB
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        return jsonify({"error": "Could not create user, please try again later."}), 500

# Route to sign in a user
@routes.route('/signin', methods=['POST'])
def signin():
    username = request.json.get('username')
    password = request.json.get('password')

    try:
        user = User.objects.get(username=username)  # Query using mongoengine
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=str(user.id))  # Convert ObjectId to string
            return jsonify(access_token=access_token), 200
    except DoesNotExist:
        return jsonify({"error": "Invalid username or password"}), 401

# Route to get all books (protected)
@routes.route('/books', methods=['GET'])
@jwt_required()
def get_books():
    books = Book.objects()  # Get all books from MongoDB
    books_list = [
        {
            "id": str(book.id),  # Convert ObjectId to string
            "title": book.title,
            "author": book.author,
            "cover_image": book.cover_image,
            "vote_count": book.vote_count
        } for book in books
    ]
    return jsonify(books_list), 200

# Route to vote for a book (protected)
@routes.route('/books/<string:book_id>/vote', methods=['PUT'])
@jwt_required()
def update_vote_count(book_id):
	current_user_id = get_jwt_identity()  # Get the current user's ID from JWT
	print("current_user_id: ", current_user_id)
	print("book_id: ", book_id)

	try:
		# Convert the book_id to ObjectId
		book = Book.objects.get(id=ObjectId(book_id))  # Query using mongoengine
		print("book.id: ", book.id)
		

		# Check if the user has voted for any book
		existing_vote = Vote.objects(user_id=ObjectId(current_user_id)).first()  # Find existing vote for any book
		
		if existing_vote:
			print("existing_vote.book_id: ", existing_vote.book_id.id)
			# User has voted before, so update the old vote
			# Use existing_vote.book_id to get the old book; convert it to ObjectId
			old_book_id = existing_vote.book_id.id  # Get the old book's ID
			print("old_book_id: ", old_book_id)
			old_book = Book.objects.get(id=ObjectId(old_book_id))  # Get the old book the user voted for
			old_book.vote_count -= 1  # Decrement the old book's vote count
			old_book.save()  # Save the changes to the old book

			# Update the existing vote with the new book_id
			existing_vote.update(book_id=ObjectId(book.id))  # Change the book_id to the new one as a string
		else:
		    # If the user has not voted before, create a new vote
		    existing_vote = Vote(user_id=current_user_id, book_id=ObjectId(book.id))  # Use book.id here as a string
		    existing_vote.save()  # Save the new vote

		# Increment the vote count for the new book
		book.vote_count += 1  # Increment the vote count for the new book
		book.save()  # Save updated vote count for the book

		return jsonify({"message": "Vote updated", "vote_count": book.vote_count}), 200
	except DoesNotExist:
		return jsonify({"error": "Book not found"}), 404
	except Exception as e:
		return jsonify({"error": str(e)}), 500  # Return a generic error for any other issues




# Route to create a new book
@routes.route('/books', methods=['POST'])
def create_book():
    if not request.json or not all(key in request.json for key in ['title', 'author', 'cover_image']):
        abort(400, description="Request must contain 'title', 'author', and 'cover_image' fields.")

    new_book = Book(
        title=request.json['title'],
        author=request.json['author'],
        cover_image=request.json['cover_image'],
        vote_count=request.json.get('vote_count', 0)
    )

    new_book.save()  # Save directly to MongoDB

    return jsonify({
        "message": "Book created successfully",
        "book": {
            "id": str(new_book.id),  # Convert ObjectId to string
            "title": new_book.title,
            "author": new_book.author,
            "cover_image": new_book.cover_image,
            "vote_count": new_book.vote_count
        }
    }), 201

# Route to get the vote row for a specific user (protected)
@routes.route('/votes/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user_vote(user_id):
    current_user_id = get_jwt_identity()

    if current_user_id != user_id:
        return jsonify({"error": "Unauthorized access"}), 403

    vote = Vote.objects(user_id=user_id).first()

    if not vote:
        return jsonify({"message": "No vote found for this user"}), 200

    return jsonify({
        "user_id": vote.user_id,
        "book_id": vote.book_id,
    }), 200


