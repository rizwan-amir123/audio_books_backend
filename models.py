from flask_mongoengine import MongoEngine
import uuid

db = MongoEngine()

class User(db.Document):
    username = db.StringField(required=True, unique=True)
    password = db.StringField(required=True)

class Book(db.Document):
    title = db.StringField(required=True)
    author = db.StringField(required=True)
    cover_image = db.StringField(required=True)
    vote_count = db.IntField(default=0)

class Vote(db.Document):
    user_id = db.ReferenceField(User, required=True)
    book_id = db.ReferenceField(Book, required=True)

