from flask import Flask, jsonify, request, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import safe_str_cmp
from marshmallow import Schema, fields, ValidationError
from passlib.hash import bcrypt

from flask_jwt_extended import create_access_token
from flask_jwt_extended import current_user
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager


app = Flask(__name__)


app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.debug = True


jwt = JWTManager(app)
db = SQLAlchemy(app)


class UserSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    password = db.Column(db.String(50), nullable=False)

    # NOTE: In a real application make sure to properly hash and salt passwords

    def check_password(self, password):
        return bcrypt.verify(password, self.password)


class UpdateBookSchema(Schema):
    name = fields.String(required=True)
    price = fields.Number(required=True)


class CreateBookSchema(UpdateBookSchema):
    isbn = fields.String(required=True)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)
    isbn = db.Column(db.Integer)

    @staticmethod
    def add_book(_name, _price, _isbn):
        new_book = Book(name=_name, price=_price, isbn=_isbn)
        db.session.add(new_book)
        db.session.commit()

    @staticmethod
    def get_all_books():
        return [Book.json(book) for book in Book.query.all()]

    @staticmethod
    def get_book(_isbn):
        return Book.json(Book.query.filter_by(isbn=_isbn).first())

    @staticmethod
    def delete_book(_isbn):
        success = Book.query.filter_by(isbn=_isbn).delete()
        db.session.commit()
        return bool(success)

    @staticmethod
    def update_book_price(_isbn, _price):
        book_to_update = Book.query.filter_by(isbn=_isbn).first()
        book_to_update.price = _price
        db.session.commit()

    @staticmethod
    def update_book_name(_isbn, _name):
        book_to_update = Book.query.filter_by(isbn=_isbn).first()
        book_to_update.name = _name
        db.session.commit()

    @staticmethod
    def replace_book(_isbn, _name, _price):
        book_to_replace = Book.query.filter_by(isbn=_isbn).first()
        book_to_replace.name = _name
        book_to_replace.price = _price
        db.session.commit()

    def json(self):
        return {'name': self.name, 'price': self.price, 'isbn': self.isbn}


# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


# Register a callback function that loades a user from your database whenever
# a protected route is accessed. This should return any python object on a
# successful lookup, or None if the lookup failed for any reason (for example
# if the user has been deleted from the database).
@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()


@app.route("/login", methods=["POST"])
def login():
    request_data = request.json
    schema = UserSchema()

    try:
        result = schema.load(request_data)
        username = request_data.get("username")
        password = request_data.get("password")

        user = User.query.filter_by(username=username).one_or_none()

        if not user or not user.check_password(password):
            return jsonify("Wrong username or password"), 401

        # Notice that we are passing in the actual sqlalchemy user object here
        access_token = create_access_token(identity=user)
        return jsonify(access_token=access_token)

    except ValidationError as err:
        return jsonify(err.messages), 400


@app.route("/profile", methods=["GET"])
@jwt_required()
def protected():
    # We can now access our sqlalchemy User object via `current_user`.
    return jsonify(
        id=current_user.id,
        username=current_user.username,
)


@app.route('/books', methods=["GET"])
@jwt_required()
def get_books():
    return jsonify(Book.get_all_books())


@app.route('/books', methods=['POST'])
@jwt_required()
def add_book():
    request_data = request.json
    schema = CreateBookSchema()

    try:
        result = schema.load(request_data)
        name = request_data.get("name")
        price = request_data.get("price")
        isbn = request_data.get("isbn")
        Book.add_book(name, price, isbn)
        return Response('', 201, mimetype='application/json')
    except ValidationError as err:
        return jsonify(err.messages), 400

@app.route('/books/<int:isbn>')
@jwt_required()
def get_book_by_isbn(isbn):
    return jsonify(Book.get_book(isbn))

@app.route('/books/<int:isbn>', methods=['PUT'])
@jwt_required()
def replace_book(isbn):
    request_data = request.json
    schema = UpdateBookSchema()

    try:
        result = schema.load(request_data)
        name = request_data.get("name")
        price = request_data.get("price")
        ook.replace_book(isbn, request_data['name'], request_data['price'])
        return Response('', 201, mimetype='application/json')
    except ValidationError as err:
        return jsonify(err.messages), 400


@app.route('/books/<int:isbn>', methods=['DELETE'])
@jwt_required()
def delete_book(isbn):
    Book.delete_book(isbn)
    return Response('', 204)

app.run()
