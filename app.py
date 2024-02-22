from flask import Flask, render_template, url_for, redirect, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_migrate import Migrate
import json


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class NormalJoke(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    joke = db.Column(db.Text, nullable=False)
    likes = db.Column(db.Integer, default=0)  # Add likes attribute here
    dislikes = db.Column(db.Integer, default=0)  # Add dislikes attribute here
    user = db.relationship('User', backref='normal_jokes')


class DarkJoke(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    joke = db.Column(db.Text, nullable=False)
    likes = db.Column(db.Integer, default=0)  # Add likes attribute here
    dislikes = db.Column(db.Integer, default=0)  # Add dislikes attribute here
    user = db.relationship('User', backref='jokes')

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joke_id = db.Column(db.Integer, nullable=False)

class Dislike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joke_id = db.Column(db.Integer, nullable=False)
    # You can add additional fields if needed

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joke_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref='replies')

class DarkJokeReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joke_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref='dark_joke_replies')


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Email(message="Invalid email"), Length(max=120)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("This username already exists, please try a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()

        if existing_user_email:
            raise ValidationError("This email address is already registered.")

class LoginForm(FlaskForm):
    username_email = StringField(validators=[InputRequired(), Length(min=4, max=120)], render_kw={"placeholder": "Username or Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


class NormalJokeForm(FlaskForm):
    joke = TextAreaField('Joke', validators=[InputRequired()])
    submit = SubmitField('Submit')

class DarkJokeForm(FlaskForm):
    joke = TextAreaField('Joke', validators=[InputRequired()])
    submit = SubmitField('Submit')

class ReplyForm(FlaskForm):
    content = TextAreaField('Reply', validators=[InputRequired()])
    submit = SubmitField('Submit')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter((User.username == form.username_email.data) | (User.email == form.username_email.data)).first()

        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/normal_jokes', methods=['GET', 'POST'])
def normal_jokes():
    form = NormalJokeForm()
    if form.validate_on_submit():
        new_joke = NormalJoke(user=current_user, joke=form.joke.data)
        db.session.add(new_joke)
        db.session.commit()
        return redirect(url_for('normal_jokes'))

    jokes = NormalJoke.query.all()
    return render_template('normal_jokes.html', form=form, jokes=jokes)

@app.route('/dark_jokes', methods=['GET', 'POST'])
def dark_jokes():
    form = DarkJokeForm()
    if form.validate_on_submit():
        new_joke = DarkJoke(user=current_user, joke=form.joke.data)
        db.session.add(new_joke)
        db.session.commit()
        return redirect(url_for('dark_jokes'))

    jokes = DarkJoke.query.all()
    return render_template('dark_jokes.html', form=form, jokes=jokes)

@app.route('/like/<int:joke_id>', methods=['POST'])
@login_required
def like_joke(joke_id):
    # Get the joke with the given ID from the database
    joke = NormalJoke.query.get_or_404(joke_id)
    
    # Check if the user has already liked the joke
    like = Like.query.filter_by(user_id=current_user.id, joke_id=joke_id).first()

    if like:
        # User has already liked the joke, remove the like
        db.session.delete(like)
        flash('You unliked the joke.', 'info')
    else:
        # User hasn't liked the joke, add a new like
        new_like = Like(user_id=current_user.id, joke_id=joke_id)
        db.session.add(new_like)
        flash('You liked the joke.', 'success')

    # Commit the changes to the database
    db.session.commit()
    
    # Redirect back to the previous page
    return redirect(request.referrer)


@app.route('/dislike/<int:joke_id>', methods=['POST'])
@login_required
def dislike_joke(joke_id):
    # Get the joke with the given ID from the database
    joke = NormalJoke.query.get_or_404(joke_id)
    
    # Increment the dislikes count for the joke
    joke.dislikes += 1
    
    # Commit the changes to the database
    db.session.commit()
    
    # Redirect back to the previous page
    return redirect(request.referrer)

@app.route('/reply/<int:joke_id>', methods=['GET', 'POST'])
@login_required
def reply_joke(joke_id):
    joke = NormalJoke.query.get_or_404(joke_id)
    replies = Reply.query.filter_by(joke_id=joke_id).all()

    form = ReplyForm()
    if form.validate_on_submit():
        reply = Reply(user_id=current_user.id, joke_id=joke_id, content=form.content.data)
        db.session.add(reply)
        db.session.commit()
        flash('Your reply has been added.', 'success')
        return redirect(url_for('reply_joke', joke_id=joke_id))

    return render_template('reply_joke.html', joke=joke, replies=replies, form=form)

@app.route('/reply_dark_joke/<int:joke_id>', methods=['GET', 'POST'])
@login_required
def reply_dark_joke(joke_id):
    joke = DarkJoke.query.get_or_404(joke_id)
    replies = DarkJokeReply.query.filter_by(joke_id=joke_id).all()

    form = ReplyForm()
    if form.validate_on_submit():
        reply = DarkJokeReply(user_id=current_user.id, joke_id=joke_id, content=form.content.data)
        db.session.add(reply)
        db.session.commit()
        flash('Your reply has been added.', 'success')
        return redirect(url_for('reply_dark_joke', joke_id=joke_id))

    return render_template('reply_dark_joke.html', joke=joke, replies=replies, form=form)

@app.route('/delete_joke/<int:joke_id>', methods=['POST'])
@login_required
def delete_joke(joke_id):
    joke = NormalJoke.query.get_or_404(joke_id)
    # Check if the current user is the owner of the joke
    if joke.user_id == current_user.id:
        db.session.delete(joke)
        db.session.commit()
        flash('Your joke has been deleted.', 'success')
    else:
        flash('You are not authorized to delete this joke.', 'danger')
    return redirect(request.referrer)

@app.route('/delete_dark_joke/<int:joke_id>', methods=['POST'])
@login_required
def delete_dark_joke(joke_id):
    joke = DarkJoke.query.get_or_404(joke_id)
    # Check if the current user is the owner of the joke
    if joke.user_id == current_user.id:
        db.session.delete(joke)
        db.session.commit()
        flash('Your dark joke has been deleted.', 'success')
    else:
        flash('You are not authorized to delete this dark joke.', 'danger')
    return redirect(request.referrer)

def read_json(filename):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        data = {}
    return data


@app.template_filter('datetimeformat')
def datetimeformat(value, format='%d/%m/%Y %H:%M'):
    return value.strftime(format)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
