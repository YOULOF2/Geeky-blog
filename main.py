from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import requests
import random
import os
# from dotenv import load_dotenv
# ==================================================================================================================== #
# ==================================================================================================================== #
HASHING_METHOD = "pbkdf2:sha256"
SALT_TIMES = 8
EMAIL_ERROR = "That email does not exist, please try again."
PASSWORD_ERROR = "Password incorrect, please try again."
ALREADY_LOGGED_IN_ERROR = "You've already signed up with that email, log in instead"
COMMENT_LOGIN_ERROR = "You need to register or login to comment."
ERROR_CODES = {
    "404": {
        "code": 404,
        "expression": "Oops!",
        "title": "Page not found",
        "description": "The page you are looking for might have been removed had its name changed or is temporarily "
                       "unavailable. "
    },
    "403": {
        "code": 403,
        "expression": "Naughty!",
        "title": "Forbidden",
        "description": "You don't have the permission to access the requested resource. It is either read-protected "
                       "or not readable by the server. "
    },
    "500": {
        "code": 500,
        "expression": "Sorry!",
        "title": "Technical Difficulties",
        "description": "Where facing some technical difficulties. Please try again later."
    }
}
APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY")
UNSPLASH_CLIENT_ID = os.environ.get("UNSPLASH_CLIENT_ID")
# ==================================================================================================================== #
app = Flask(__name__)
app.config['SECRET_KEY'] = APP_SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap(app)
# ==================================================================================================================== #
# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# ==================================================================================================================== #

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# ==================================================================================================================== #

# ==================================================================================================================== #


login_manager = LoginManager()
login_manager.init_app(app)


# ==================================================================================================================== #
# Functions
def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        try:
            user_id = int(current_user.get_id())
        except TypeError:
            return abort(403)
        else:
            if user_id == 1:
                return function(*args, **kwargs)
            else:
                return abort(403)

    return wrapper_function


def is_admin():
    try:
        user_id = int(current_user.get_id())
    except TypeError:
        return False
    else:
        if user_id == 1:
            return True
        return False


def get_random_wallpaper(data_json):
    random_wallpaper_data = random.choice(data_json)
    wallpaper = random_wallpaper_data["urls"]["full"]
    return wallpaper


def get_wallpaper_data():
    endpoint = "https://api.unsplash.com/photos/random"
    parameters = {
        "client_id": UNSPLASH_CLIENT_ID,
        "count": 30,
        "orientation": "landscape",
        "query": "adventure"
    }
    response = requests.get(url=endpoint, params=parameters)
    wallpaper_json = response.json()
    print("Getting wallpapers")
    return wallpaper_json


all_wallpaper_data = get_wallpaper_data()
wallpaper = get_random_wallpaper(all_wallpaper_data)


# ==================================================================================================================== #
# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "user_data"
    id = db.Column(db.Integer, primary_key=True)
    # ********** Add Children Relationship ********** #
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
    # *********************************************** #

    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # ********** Add Parent Relationship ********** #
    # Create Foreign Key, "user_data.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("user_data.id"))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")
    # ********************************************* #

    # ********** Add Children Relationship ********** #
    comments = relationship("Comment", back_populates="parent_post")
    # ********************************************* #

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # ********** Add Parent Relationship ********** #
    author_id = db.Column(db.Integer, db.ForeignKey("user_data.id"))
    comment_author = relationship("User", back_populates="comments")

    parent_post = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # ********************************************* #

    text = db.Column(db.Text, nullable=False)


# ==================================================================================================================== #


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# db.create_all()
# ==================================================================================================================== #


# ==================================================================================================================== #

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    wallpaper = get_random_wallpaper(all_wallpaper_data)
    if not is_admin():
        return render_template("index.html", all_posts=posts, user_logged_in=current_user.is_authenticated,
                               wallpaper=wallpaper)
    else:
        return render_template("index.html", all_posts=posts, user_logged_in=True, admin_access=True,
                               wallpaper=wallpaper)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first() is None:
            hashed_password = generate_password_hash(form.password.data, method=HASHING_METHOD, salt_length=SALT_TIMES)
            new_user = User(
                email=form.email.data,
                password=hashed_password,
                name=form.user_name.data
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        else:
            flash(ALREADY_LOGGED_IN_ERROR)
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            user_hashed_pass = user.password
            correct_password = check_password_hash(user_hashed_pass, form.password.data)
            if correct_password:
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash(PASSWORD_ERROR)
                return render_template("login.html", form=form)
        else:
            flash(EMAIL_ERROR)
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.body.data,
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            print(requested_post.comments)
        else:
            flash(COMMENT_LOGIN_ERROR)
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, is_admin=is_admin(), post_id=post_id, form=form,
                           user_logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = post.author
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/next_bg")
@admin_only
def next_bg():
    global wallpaper
    wallpaper = get_random_wallpaper(all_wallpaper_data)
    return redirect(url_for("get_all_posts"))


@app.route("/new_bg_data")
@admin_only
def new_bg_data():
    global all_wallpaper_data
    all_wallpaper_data = get_wallpaper_data()
    return redirect(url_for("get_all_posts"))


# ==================================================================================================================== #
# Not found pages
@app.errorhandler(404)
def page_not_found(e):
    error_data = ERROR_CODES["404"]
    return render_template("error.html", error=error_data)


@app.errorhandler(403)
def page_not_found(e):
    error_data = ERROR_CODES["403"]
    return render_template("error.html", error=error_data)


@app.errorhandler(500)
def page_not_found(e):
    error_data = ERROR_CODES["500"]
    return render_template("error.html", error=error_data)


# ==================================================================================================================== #
if __name__ == "__main__":
    app.run(debug=True)
