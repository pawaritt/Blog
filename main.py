import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateRegisterForm, CreateLogInForm, CreateCommentForm, CreateReplyForm
from functools import wraps
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# CONFIGURE TABLES
class Reply(db.Model):
    __tablename__ = "reply"
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("comment.id"), nullable=False)
    replied_comment = relationship("Comments", back_populates="reply")
    text = db.Column(db.String(250), nullable=False)


class Comments(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    comment_author = relationship("Users", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    post = relationship("BlogPost", back_populates="comments")

    reply = relationship("Reply", back_populates="replied_comment")

    parent_text = db.Column(db.Text, nullable=False)

    date_time = db.Column(db.String(250), nullable=False)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    author = relationship("Users", back_populates="post")
    comments = relationship("Comments", back_populates="post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    post = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="comment_author")


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(401)
        return f(*args, **kwargs)
    return decorated_function


@app.errorhandler(401)
def not_found(error):
    return redirect(url_for('get_all_posts'))


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = CreateRegisterForm()
    if form.validate_on_submit():
        user = Users(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=generate_password_hash(password=request.form.get('password'),
                                            method='pbkdf2:sha256',
                                            salt_length=8)
        )
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = CreateLogInForm()
    if form.validate_on_submit():
        current_email = request.form.get('email')
        user = Users.query.filter_by(email=current_email).first()
        if not user:
            flash("email is invalid.")
            return redirect(url_for('login'))
        elif not check_password_hash(pwhash=user.password, password=request.form.get('password')):
            flash("password is incorrect.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
@login_required
def show_post(post_id):
    comment_form = CreateCommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        text = str(comment_form.comment.data).replace('<p>', '').replace('</p>', '')
        time = str(datetime.datetime.now().strftime("%B %d %Y, %X"))
        comment = Comments(author_id=current_user.id,
                           post_id=requested_post.id,
                           parent_text=text,
                           date_time=time)
        db.session.add(comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
@login_required
def about():
    return render_template("about.html")


@app.route("/contact")
@login_required
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@login_required
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
        current_user.post.append(new_post)
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>", methods=['POST', 'GET'])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
