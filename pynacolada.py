# Depends : path.py, Flask, Flask-login, flask-wtf, wtform, Flask-SQLAlchemy, flask-bcrypt
# TODO : Templates, public folder, zip
import tempfile
import hashlib
from shutil import make_archive

from path import path
from flask import Flask, render_template, send_file, url_for, redirect, abort, request, session
from flask_login import LoginManager, login_user, flash, UserMixin, login_required, logout_user
from flask_wtf import Form
from wtforms import BooleanField, TextField, PasswordField, validators
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt


app = Flask(__name__)
login_manager = LoginManager()
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


#
# Models
#
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(120), unique=False)
    root_folder = db.Column(db.String(120), unique=False)

    def __init__(self, username, email, password, root_folder):
        self.username = username
        self.email = email
        self.password = bcrypt.generate_password_hash(password)
        self.root_folder = root_folder

    def __repr__(self):
        return '<User %r>' % self.username

    def get(userid):
        return User.query.filter(User.id == userid).first()


class PublicLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    link = db.Column(db.String(35), unique=True)
    path = db.Column(db.String(120), unique=True)
    user = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, path, user):
        self.path = path
        self.user = user
        self.link = hashlib.md5(path.encode('utf-8')).hexdigest()

    def __repr__(self):
        return '<PublicLink %r>' % self.path


#
# Forms
#
class LoginForm(Form):
    username = TextField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.Required()])
    rememberme = BooleanField('Remember me')


#
# Views
#
@app.route("/")
@login_required
def index():
    return list()


@login_manager.user_loader
def load_user(userid):
    user = User.get(userid)
    session['root_folder'] = user.root_folder
    session.modified = True
    return User.get(userid)


@app.route("/install")
def install():
    db.create_all()
    olivier = User('olivier', 'mail@olivierlemoal.fr',
                   'password', '/home/olivier/pybrowse/olivier/')
    db.session.add(olivier)
    db.session.commit()
    return "Installed"


@app.route("/p/<public_id>/")
@app.route("/p/<public_id>/<path:directory>")
def public(public_id, directory=None):
    link = PublicLink.query.filter(PublicLink.link == public_id).first()
    public_path = path(link.path)
    if public_path.isfile():
        return send_file(public_path, as_attachment=True)
    elif public_path.isdir():
        path_dir = public_path
        app.logger.debug(directory)
        if directory:
            path_dir += "/" + directory
            if path_dir.isfile():
                return send_file(path_dir, as_attachment=True)
        files = path_dir.files()
        files = [file.relpath(start=path_dir) for file in files]
        directories = path_dir.dirs()
        directories = [directory.relpath(start=path_dir)
                       for directory in directories]
        return render_template('list_public.html', files=files, directories=directories, directory=directory, public_id=public_id)
    else:
        abort(404)


@app.route("/add_p/<path:public_path>")
@login_required
def add_public(public_path):
    public_path = path(session['root_folder'] + public_path)
    link = PublicLink(public_path, session["user_id"])
    db.session.add(link)
    db.session.commit()
    return "ok"


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    error = None
    remember = False
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter(
            User.username == request.form['username']).first()
        if user:
            if bcrypt.check_password_hash(user.password, request.form['password']):
                if request.form.get('rememberme', ''):
                    remember = True
                login_user(user, remember=remember)
                flash("Logged in successfully.")
                return redirect(request.args.get("next") or url_for("index"))
            else:
                error = 'Invalid credentials'
        else:
            error = 'Invalid credentials'
    return render_template("login.html", form=form, error=error)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


@app.route("/browse/<path:directory>/")
@app.route("/browse/")
@login_required
def list(directory=""):
    dir_path = path(session['root_folder'] + directory)
    files = dir_path.files()
    files = [file.relpath(start=session['root_folder']) for file in files]
    directories = dir_path.dirs()
    directories = [directory.relpath(start=session['root_folder'])
                   for directory in directories]
    return render_template('list.html', files=files, directories=directories, directory=directory)


@app.route("/download/<path:todl_path>")
@login_required
def download(todl_path):
    file_path = path(session['root_folder'] + todl_path)
    if not file_path.abspath().startswith(session['root_folder']) or file_path.isdir():
        abort(404)
    return send_file(file_path, as_attachment=True)


@app.route("/zip/<path:tozip_path>")
@login_required
def zip(tozip_path):
    tozip_path = path(session['root_folder'] + tozip_path)
    if not tozip_path.abspath().startswith(session['root_folder']) or not tozip_path.isdir():
        abort(404)
    archive_type = "zip"
    temp_file = tempfile.NamedTemporaryFile()
    archive = make_archive(temp_file.name, archive_type, tozip_path)
    # temp_file.close()
    return send_file(archive, as_attachment=True, attachment_filename=path(tozip_path).name)


if __name__ == "__main__":
    login_manager.init_app(app)
    login_manager.login_view = '/login'
    app.secret_key = 'LakSAljkDà5@~=}pOlkdaklada]$ù'
    app.config[
        'SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/olivier/pybrowse/test.db'
    app.debug = True
    app.run()
