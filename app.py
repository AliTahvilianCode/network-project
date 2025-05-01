from flask import Flask, request, redirect, url_for, make_response, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
from flask import abort
from flask import Flask, render_template

MAX_ATTEMPTS = 5
BLOCK_TIME_MINUTES = 5
INACTIVITY_TIMEOUT = 5

app = Flask(__name__)

app.secret_key = 'your_secret_key_here'
SECRET_KEY = 'your_secret_key_here'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)

    posts = db.relationship('Post', backref='user',
                            lazy=True, cascade="all, delete")

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.errorhandler(403)
def forbidden_error(error):
    return '<h1>403 - Unauthorized Access</h1>', 403

@app.errorhandler(404)
def not_found_error(error):
    return '<h1>404 - Page Not Found</h1>', 404

@app.errorhandler(401)
def unauthorized_error(error):
    return '<h1>401 - Login Required</h1>', 401

@app.errorhandler(400)
def unauthorized_error(error):
    return '<h1>400 - Bad Request :( </h1>', 400

def get_current_user():
    token = request.cookies.get('token')
    if not token:
        abort(400)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['username'], payload['role']
    except jwt.ExpiredSignatureError:
        return 'Token has expired!', 401
    except jwt.InvalidTokenError:
        return 'Invalid token!', 401

def check_session_timeout():
    last_active = session.get('last_active')
    if last_active:
        last_active_time = datetime.fromisoformat(last_active)
        if datetime.now() - last_active_time > timedelta(minutes=INACTIVITY_TIMEOUT):
            session.clear()
            return False
    session['last_active'] = datetime.now().isoformat()
    return True

@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if not check_session_timeout():
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        remember = request.form.get('remember')
        if not username or not password or not role:
            abort(400)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('already_registered.html')
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        expiration_time = datetime.utcnow() + (timedelta(days=7)
                                               if remember else timedelta(hours=1))
        payload = {
            'username': username,
            'role': role,
            'exp': expiration_time
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        if role == 'admin':
            response = make_response(redirect(url_for('dashboard_admin')))
        elif role == 'user':
            response = make_response(redirect(url_for('dashboard_user')))
        else:
            abort(400)

        response.set_cookie('token', token, max_age=(
            7*24*60*60 if remember else None), httponly=True, secure=False)
        return response
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not check_session_timeout():
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')

        if 'blocked_until' in session:
            blocked_until = datetime.fromisoformat(session['blocked_until'])
            if datetime.now() < blocked_until:
                remaining = (blocked_until - datetime.now()).seconds // 60 + 1
                return render_template('blocked.html', remaining=remaining)
            else:
                session.pop('blocked_until')
                session.pop('attempts', None)

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session.pop('attempts', None)
            session.pop('blocked_until', None)
            expiration_time = datetime.utcnow() + (timedelta(days=7) if remember else timedelta(hours=1))
            payload = {
                'username': user.username,
                'role': user.role,
                'exp': expiration_time
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

            if user.role == 'admin':
                response = make_response(redirect(url_for('dashboard_admin')))
            elif user.role == 'user':
                response = make_response(redirect(url_for('dashboard_user')))
            else:
                abort(400)

            response.set_cookie('username', user.username, max_age=7*24*60*60 if remember else None)
            response.set_cookie('role', user.role, max_age=7*24*60*60 if remember else None)
            response.set_cookie('token', token, max_age=7*24*60*60 if remember else None, httponly=True, secure=False)
            return response
        else:
            session['attempts'] = session.get('attempts', 0) + 1
            if session['attempts'] >= MAX_ATTEMPTS:
                block_time = datetime.now() + timedelta(minutes=BLOCK_TIME_MINUTES)
                session['blocked_until'] = block_time.isoformat()
                return render_template('attempt_blocked.html',
                                       max_attempts=MAX_ATTEMPTS,
                                       block_minutes=BLOCK_TIME_MINUTES)
            return render_template('failed.html', attempts=session['attempts'])

    return render_template('login.html')

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('username')
    response.delete_cookie('role')
    response.delete_cookie('token')
    return response

@app.route('/dashboard_user')
def dashboard_user():
    username, role = get_current_user()

    if not username:
        return redirect(url_for('login'))

    if role != 'user':
        abort(403)

    if not check_session_timeout():
        return redirect(url_for('login'))

    return render_template('dashboard_user.html', username=username)

@app.route('/dashboard_admin')
def dashboard_admin():
    username, role = get_current_user()

    if not username:
        return redirect(url_for('login'))

    if role != 'admin':
        abort(403)

    if not check_session_timeout():
        return redirect(url_for('login'))

    return render_template('dashboard_admin.html', username=username)




@app.route('/post', methods=['GET', 'POST'])
def post():
    username, role = get_current_user()
    if role != 'user':
        abort(403)
    if not username:
        return redirect(url_for('login'))
    if not check_session_timeout():
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']
        user = User.query.filter_by(username=username).first()
        new_post = Post(content=content, user_id=user.id)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('dashboard_user'))
    return render_template('post.html')

@app.route('/all_posts')
def all_posts():
    username, role = get_current_user()
    if not username or not check_session_timeout():
        return redirect(url_for('login'))

    all_users = User.query.all()
    user_posts = {user.username: user.posts for user in all_users if user.posts}
    dashboard = '/dashboard_admin' if role == 'admin' else '/dashboard_user'
    
    return render_template('all_posts.html', user_posts=user_posts, dashboard=dashboard)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    username, role = get_current_user()
    if not username:
        return redirect(url_for('login'))
    
    post = Post.query.get_or_404(post_id)
    preview = post.content[:15]
    
    return render_template('view_post.html', post=post, preview=preview, role=role)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    username, role = get_current_user()
    if role != 'admin':
        abort(403)
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('all_posts'))

@app.route('/manage_users', methods=['GET', 'POST'])
def manage_users():
    username, role = get_current_user()
    if not username:
        return redirect(url_for('login'))
    if role != 'admin':
        abort(403)
    
    if request.method == 'POST':
        selected_users = request.form.getlist('user_ids')
        for user_id in selected_users:
            user = User.query.get(int(user_id))
            if user and user.role != 'admin':
                db.session.delete(user)
        db.session.commit()
        return redirect(url_for('manage_users'))

    all_users = User.query.all()
    return render_template('manage_users.html', all_users=all_users)

if __name__ == '__main__':
    app.app_context().push()
    db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)