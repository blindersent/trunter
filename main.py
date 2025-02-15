from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from PIL import Image
import secrets
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
Config.init_app(app)

# Создаем папки для загрузки файлов, если они не существуют
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'reels'), exist_ok=True)

# Создаем default.jpg если его нет
default_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', 'default.jpg')
if not os.path.exists(default_pic_path):
    # Создаем пустое изображение 500x500
    img = Image.new('RGB', (500, 500), color='purple')
    img.save(default_pic_path)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi'}

# Добавляем модели для лайков и комментариев
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    reel_id = db.Column(db.Integer, db.ForeignKey('reel.id'), nullable=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    reel_id = db.Column(db.Integer, db.ForeignKey('reel.id'), nullable=True)
    author = db.relationship('User', backref='comments')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    display_name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    profile_pic = db.Column(db.String(120), default='default.jpg')
    bio = db.Column(db.String(500))
    status = db.Column(db.String(100))
    last_username_change = db.Column(db.DateTime)
    posts = db.relationship('Post', backref='author', lazy=True)
    reels = db.relationship('Reel', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    
    # Отношения для друзей/подписчиков
    followers = db.relationship('User',
                              secondary='followers',
                              primaryjoin='User.id==followers.c.followed_id',
                              secondaryjoin='User.id==followers.c.follower_id',
                              backref=db.backref('following', lazy='dynamic'),
                              lazy='dynamic')

    def follow(self, user):
        if not self.is_following(user):
            self.following.append(user)
            return True
        return False

    def unfollow(self, user):
        if self.is_following(user):
            self.following.remove(user)
            return True
        return False

    def is_following(self, user):
        return self.following.filter(followers.c.followed_id == user.id).count() > 0

    def followed_posts(self):
        return Post.query.join(
            followers, (followers.c.followed_id == Post.user_id)
        ).filter(
            followers.c.follower_id == self.id
        ).order_by(
            Post.date_posted.desc()
        )

# Таблица для отслеживания подписчиков
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.relationship('Like', backref='post', lazy=True)
    comments = db.relationship('Comment', backref='post', lazy=True)

    def is_liked_by(self, user):
        return bool(Like.query.filter_by(user_id=user.id, post_id=self.id).first())

    @property
    def like_count(self):
        return len(self.likes)

    @property
    def comment_count(self):
        return len(self.comments)

class Reel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    video_path = db.Column(db.String(200), nullable=False)
    thumbnail_path = db.Column(db.String(200))
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    views = db.Column(db.Integer, default=0)
    likes = db.relationship('Like', backref='reel', lazy=True)
    comments = db.relationship('Comment', backref='reel', lazy=True)

    def is_liked_by(self, user):
        return bool(Like.query.filter_by(user_id=user.id, reel_id=self.id).first())

    @property
    def like_count(self):
        return len(self.likes)

    @property
    def comment_count(self):
        return len(self.comments)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/home')
def home():
    if current_user.is_authenticated:
        posts = Post.query.order_by(Post.date_posted.desc()).all()
        return render_template('home.html', posts=posts)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if User.query.filter_by(username=username).first():
            flash('Это имя пользователя уже занято', 'danger')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Этот email уже зарегистрирован', 'danger')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            flash('Пароли не совпадают', 'danger')
            return redirect(url_for('register'))
            
        user = User(username=username, email=email)
        user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        db.session.add(user)
        db.session.commit()
        
        flash('Регистрация успешна! Теперь вы можете войти', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            return redirect(url_for('home'))
        else:
            flash('Проверьте email и пароль', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/create_post', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content')
    if content:
        post = Post(content=content, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Пост успешно создан!', 'success')
    return redirect(url_for('home'))

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user).order_by(Post.date_posted.desc()).all()
    followers_count = user.followers.count()
    following_count = user.following.count()
    return render_template('profile.html', 
                         user=user, 
                         posts=posts,
                         followers_count=followers_count,
                         following_count=following_count)

@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('home'))
    if user == current_user:
        flash('Вы не можете подписаться на себя!', 'danger')
        return redirect(url_for('profile', username=username))
    current_user.follow(user)
    db.session.commit()
    flash(f'Вы подписались на {username}!', 'success')
    return redirect(url_for('profile', username=username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Пользователь не найден.', 'danger')
        return redirect(url_for('home'))
    if user == current_user:
        flash('Вы не можете отписаться от себя!', 'danger')
        return redirect(url_for('profile', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash(f'Вы отписались от {username}.', 'info')
    return redirect(url_for('profile', username=username))

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def save_picture(form_picture, folder):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, picture_fn)
    
    # Сжимаем изображение
    if folder == 'profile_pics':
        output_size = (500, 500)
        i = Image.open(form_picture)
        i.thumbnail(output_size)
        i.save(picture_path)
    else:
        form_picture.save(picture_path)
    
    return picture_fn

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Проверка изменения имени пользователя
        if 'username' in request.form and request.form['username'] != current_user.username:
            if current_user.last_username_change and \
               datetime.utcnow() - current_user.last_username_change < timedelta(days=60):
                flash('Вы можете изменить имя пользователя только раз в два месяца', 'danger')
                return redirect(url_for('edit_profile'))
            
            if User.query.filter_by(username=request.form['username']).first():
                flash('Это имя пользователя уже занято', 'danger')
                return redirect(url_for('edit_profile'))
            
            current_user.username = request.form['username']
            current_user.last_username_change = datetime.utcnow()

        # Обновление остальной информации профиля
        if 'display_name' in request.form:
            current_user.display_name = request.form['display_name']
        if 'bio' in request.form:
            current_user.bio = request.form['bio']
        if 'status' in request.form:
            current_user.status = request.form['status']

        # Обработка загрузки фото профиля
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename != '' and allowed_file(file.filename, ALLOWED_EXTENSIONS):
                if current_user.profile_pic != 'default.jpg':
                    try:
                        old_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profile_pics', current_user.profile_pic)
                        if os.path.exists(old_pic_path):
                            os.remove(old_pic_path)
                    except Exception as e:
                        print(f"Ошибка при удалении старого фото: {e}")
                
                try:
                    picture_file = save_picture(file, 'profile_pics')
                    current_user.profile_pic = picture_file
                except Exception as e:
                    print(f"Ошибка при сохранении нового фото: {e}")
                    flash('Ошибка при загрузке фото', 'danger')
                    return redirect(url_for('edit_profile'))

        try:
            db.session.commit()
            flash('Профиль успешно обновлен!', 'success')
        except Exception as e:
            print(f"Ошибка при сохранении изменений: {e}")
            db.session.rollback()
            flash('Произошла ошибка при обновлении профиля', 'danger')
            
        return redirect(url_for('profile', username=current_user.username))

    return render_template('edit_profile.html', user=current_user)

@app.route('/create_reel', methods=['GET', 'POST'])
@login_required
def create_reel():
    if request.method == 'POST':
        if 'video' not in request.files:
            flash('Нет видеофайла', 'danger')
            return redirect(url_for('create_reel'))
        
        video = request.files['video']
        if video.filename == '':
            flash('Не выбран файл', 'danger')
            return redirect(url_for('create_reel'))
        
        if video and allowed_file(video.filename, ALLOWED_VIDEO_EXTENSIONS):
            video_filename = save_picture(video, 'reels')
            
            # Создание миниатюры (в реальном приложении нужно использовать
            # библиотеку для извлечения кадра из видео)
            thumbnail_filename = 'default_thumbnail.jpg'
            
            reel = Reel(
                title=request.form.get('title', ''),
                description=request.form.get('description', ''),
                video_path=video_filename,
                thumbnail_path=thumbnail_filename,
                author=current_user
            )
            
            db.session.add(reel)
            db.session.commit()
            
            flash('Рилс успешно создан!', 'success')
            return redirect(url_for('profile', username=current_user.username))
        else:
            flash('Разрешены только видеофайлы форматов: ' + ', '.join(ALLOWED_VIDEO_EXTENSIONS), 'danger')
            
    return render_template('create_reel.html')

@app.route('/uploads/<folder>/<filename>')
def uploaded_file(folder, filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], folder), filename)

@app.route('/like/<string:type>/<int:id>', methods=['POST'])
@login_required
def like(type, id):
    if type not in ['post', 'reel']:
        return jsonify({'error': 'Invalid type'}), 400
    
    existing_like = None
    if type == 'post':
        existing_like = Like.query.filter_by(user_id=current_user.id, post_id=id).first()
    else:
        existing_like = Like.query.filter_by(user_id=current_user.id, reel_id=id).first()
    
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        return jsonify({'status': 'unliked'})
    
    like = Like(user_id=current_user.id)
    if type == 'post':
        like.post_id = id
    else:
        like.reel_id = id
    
    db.session.add(like)
    db.session.commit()
    return jsonify({'status': 'liked'})

@app.route('/comment/<string:type>/<int:id>', methods=['POST'])
@login_required
def add_comment(type, id):
    content = request.form.get('content')
    if not content:
        return jsonify({'error': 'Comment cannot be empty'}), 400
    
    comment = Comment(content=content, user_id=current_user.id)
    if type == 'post':
        comment.post_id = id
    else:
        comment.reel_id = id
    
    db.session.add(comment)
    db.session.commit()
    
    return jsonify({
        'id': comment.id,
        'content': comment.content,
        'author': comment.author.username,
        'profile_pic': url_for('uploaded_file', folder='profile_pics', filename=comment.author.profile_pic),
        'date': comment.date_posted.strftime('%d.%m.%Y %H:%M')
    })

@app.route('/get_comments/<string:type>/<int:id>')
@login_required
def get_comments(type, id):
    comments = []
    if type == 'post':
        comments = Comment.query.filter_by(post_id=id).order_by(Comment.date_posted.desc()).all()
    else:
        comments = Comment.query.filter_by(reel_id=id).order_by(Comment.date_posted.desc()).all()
    
    return jsonify([{
        'id': c.id,
        'content': c.content,
        'author': c.author.username,
        'profile_pic': url_for('uploaded_file', folder='profile_pics', filename=c.author.profile_pic),
        'date': c.date_posted.strftime('%d.%m.%Y %H:%M')
    } for c in comments])

# Добавляем модель для сообщений
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

@app.route('/messages')
@login_required
def messages():
    # Получаем список диалогов
    sent_messages = Message.query.filter_by(sender_id=current_user.id).all()
    received_messages = Message.query.filter_by(recipient_id=current_user.id).all()
    
    # Создаем список уникальных пользователей, с которыми есть диалоги
    chat_users = set()
    for msg in sent_messages:
        chat_users.add(msg.recipient)
    for msg in received_messages:
        chat_users.add(msg.sender)
    
    return render_template('messages.html', chat_users=list(chat_users))

@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    chat_with = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            message = Message(
                sender_id=current_user.id,
                recipient_id=user_id,
                content=content
            )
            db.session.add(message)
            db.session.commit()
            return redirect(url_for('chat', user_id=user_id))
    
    # Получаем историю сообщений
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Отмечаем сообщения как прочитанные
    unread_messages = Message.query.filter_by(
        recipient_id=current_user.id,
        sender_id=user_id,
        is_read=False
    ).all()
    
    for message in unread_messages:
        message.is_read = True
    db.session.commit()
    
    return render_template('chat.html', chat_with=chat_with, messages=messages)

@app.route('/friends')
@login_required
def friends():
    user_friends = current_user.friends.all()
    # Получаем рекомендации друзей (например, друзья друзей)
    friend_suggestions = User.query.filter(
        ~User.id.in_([friend.id for friend in user_friends]),
        User.id != current_user.id
    ).limit(5).all()
    
    return render_template('friends.html', friends=user_friends, suggestions=friend_suggestions)

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    if query:
        users = User.query.filter(
            (User.username.ilike(f'%{query}%')) |
            (User.display_name.ilike(f'%{query}%'))
        ).limit(20).all()
    else:
        users = []
    return render_template('search.html', users=users, query=query)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            post.content = content
            db.session.commit()
            flash('Пост успешно обновлен!', 'success')
            return redirect(url_for('profile', username=current_user.username))
    
    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    
    db.session.delete(post)
    db.session.commit()
    flash('Пост успешно удален!', 'success')
    return redirect(url_for('profile', username=current_user.username))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, 
                host='0.0.0.0',      # Слушаем все сетевые интерфейсы
                port=5000,           # Используем порт 5000
                debug=False,         # Отключаем режим отладки
                allow_unsafe_werkzeug=True)  # Разрешаем небезопасный режим для разработки