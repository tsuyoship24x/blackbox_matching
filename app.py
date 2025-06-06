import datetime
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectMultipleField, SelectField, IntegerField
from wtforms.validators import DataRequired, EqualTo, ValidationError

from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

friend_assoc = db.Table('friend_assoc',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('friend_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

match_who_assoc = db.Table('match_who_assoc',
    db.Column('match_id', db.Integer, db.ForeignKey('match_request.id'), primary_key=True),
    db.Column('who_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

# DM chat room relations
chat_room_members = db.Table(
    'chat_room_members',
    db.Column('room_id', db.Integer, db.ForeignKey('chat_room.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

CATEGORIES = [
    ('飲み会', '飲み会'),
    ('スポーツ', 'スポーツ'),
    ('ゲーム', 'ゲーム'),
    ('カフェ', 'カフェ'),
    ('映画', '映画')
]

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    friends = db.relationship(
        'User', secondary=friend_assoc,
        primaryjoin=(friend_assoc.c.user_id == id),
        secondaryjoin=(friend_assoc.c.friend_id == id),
        backref='friend_of'
    )
    match_requests = db.relationship('MatchRequest', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class MatchRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # timestamp of when this request was made (legacy column in DB)
    occur_time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    # category of activity
    category = db.Column(db.String(64), nullable=False)
    # required activity duration in hours
    activity_hours = db.Column(db.Integer, nullable=False)
    # minimum and maximum number of participants desired
    min_people = db.Column(db.Integer, nullable=False, default=1)
    max_people = db.Column(db.Integer, nullable=False, default=1)
    # record creation time (new column)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # requested friends
    who = db.relationship(
        'User', secondary=match_who_assoc,
        backref='matched_in_requests'
    )
    # time ranges for this match request
    time_ranges = db.relationship(
        'MatchTimeRange', backref='match_request',
        lazy=True, cascade='all, delete-orphan'
    )

class MatchTimeRange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey('match_request.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)


class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    members = db.relationship('User', secondary=chat_room_members, backref='chat_rooms')


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    room = db.relationship('ChatRoom', backref='messages')
    user = db.relationship('User')

class RegistrationForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    password2 = PasswordField('パスワード確認', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('登録')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('このユーザー名は既に使われています。')

class LoginForm(FlaskForm):
    username = StringField('ユーザー名', validators=[DataRequired()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    submit = SubmitField('ログイン')

class MatchForm(FlaskForm):
    category = SelectField('何を', choices=CATEGORIES, validators=[DataRequired()])
    who = SelectMultipleField('誰と', coerce=int, validators=[DataRequired()])
    min_people = IntegerField('最低人数', validators=[DataRequired()])
    max_people = IntegerField('上限人数', validators=[DataRequired()])
    activity_hours = IntegerField('活動時間（時間）', validators=[DataRequired()])
    submit = SubmitField('登録')

    def validate_max_people(self, field):
        if self.min_people.data and field.data < self.min_people.data:
            raise ValidationError('上限人数は最低人数以上で指定してください。')


class ChatForm(FlaskForm):
    message = StringField('メッセージ', validators=[DataRequired()])
    submit = SubmitField('送信')

@app.before_first_request
def init_db():
    # create tables (only creates missing tables; does not alter existing ones)
    db.create_all()
    # Ensure new column 'activity_hours' exists in match_request (for existing SQLite DB)
    # Migrate legacy schema columns if necessary
    # 1) Add activity_hours column for older DBs
    try:
        cols = [row[1] for row in db.session.execute("PRAGMA table_info('match_request')")]
        if 'activity_hours' not in cols:
            db.session.execute(
                "ALTER TABLE match_request ADD COLUMN activity_hours INTEGER NOT NULL DEFAULT 0"
            )
            db.session.commit()
    except Exception:
        pass
    # 2) Add occur_time column if missing, or backfill existing rows
    try:
        cols = [row[1] for row in db.session.execute("PRAGMA table_info('match_request')")]
        if 'occur_time' not in cols:
            # add timestamp of request (default now)
            db.session.execute(
                "ALTER TABLE match_request ADD COLUMN occur_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
            )
            db.session.commit()
        else:
            # backfill any NULL occur_time using created_at
            db.session.execute(
                "UPDATE match_request SET occur_time = created_at WHERE occur_time IS NULL"
            )
            db.session.commit()
    except Exception:
        pass
    # 3) Add min_people and max_people columns if missing
    try:
        cols = [row[1] for row in db.session.execute("PRAGMA table_info('match_request')")]
        if 'min_people' not in cols:
            db.session.execute(
                "ALTER TABLE match_request ADD COLUMN min_people INTEGER NOT NULL DEFAULT 2"
            )
            db.session.commit()
        db.session.execute(
            "UPDATE match_request SET min_people = 2 WHERE min_people IS NULL OR min_people < 2"
        )
        db.session.commit()
        if 'max_people' not in cols:
            db.session.execute(
                "ALTER TABLE match_request ADD COLUMN max_people INTEGER NOT NULL DEFAULT 2"
            )
            db.session.commit()
        db.session.execute(
            "UPDATE match_request SET max_people = 2 WHERE max_people IS NULL OR max_people < 2"
        )
        db.session.commit()
    except Exception:
        pass

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        u = User(username=form.username.data)
        u.set_password(form.password.data)
        db.session.add(u)
        db.session.commit()
        flash('登録が完了しました。ログインしてください。')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('ユーザー名かパスワードが違います。')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/add_friend', methods=['GET','POST'])
@login_required
def add_friend():
    search = request.form.get('search', '')
    users = []
    if search:
        users = User.query.filter(User.username.contains(search), User.id != current_user.id).all()
    return render_template('add_friend.html', users=users, search=search)

@app.route('/send_friend_request/<int:user_id>')
@login_required
def send_friend_request(user_id):
    other = User.query.get_or_404(user_id)
    if other == current_user or other in current_user.friends:
        flash('無効な操作です。')
        return redirect(url_for('add_friend'))
    current_user.friends.append(other)
    other.friends.append(current_user)
    db.session.commit()
    flash(f'{other.username} さんと友達になりました。')
    return redirect(url_for('add_friend'))

@app.route('/create_match', methods=['GET','POST'])
@login_required
def create_match():
    form = MatchForm()
    form.who.choices = [(f.id, f.username) for f in current_user.friends]
    if form.validate_on_submit():
        # parse time ranges
        starts = request.form.getlist('range_start')
        ends = request.form.getlist('range_end')
        mr = MatchRequest(
            user=current_user,
            category=form.category.data,
            activity_hours=form.activity_hours.data,
            min_people=form.min_people.data,
            max_people=form.max_people.data
        )
        # associate friends
        for fid in form.who.data:
            u = User.query.get(fid)
            if u:
                mr.who.append(u)
        # add time ranges
        for s, e in zip(starts, ends):
            try:
                st = datetime.datetime.fromisoformat(s)
                et = datetime.datetime.fromisoformat(e)
            except ValueError:
                continue
            if et > st:
                mr.time_ranges.append(MatchTimeRange(start_time=st, end_time=et))
        db.session.add(mr)
        db.session.commit()
        flash('マッチング希望を登録しました。')
        return redirect(url_for('dashboard'))
    return render_template('create_match.html', form=form)

@app.route('/matches')
@login_required
def matches():
    results = []
    for my_req in current_user.match_requests:
        members = [current_user]
        start_times = []
        end_times = []
        other_reqs = []
        for who in my_req.who:
            others = MatchRequest.query.filter_by(user_id=who.id, category=my_req.category).all()
            for o_req in others:
                if current_user in o_req.who:
                    matched = False
                    for my_tr in my_req.time_ranges:
                        for other_tr in o_req.time_ranges:
                            start = max(my_tr.start_time, other_tr.start_time)
                            end = min(my_tr.end_time, other_tr.end_time)
                            if end > start:
                                overlap = (end - start).total_seconds() / 3600
                                required = max(my_req.activity_hours, o_req.activity_hours)
                                if overlap >= required:
                                    members.append(who)
                                    start_times.append(start)
                                    end_times.append(end)
                                    other_reqs.append(o_req)
                                    matched = True
                                    break
                        if matched:
                            break
                if who in members:
                    break
        group_size = len(members)
        if group_size < my_req.min_people or group_size > my_req.max_people:
            continue
        ok = True
        for o_req in other_reqs:
            if group_size < o_req.min_people or group_size > o_req.max_people:
                ok = False
                break
        if not ok or not start_times:
            continue
        start = max(start_times)
        end = min(end_times)
        if end <= start:
            continue
        room_query = ChatRoom.query
        for m in members:
            room_query = room_query.filter(ChatRoom.members.contains(m))
        room = room_query.first()
        if not room:
            room = ChatRoom()
            for m in members:
                room.members.append(m)
            db.session.add(room)
            db.session.commit()
        results.append({
            'friends': [m.username for m in members if m != current_user],
            'category': my_req.category,
            'start': start,
            'end': end,
            'hours': (end - start).total_seconds() / 3600,
            'room_id': room.id
        })
    return render_template('matches.html', results=results)


@app.route('/chat/<int:room_id>', methods=['GET', 'POST'])
@login_required
def chat(room_id):
    room = ChatRoom.query.get_or_404(room_id)
    if current_user not in room.members:
        flash('アクセスできません。')
        return redirect(url_for('matches'))
    form = ChatForm()
    if form.validate_on_submit():
        msg = ChatMessage(room=room, user=current_user, content=form.message.data)
        db.session.add(msg)
        db.session.commit()
        return redirect(url_for('chat', room_id=room.id))
    messages = ChatMessage.query.filter_by(room=room).order_by(ChatMessage.timestamp).all()
    return render_template('chat.html', form=form, messages=messages, room=room)

if __name__ == '__main__':
    app.run(debug=True)
