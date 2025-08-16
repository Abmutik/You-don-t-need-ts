from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'ba71613e778ebe5ddaaa927c314a17a1'  # Замени на случайный ключ

# Основные пользователи (для входа на сайт)
users = {
    'INTRUDER': generate_password_hash('HELPME'),
    'user2': generate_password_hash('password2')
}

# Защищённые поддиректории: { 'относительный_путь': { 'логин': хэш_пароля } }
# Пример: для 'subdir1' логин 'admin', пароль 'secret'
protected_dirs = {
    'subdir1': {
        'INTRUDER': generate_password_hash('HELPME')
    }
    # Добавь больше, например: 'subdir1/subsubdir': { 'user': generate_password_hash('pass') }
}

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id in users else None

# Страница логина (основная)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            session['unlocked_dirs'] = []  # Инициализация списка разблокированных директорий
            return redirect(url_for('catalog'))
        else:
            flash('Неверный логин или пароль')
    return render_template('login.html')

# Выход
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('unlocked_dirs', None)
    return redirect(url_for('login'))

# Каталог (с поддержкой путей)
@app.route('/catalog/', defaults={'rel_path': ''})
@app.route('/catalog/<path:rel_path>')
@login_required
def catalog(rel_path):
    files_dir = os.path.join(app.root_path, 'files')
    full_path = os.path.normpath(os.path.join(files_dir, rel_path))

    # Проверка, что путь внутри files/
    if not full_path.startswith(files_dir):
        return 'Доступ запрещён', 403

    if not os.path.exists(full_path) or not os.path.isdir(full_path):
        return 'Директория не найдена', 404

    # Проверка защиты директории
    if rel_path in protected_dirs and rel_path not in session.get('unlocked_dirs', []):
        return redirect(url_for('dir_login', rel_path=rel_path))

    # Список файлов и папок
    items = []
    for item in os.listdir(full_path):
        item_path = os.path.join(full_path, item)
        rel_item_path = os.path.join(rel_path, item)
        is_dir = os.path.isdir(item_path)
        items.append({
            'name': item,
            'is_dir': is_dir,
            'url': url_for('catalog', rel_path=rel_item_path) if is_dir else url_for('download', rel_path=rel_item_path)
        })

    # Сортировка: папки сверху
    items.sort(key=lambda x: (not x['is_dir'], x['name']))

    return render_template('catalog.html', items=items, current_path=rel_path)

# Логин для защищённой директории
@app.route('/dir_login/<path:rel_path>', methods=['GET', 'POST'])
@login_required
def dir_login(rel_path):
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if rel_path in protected_dirs and username in protected_dirs[rel_path] and check_password_hash(protected_dirs[rel_path][username], password):
            unlocked = session.get('unlocked_dirs', [])
            unlocked.append(rel_path)
            session['unlocked_dirs'] = unlocked
            return redirect(url_for('catalog', rel_path=rel_path))
        else:
            flash('Неверный логин или пароль для этой директории')
    return render_template('dir_login.html', rel_path=rel_path)

# Скачивание файла
@app.route('/download/<path:rel_path>')
@login_required
def download(rel_path):
    files_dir = os.path.join(app.root_path, 'files')
    dir_path = os.path.dirname(os.path.join(files_dir, rel_path))

    # Проверка доступа к директории (включая защищённые)
    rel_dir = os.path.dirname(rel_path)
    if rel_dir in protected_dirs and rel_dir not in session.get('unlocked_dirs', []):
        return redirect(url_for('dir_login', rel_path=rel_dir))

    # Добавь as_attachment=True для принудительного скачивания
    return send_from_directory('files', rel_path, as_attachment=True)

# Главная
@app.route('/')
def index():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

