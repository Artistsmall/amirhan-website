from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import secrets
from flask_mail import Mail, Message
import logging
from logging.handlers import RotatingFileHandler

# Настройка логирования
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.info("Запуск Амирхан-М")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')

# Настройка базы данных
if os.environ.get('DATABASE_URL'):
    # Используем PostgreSQL на Render.com
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
else:
    # Локальная SQLite база данных
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Настройка логирования
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/timerhan.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Запуск Амирхан')

# Обработчик ошибок
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Ошибка сервера: {str(error)}')
    return render_template('errors/500.html'), 500

@app.errorhandler(404)
def not_found_error(error):
    app.logger.info('Страница не найдена: %s', request.url)
    return render_template('errors/404.html'), 404

# Обработчик для всех неизвестных URL
@app.route('/<path:path>')
def catch_all(path):
    app.logger.info(f'Попытка доступа к несуществующему URL: {path}')
    return render_template('errors/404.html'), 404

# Конфигурация почты
app.config['MAIL_SERVER'] = 'smtp.mail.ru'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'Radik_82m@mail.ru'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    orders = db.relationship('Order', backref='user', lazy=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiration = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(200))
    category = db.Column(db.String(50))

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    product = db.relationship('Product', backref='order_items')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='new')  # new, processing, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', lazy=True)
    total_amount = db.Column(db.Float, nullable=False)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    product = db.relationship('Product', backref='cart_items')

class ScrapMetal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price_per_kg = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50))
    image_url = db.Column(db.String(200))

class ScrapRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scrap_metal_id = db.Column(db.Integer, db.ForeignKey('scrap_metal.id'), nullable=False)
    weight = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='new')  # new, approved, completed, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    total_amount = db.Column(db.Float, nullable=False)
    comment = db.Column(db.Text)
    user = db.relationship('User', backref='scrap_requests')
    scrap_metal = db.relationship('ScrapMetal', backref='requests')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    try:
        products = Product.query.all()
        logger.info(f"Загружено {len(products)} товаров")
        return render_template('home.html', products=products)
    except Exception as e:
        logger.error(f"Ошибка при загрузке списка товаров: {str(e)}")
        flash('Произошла ошибка при загрузке данных. Пожалуйста, попробуйте позже.', 'error')
        return render_template('home.html', products=[])

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Неверный email или пароль')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash('Email уже зарегистрирован')
            return redirect(url_for('register'))
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/cart')
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    quantity = int(request.form.get('quantity', 1))
    cart_item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=current_user.id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
    
    db.session.commit()
    flash('Товар добавлен в корзину')
    return redirect(url_for('cart'))

@app.route('/cart/update/<int:item_id>', methods=['POST'])
@login_required
def update_cart(item_id):
    cart_item = CartItem.query.get_or_404(item_id)
    if cart_item.user_id != current_user.id:
        abort(403)
    
    quantity = int(request.form.get('quantity', 0))
    if quantity > 0:
        cart_item.quantity = quantity
        db.session.commit()
    else:
        db.session.delete(cart_item)
        db.session.commit()
    
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if request.method == 'POST':
        cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
        if not cart_items:
            flash('Ваша корзина пуста')
            return redirect(url_for('cart'))

        total_amount = sum(item.product.price * item.quantity for item in cart_items)
        
        order = Order(
            user_id=current_user.id,
            total_amount=total_amount
        )
        db.session.add(order)
        
        for cart_item in cart_items:
            order_item = OrderItem(
                order=order,
                product_id=cart_item.product_id,
                quantity=cart_item.quantity,
                price=cart_item.product.price
            )
            db.session.add(order_item)
            db.session.delete(cart_item)
        
        db.session.commit()
        flash('Заказ успешно оформлен')
        return redirect(url_for('order_history'))
    
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in cart_items)
    return render_template('checkout.html', cart_items=cart_items, total=total)

@app.route('/orders')
@login_required
def order_history():
    orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
    return render_template('orders.html', orders=orders)

def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('У вас нет доступа к этой странице')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/admin/orders')
@login_required
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    scrap_requests = ScrapRequest.query.order_by(ScrapRequest.created_at.desc()).all()
    return render_template('admin/orders.html', orders=orders, scrap_requests=scrap_requests)

@app.route('/admin/order/<int:order_id>/status', methods=['POST'])
@login_required
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    if new_status in ['new', 'processing', 'completed', 'cancelled']:
        order.status = new_status
        db.session.commit()
        flash(f'Статус заказа #{order.id} обновлен')
    return redirect(url_for('admin_orders'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Генерируем токен
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # Отправляем email
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Сброс пароля',
                        sender='noreply@metalshop.com',
                        recipients=[user.email])
            msg.body = f'''Для сброса пароля перейдите по ссылке:
{reset_url}

Если вы не запрашивали сброс пароля, проигнорируйте это сообщение.
'''
            mail.send(msg)
            flash('Инструкции по сбросу пароля отправлены на ваш email', 'success')
            return redirect(url_for('login'))
        
        flash('Email не найден', 'error')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiration < datetime.utcnow():
        flash('Недействительная или просроченная ссылка для сброса пароля')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        flash('Ваш пароль был успешно изменен')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/scrap')
def scrap_metals():
    try:
        metals = ScrapMetal.query.all()
        logger.info(f"Загружено {len(metals)} видов металлолома")
        return render_template('scrap/index.html', metals=metals)
    except Exception as e:
        logger.error(f"Ошибка при загрузке списка металлолома: {str(e)}")
        flash('Произошла ошибка при загрузке данных. Пожалуйста, попробуйте позже.', 'error')
        return redirect(url_for('home'))

@app.route('/scrap/<int:metal_id>')
def scrap_metal_detail(metal_id):
    try:
        metal = ScrapMetal.query.get_or_404(metal_id)
        logger.info(f"Загружены детали металлолома ID={metal_id}: {metal.name}")
        return render_template('scrap/detail.html', metal=metal)
    except Exception as e:
        logger.error(f"Ошибка при загрузке деталей металлолома ID={metal_id}: {str(e)}")
        flash('Произошла ошибка при загрузке данных. Пожалуйста, попробуйте позже.', 'error')
        return redirect(url_for('scrap_metals'))

@app.route('/scrap/request/<int:metal_id>', methods=['GET', 'POST'])
@login_required
def create_scrap_request(metal_id):
    try:
        metal = ScrapMetal.query.get_or_404(metal_id)
        logger.info(f"Загружена форма заявки для металла ID={metal_id}")
        
        if request.method == 'POST':
            try:
                weight = float(request.form.get('weight', 0))
                if weight <= 0:
                    raise ValueError('Вес должен быть больше 0')
                
                comment = request.form.get('comment', '')
                total_amount = weight * metal.price_per_kg
                
                scrap_request = ScrapRequest(
                    user_id=current_user.id,
                    scrap_metal_id=metal_id,
                    weight=weight,
                    total_amount=total_amount,
                    comment=comment
                )
                
                db.session.add(scrap_request)
                db.session.commit()
                
                logger.info(f"Создана новая заявка ID={scrap_request.id} для пользователя ID={current_user.id}")
                flash('Ваша заявка на сдачу металла принята', 'success')
                return redirect(url_for('my_scrap_requests'))
            
            except ValueError as ve:
                logger.warning(f"Ошибка валидации данных: {str(ve)}")
                flash(str(ve), 'error')
                return render_template('scrap/create_request.html', metal=metal)
            
            except Exception as e:
                logger.error(f"Ошибка при создании заявки: {str(e)}")
                db.session.rollback()
                flash('Произошла ошибка при создании заявки. Пожалуйста, попробуйте позже.', 'error')
                return render_template('scrap/create_request.html', metal=metal)
        
        return render_template('scrap/create_request.html', metal=metal)
    
    except Exception as e:
        logger.error(f"Ошибка при загрузке формы заявки: {str(e)}")
        flash('Произошла ошибка при загрузке формы. Пожалуйста, попробуйте позже.', 'error')
        return redirect(url_for('scrap_metals'))

@app.route('/my_scrap_requests')
@login_required
def my_scrap_requests():
    try:
        requests = ScrapRequest.query.filter_by(user_id=current_user.id).order_by(ScrapRequest.created_at.desc()).all()
        logger.info(f"Загружены заявки пользователя ID={current_user.id}, количество: {len(requests)}")
        return render_template('scrap/my_requests.html', requests=requests)
    except Exception as e:
        logger.error(f"Ошибка при загрузке заявок пользователя ID={current_user.id}: {str(e)}")
        flash('Произошла ошибка при загрузке заявок. Пожалуйста, попробуйте позже.', 'error')
        return redirect(url_for('home'))

@app.route('/admin/scrap-requests')
@login_required
@admin_required
def admin_scrap_requests():
    requests = ScrapRequest.query.order_by(ScrapRequest.created_at.desc()).all()
    return render_template('admin/scrap_requests.html', requests=requests)

@app.route('/history')
@login_required
def history():
    try:
        # Получаем заказы пользователя
        orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.created_at.desc()).all()
        # Получаем заявки на металлолом
        scrap_requests = ScrapRequest.query.filter_by(user_id=current_user.id).order_by(ScrapRequest.created_at.desc()).all()
        
        return render_template('history.html', orders=orders, scrap_requests=scrap_requests)
    except Exception as e:
        logger.error(f"Ошибка при загрузке истории: {str(e)}")
        flash('Произошла ошибка при загрузке истории. Пожалуйста, попробуйте позже.', 'error')
        return redirect(url_for('home'))

@app.route('/admin/scrap-request/<int:request_id>/status', methods=['POST'])
@login_required
@admin_required
def update_scrap_request_status(request_id):
    scrap_request = ScrapRequest.query.get_or_404(request_id)
    status = request.form.get('status')
    
    if status in ['new', 'approved', 'completed', 'rejected']:
        scrap_request.status = status
        try:
            db.session.commit()
            flash('Статус заявки обновлен', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Ошибка при обновлении статуса заявки: {str(e)}')
            flash('Произошла ошибка при обновлении статуса', 'error')
    else:
        flash('Некорректный статус', 'error')
    
    return redirect(url_for('admin_scrap_requests'))

@app.route('/api/order/<int:order_id>')
@login_required
def get_order_details(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        
        # Проверяем, принадлежит ли заказ текущему пользователю или является ли он администратором
        if order.user_id != current_user.id and not current_user.is_admin:
            abort(403)
        
        items = []
        for item in order.items:
            items.append({
                'name': item.product.name,
                'quantity': item.quantity,
                'price': item.price,
                'total': item.price * item.quantity
            })
        
        return jsonify({
            'id': order.id,
            'created_at': order.created_at.strftime('%d.%m.%Y %H:%M'),
            'status': order.status,
            'items': items,
            'total_amount': order.total_amount
        })
    except Exception as e:
        logger.error(f"Ошибка при получении деталей заказа {order_id}: {str(e)}")
        return jsonify({'error': 'Произошла ошибка при загрузке данных'}), 500

@app.route('/api/scrap-request/<int:request_id>')
@login_required
def get_scrap_request_details(request_id):
    try:
        scrap_request = ScrapRequest.query.get_or_404(request_id)
        
        # Проверяем, принадлежит ли заявка текущему пользователю или является ли он администратором
        if scrap_request.user_id != current_user.id and not current_user.is_admin:
            abort(403)
        
        return jsonify({
            'id': scrap_request.id,
            'created_at': scrap_request.created_at.strftime('%d.%m.%Y %H:%M'),
            'status': scrap_request.status,
            'weight': scrap_request.weight,
            'total_amount': scrap_request.total_amount,
            'comment': scrap_request.comment,
            'metal': {
                'name': scrap_request.scrap_metal.name,
                'price_per_kg': scrap_request.scrap_metal.price_per_kg
            }
        })
    except Exception as e:
        logger.error(f"Ошибка при получении деталей заявки {request_id}: {str(e)}")
        return jsonify({'error': 'Произошла ошибка при загрузке данных'}), 500

def init_db():
    """Инициализация базы данных"""
    try:
        # Создаем все таблицы
        with app.app_context():
            db.create_all()
            
            # Проверяем наличие данных
            scrap_count = db.session.query(ScrapMetal).count()
            product_count = db.session.query(Product).count()
            admin_count = db.session.query(User).filter_by(is_admin=True).count()
            
            # Если нет администратора, создаем его
            if admin_count == 0:
                admin = User(
                    email='admin@example.com',
                    username='admin',
                    is_admin=True
                )
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                logger.info("Создан аккаунт администратора")
            
            # Если таблица ScrapMetal пуста, добавляем тестовые данные
            if scrap_count == 0:
                test_metals = [
                    {
                        'name': 'Черный металлолом 3А',
                        'description': 'Габаритный стальной лом толщиной от 4мм',
                        'price_per_kg': 25.50,
                        'category': 'Черный металл'
                    },
                    {
                        'name': 'Медь',
                        'description': 'Медный лом категории А',
                        'price_per_kg': 520.00,
                        'category': 'Цветной металл'
                    },
                    {
                        'name': 'Алюминий',
                        'description': 'Алюминиевый лом',
                        'price_per_kg': 120.00,
                        'category': 'Цветной металл'
                    },
                    {
                        'name': 'Черный металлолом 5А',
                        'description': 'Негабаритный стальной лом',
                        'price_per_kg': 22.50,
                        'category': 'Черный металл'
                    }
                ]
                
                for metal_data in test_metals:
                    metal = ScrapMetal(**metal_data)
                    db.session.add(metal)
                
                db.session.commit()
                logger.info("Тестовые данные добавлены в таблицу ScrapMetal")
            
            # Если таблица Product пуста, добавляем тестовые данные
            if product_count == 0:
                test_products = [
                    {
                        'name': 'Арматура А500С',
                        'description': 'Арматура строительная рифленая класса А500С. Применяется для армирования железобетонных конструкций.',
                        'price': 65000,
                        'category': 'Арматура',
                        'image_url': '/static/images/products/armatura.jpg'
                    },
                    {
                        'name': 'Лист стальной горячекатаный',
                        'description': 'Лист стальной горячекатаный, марка стали Ст3сп5, толщина 4 мм. Широко применяется в строительстве и машиностроении.',
                        'price': 75000,
                        'category': 'Листовой прокат',
                        'image_url': '/static/images/products/list.jpg'
                    },
                    {
                        'name': 'Труба профильная',
                        'description': 'Труба профильная 40х40х3 мм, сталь Ст3. Используется в строительстве и производстве металлоконструкций.',
                        'price': 85000,
                        'category': 'Трубный прокат',
                        'image_url': '/static/images/products/truba.jpg'
                    }
                ]
                
                for product_data in test_products:
                    product = Product(**product_data)
                    db.session.add(product)
                
                db.session.commit()
                logger.info("Тестовые данные добавлены в таблицу Product")

            # Создаем тестового пользователя, если его нет
            test_user = User.query.filter_by(email='test@test.com').first()
            if not test_user:
                test_user = User(
                    email='test@test.com',
                    username='test_user'
                )
                test_user.set_password('test123')
                db.session.add(test_user)
                db.session.commit()
                logger.info("Создан тестовый пользователь")

            # Добавляем тестовые заявки на сдачу металла
            if db.session.query(ScrapRequest).count() == 0:
                metals = ScrapMetal.query.all()
                test_user = User.query.filter_by(email='test@test.com').first()
                
                if test_user and metals:
                    test_requests = [
                        {
                            'user_id': test_user.id,
                            'scrap_metal_id': metals[0].id,  # Черный металлолом 3А
                            'weight': 1000.0,
                            'total_amount': 1000.0 * metals[0].price_per_kg,
                            'status': 'completed',
                            'comment': 'Тестовая заявка на сдачу черного металла',
                            'created_at': datetime.utcnow() - timedelta(days=5)
                        },
                        {
                            'user_id': test_user.id,
                            'scrap_metal_id': metals[1].id,  # Медь
                            'weight': 50.0,
                            'total_amount': 50.0 * metals[1].price_per_kg,
                            'status': 'approved',
                            'comment': 'Тестовая заявка на сдачу меди',
                            'created_at': datetime.utcnow() - timedelta(days=2)
                        },
                        {
                            'user_id': test_user.id,
                            'scrap_metal_id': metals[2].id,  # Алюминий
                            'weight': 100.0,
                            'total_amount': 100.0 * metals[2].price_per_kg,
                            'status': 'new',
                            'comment': 'Тестовая заявка на сдачу алюминия',
                            'created_at': datetime.utcnow() - timedelta(days=1)
                        }
                    ]
                    
                    for request_data in test_requests:
                        scrap_request = ScrapRequest(**request_data)
                        db.session.add(scrap_request)
                    
                    db.session.commit()
                    logger.info("Добавлены тестовые заявки на сдачу металла")
            
            logger.info("База данных успешно инициализирована")
            
    except Exception as e:
        logger.error(f"Ошибка при инициализации базы данных: {str(e)}")
        db.session.rollback()
        raise

# Инициализация базы данных при запуске приложения
with app.app_context():
    init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 50340))
    app.run(host='0.0.0.0', port=port, debug=True) 