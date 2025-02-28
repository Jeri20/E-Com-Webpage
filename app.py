from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model (Admin & User)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Product Model
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        is_admin = request.form.get('is_admin') == 'on'

        user = User(username=username, password=password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin' if user.is_admin else 'shop'))
        else:
            flash('Login failed. Check your credentials.', 'danger')

    return render_template('login.html')

@app.route('/shop')
@login_required
def shop():
    products = Product.query.all()
    return render_template('shop.html', products=products)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash("You don't have permission to access this page!", "danger")
        return redirect(url_for('shop'))  # Prevents users from accessing

    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        price = float(request.form['price'])

        new_product = Product(name=name, category=category, price=price)
        db.session.add(new_product)
        db.session.commit()
        flash('Product added!', 'success')
        return redirect(url_for('admin'))  # Refresh admin page

    products = Product.query.all()
    return render_template('admin.html', products=products)

@app.route('/add_to_cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    cart = session.get('cart', [])
    if product_id not in cart:  # Prevent duplicate entries
        cart.append(product_id)
    session['cart'] = cart
    flash('Product added to cart!', 'success')
    return redirect(url_for('shop'))

@app.route('/remove_from_cart/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    cart = session.get('cart', [])
    if product_id in cart:
        cart.remove(product_id)
        session['cart'] = cart
        flash('Product removed from cart!', 'success')
    return redirect(url_for('cart'))

@app.route('/cart')
@login_required
def cart():
    cart = session.get('cart', [])
    products = Product.query.filter(Product.id.in_(cart)).all()
    return render_template('cart.html', products=products)

@app.route('/logout')
def logout():
    logout_user()
    session.pop('cart', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
