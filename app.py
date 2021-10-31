import os
import random
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask import Flask, flash, render_template, redirect, url_for, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, current_user, logout_user, login_required, UserMixin, LoginManager
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, IntegerField, TextAreaField, HiddenField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange, ValidationError
from flask_uploads import UploadSet, configure_uploads, IMAGES

# Create the flask app
app = Flask(__name__)

# Declare a single collection of files
photos = UploadSet('photos', IMAGES)

# Configure the upload destination
app.config['UPLOADED_PHOTOS_DEST'] = 'static/uploads'

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mobilestore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure app's secret key to use sessions for authentication
app.config['SECRET_KEY'] = os.urandom(24)

# Pass the app to the upload set's configuration
configure_uploads(app, photos)

# Create an instance of SQLAlchemy database
db = SQLAlchemy(app)

# Create an instance of Bcrypt, which will be used for password storage as it supports password hashing
bcrypt = Bcrypt(app)

# Create an instance of LoginManager
# which will provide user session management,
# handle the common tasks of logging in, logging out,
# and remembering user's session
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# A user_loader callback, used to reload the user object
# from the user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# A `user` type represents all users in the store.
# It also acts as a super class of `Customer` and `Admin`
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False)


# A 'customer' type inherits from 'user'.
# It represents a normal user who registers in the website
# and perform activities such as browsing products, placing orders, etc.
class Customer(User):
    orders = db.relationship('Order', backref='customer', lazy=True)
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    phone_number = db.Column(db.Integer)
    addresses = db.relationship('Address', backref='customer', lazy=True)

# A 'admin' type inherits from `user`
# It represents either an admin of the website or a vendor staff,
# who can add products to the marketplace and manage orders from customers
class Admin(User):
    products = db.relationship('Product', backref='owner', lazy=True)

# An 'address' type represents the physical address of a customer
# The address will be created after a successful order is placed
# with the info provided by users
class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False)
    street = db.Column(db.String(100))
    city = db.Column(db.String(100))
    state = db.Column(db.String(20))
    country = db.Column(db.String(50))

# A 'storelocation` represents a store where the product is located
class StoreLocation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    address = db.Column(db.String(200))

# A 'product' type represents any products in the marketplace
# Products are only created by either website's admin or vendor
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.String, db.ForeignKey(
        'user.email'), nullable=False)
    store_location = db.relationship(
        'StoreLocation', backref='location', lazy=True)
    name = db.Column(db.String(50))
    price = db.Column(db.Integer)
    stock = db.Column(db.Integer)
    description = db.Column(db.String(500))
    image = db.Column(db.String(100))
    createdAt = db.Column(db.DateTime, default=datetime.now)
    orders = db.relationship('CartItem', backref='product', lazy=True)


# An 'order' type represents a purchase made by a customer
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reference = db.Column(db.String(5))
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    phone_number = db.Column(db.Integer)
    email = db.Column(db.String(50))
    street = db.Column(db.String(100))
    city = db.Column(db.String(100))
    state = db.Column(db.String(20))
    country = db.Column(db.String(50))
    status = db.Column(db.String(50))
    shipping_method = db.Column(db.String(50))
    payment_method = db.Column(db.String(50))
    items = db.relationship('CartItem', backref='order', lazy=True)

    # Calculate the total value of the order
    def order_total(self):
        total = 0
        for item in self.items:
            total += item.quantity * item.product.price
        return total

    # Calculate the number of items of the order
    def quantity_total(self):
        return len(self.items)


# A 'cartitem' type represents a 'product' what users add to shopping cart
# Each of the cart item will associate with a quantity
class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)


# A form enables users to register for an account
# All fields for registration are required
class RegistrationForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    # Validate the email provided by users with the existing record in the database
    # Trigger a validation error if the email has been registered before
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'That email has been taken. Please choose a different one.')


# A form enables users to login into the website
class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

# A form enables an admin or a vendor to add products to sell on the marketplace
class AddProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    price = IntegerField('Price', validators=[
                         DataRequired(), NumberRange(min=0)])
    stock = IntegerField("Stock", validators=[
                         DataRequired(), NumberRange(min=0)])
    description = TextAreaField('Description', validators=[DataRequired()])
    image = FileField('Product Image', validators=[
                      FileAllowed(IMAGES, 'Only images are accepted'), DataRequired()])


# A form enables users to add product to shopping cart
class AddToCartForm(FlaskForm):
    quantity = IntegerField('Quantity')
    product_id = HiddenField('product_id')


# A form enables users to place an order
# Users will be asked the required info to support delivery
# From here users can also select the available payment method and shipping method 
class CheckoutForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    street = StringField('Street', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    state = SelectField('State', choices=[
        ('California', 'California'),
        ('Washington', 'Washington'),
        ('Arizona', 'Arizona')
    ])

    country = SelectField('Country', choices=[
        ('United States', 'United States'),
        ('United Kingdom', 'United Kingdom'),
        ('France', 'France')
    ])

    payment_method = SelectField('Payment Method', choices=[
        ('Credit/Debit Card', 'Credit/Debit Card'),
        ('Paypal', 'Paypal'),
        ('Voucher', 'Voucher')
    ])

    shipping_method = SelectField('Shipping Method', choices=[
        ('Standard Delivery', 'Standard Delivery'),
        ('InHouse Courier Service', 'InHouse Courier Service')
    ])

    remember = BooleanField('Remember my info for next purchase')


# A helper method to 
# - handle the item that users add to shopping cart
# - calculate some useful information such as total value, total items, etc
def proceed_cart():
    products = []
    grand_total = 0

    if 'cart' not in session:
        session['cart'] = []

    for item in session['cart']:
        product = Product.query.filter_by(id=item['product_id']).first()
        quantity = int(item['quantity'])
        total = quantity * product.price
        grand_total += total
        products.append({
            'product_id': product.id,
            'name': product.name,
            'price': product.price,
            'image': product.image,
            'quantity': quantity,
            'total': total,
            'owner': product.owner_id
        })
    return products, grand_total


# A helper method to get the shipping method for an order.
# Because the in-house courier service is only available for the website owner's products,
# and users can add products from multiple sources to shopping cart,
# if there are any products from the vendor in the shopping cart, 
# then 'InHouse Courier Service' will not be available as an option
def get_shipping_method(products):
    for product in products:
        owner = User.query.filter_by(email=product['owner']).first()
        if owner and owner.role == 'vendor':
            return [('Standard Delivery', 'Standard Delivery')]
        else:
            return [
                ('Standard Delivery', 'Standard Delivery'),
                ('InHouse Courier Service', 'InHouse Courier Service')
            ]

# A helper method to check if the current-logged-in user has the role of 'admin' or 'vendor'
def isAdmin():
    if current_user.get_id() is not None:
        current_logged_in_user = User.query.filter_by(
            id=current_user.get_id()).first()
        return current_logged_in_user.role == 'admin' or current_logged_in_user.role == 'vendor'
    else:
        return False


# A helper method to get the email of current logged in user
def get_user_email():
    if current_user.get_id() is not None:
        current_logged_in_user = User.query.filter_by(
            id=current_user.get_id()).first()
        return current_logged_in_user.email


# A helper method to add/update the item in shopping cart
# The logic is straightforward:
# - If the same item exists in cart, update its quantity
# - If the item is not existing in cart, then add it as a new item
def update_or_add_to_cart(product_id, quantity):
    if 'cart' not in session:
        session['cart'] = []

    isNewItem = True
    itemNeedUpdate = {}

    for item in session['cart']:
        if item['product_id'] == product_id:
            isNewItem = False
            itemNeedUpdate = item

    if isNewItem:
        session['cart'].append({
            "product_id": product_id,
            "quantity": quantity
        })
    else:
        current_quantity = itemNeedUpdate['quantity']
        itemNeedUpdate.update({'quantity': current_quantity + quantity})

    session.modified = True

# A helper method to get all incomplete orders for a store's owner
def get_orders_for_store(store_owner):
    results = []
    orders = Order.query.filter(Order.status != 'Shipped')
    for order in orders:
        for item in order.items:
            if item.product.owner_id == store_owner:
                results.append(order)

    return results

# Root decorator for the home page
@app.route('/', methods=['GET', 'POST'])
def index():
    search = request.args.get('search_term')
    # if users perform search, then query the products based on the search term
    # otherwise, query all the products with stock > 0
    if search:
        products = Product.query.filter(Product.name.contains(
            search) | Product.description.contains(search)).filter(Product.stock > 0)
    else:
        products = Product.query.filter(Product.stock > 0)
    return render_template('index.html', products=products, admin=isAdmin())


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # hashing the password for storage
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode('utf-8')
        
        # create a new user with the role of 'customer'
        # the system does not support registering as 'admin' or 'vendor'
        user = Customer(email=form.email.data, password=hashed_password, role='customer')
        db.session.add(user)
        db.session.commit()
        flash(f'Your account { form.email.data } has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            else:
                return redirect(url_for('admin')) if isAdmin() else redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again!', 'danger')
    return render_template('login.html', title='Login', form=form)


# Logout decorator to enable logging out the current logged in user
# Users will then be redirected to the home page
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


# Product decorator to enable routing to view the product's details
@app.route('/product/<product_id>')
def product(product_id):
    product = Product.query.filter_by(id=product_id).first()
    # if the product is valid, then render the product detail screen
    # otherwise redirect users to the home page
    if product:
        form = AddToCartForm()
        return render_template('product-detail.html', product=product, form=form, admin=isAdmin())
    else:
        return redirect(url_for('index'))


# Quick add decorator to support quickly add a product to shopping cart
# The default quantity is 1 if users perform a quick add
@app.route('/quick-add/<product_id>')
def quick_add(product_id):
    update_or_add_to_cart(product_id, 1)
    return redirect(url_for('index'))


# Add to cart decorator to support adding a product to shopping cart
@app.route('/add-to-cart', methods=['POST'])
def add_to_cart():
    # Create a 'AddToCartForm` to get the quantity of the product
    form = AddToCartForm()

    if form.validate_on_submit():
        update_or_add_to_cart(form.product_id.data, form.quantity.data)
    return redirect(url_for('index'))


# A decorator and function to support remove an item from shopping cart
# A valid login session is required to access this route
@app.route('/remove-from-cart/<product_id>')
@login_required
def remove_from_cart(product_id):
    # filter out the item to be removed
    items_in_cart = [item for item in session['cart']
                     if not item['product_id'] == product_id]

    # update the cart
    session['cart'] = items_in_cart
    session.modified = True

    # redirect users to the cart home screen
    return redirect(url_for('cart'))


# Cart decorator to enable routing to the shopping cart
# A valid login session is required to access shopping cart
@app.route('/cart')
@login_required
def cart():
    products, grand_total = proceed_cart()
    return render_template('cart.html', products=products, grand_total=grand_total)


# Checkout decorator to enable routing to the checkout form
# A valid login session is required to access checkout form
@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    form = CheckoutForm()
    products, grand_total = proceed_cart()

    if form.validate_on_submit():
        order = Order()

        # Populate the attributes from the form's data to the order
        form.populate_obj(order)

        # Create a random reference number with 5 characters
        order.reference = ''.join(
            [random.choice('ABCEDFGHIJKEMNOPQRSTUVWXYZ1234567890') for _ in range(5)])
        
        # For this version, the system is not handling payment.
        # Assuming payment was successful, the order status is set to 'AWAITING PICKING' as default
        order.status = 'AWAITING PICKING'
        order.user_id = current_user.get_id()

        # Loop through the added product to create the relevant cart items with quantity
        for product in products:
            cart_item = CartItem(
                quantity=product['quantity'],
                product_id=product['product_id']
            )
            order.items.append(cart_item)

            # Update product's stock
            product = Product.query.filter_by(id=product['product_id']).update(
                {'stock': Product.stock - product['quantity']})

        # If users chose to remember their shipping information for next purchase
        # then create a new address instance, associated with the customer id
        if form.remember:
            address = Address()
            form.populate_obj(address)
            address.customer_id = current_user.get_id()

            db.session.add(address)

        db.session.add(order)
        db.session.commit()

        # Clear the shopping cart after checking out
        session['cart'] = []
        session.modified = True

        # Inform user and redirect them to home page
        flash('Your order has been placed!', 'success')
        return redirect(url_for('index'))

    # Get shipping method based on the items in cart
    form.shipping_method.choices = get_shipping_method(products)
    return render_template('checkout.html', form=form, products=products, grand_total=grand_total)


# Admin decorator to enable routing to the admin home page
# A valid login session is required to access this page
# If the logged-in user is not an admin or a vendor, then redirect them to home page
@app.route('/admin')
@login_required
def admin():
    # Security check, only allow admin/vendor to access this page
    if isAdmin():
        products = Product.query.filter_by(owner_id=get_user_email())
        products_in_stock = Product.query.filter(Product.stock > 0).count()
        orders = get_orders_for_store(get_user_email())
        return render_template('admin/index.html', admin=True, products=products, products_in_stock=products_in_stock, orders=orders)
    else:
        return redirect(url_for('index'))


# Add new product decorator to enable routing to add new product form
# A valid login session is required to access this page
# If the logged-in user is not an admin or a vendor, then redirect them to home page
@app.route('/admin/add', methods=['GET', 'POST'])
@login_required
def add():
    form = AddProductForm()

    if form.validate_on_submit():
        product_image_url = photos.save(form.image.data)
        # Create new product with valid information
        # and save to the database
        new_product = Product(name=form.name.data,
                              price=form.price.data,
                              stock=form.stock.data,
                              description=form.description.data,
                              image=product_image_url,
                              owner_id=get_user_email())
        db.session.add(new_product)
        db.session.commit()
        flash('New product created', 'success')
        return redirect(url_for('admin'))
    
    # Security check, only allow admin/vendor to access this page
    if isAdmin():
        return render_template('admin/add-product.html', admin=True, form=form)
    else:
        return redirect(url_for('index'))


# View order detail decorator to enable routing to the order's details page
# A valid login session is required to access this page
# If the logged-in user is not an admin or a vendor, then redirect them to home page
@app.route('/admin/order/<order_id>')
@login_required
def order(order_id):
    # Query the order incomplete order for the current admin/vendor
    orders = get_orders_for_store(get_user_email())

    # Filter the desire order for the orders list
    order = next(filter(lambda item: item.id == int(order_id), orders), None)

    # Only display the order details if the order is valid and the user has admin role
    if isAdmin() and order :
        return render_template('admin/view-order.html', admin=True, order=order)
    else:
        return redirect(url_for('admin'))


if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', debug=True)
