from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "secretkey123"

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Creating the uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        price REAL,
        stock INTEGER,
        image TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        product_id INTEGER,
        quantity INTEGER,
        status TEXT,
        estimated_delivery TEXT,
        payment_status TEXT
    )
    """)

    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ("admin", generate_password_hash("admin123"), "Admin"))
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ("staff", generate_password_hash("staff123"), "Staff"))
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
               ("customer", generate_password_hash("customer123"), "Customer"))

    conn.commit()
    conn.close()

init_db()
# ------------------------------------


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=? AND role=?",
                       (username, role))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            session['role'] = role

            if role == "Customer":
                return redirect(url_for('products'))
            else:
                return redirect(url_for('dashboard'))
        else:
            return "Invalid Credentials"

    return render_template("login.html")


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM products")
    total_products = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM orders")
    total_orders = cursor.fetchone()[0]

    cursor.execute("SELECT SUM(stock) FROM products")
    total_stock = cursor.fetchone()[0] or 0

    conn.close()

    return render_template(
        "dashboard.html",
        username=session['username'],
        role=session['role'],
        total_products=total_products,
        total_orders=total_orders,
        total_stock=total_stock
    )

@app.route('/products')
def products():
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Get products
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()

    customer_orders = []

    # If customer, get their orders
    if session['role'] == "Customer":
        cursor.execute("""
            SELECT id, status, payment_status
            FROM orders
            WHERE username=?
        """, (session['username'],))
        customer_orders = cursor.fetchall()

    conn.close()

    return render_template(
        "products.html",
        products=products,
        role=session['role'],
        customer_orders=customer_orders
    )



@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'username' not in session or session['role'] != "Admin":
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        stock = request.form['stock']
        image = request.files['image']

        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO products (name, price, stock, image)
            VALUES (?, ?, ?, ?)
        """, (name, price, stock, filename))

        conn.commit()
        conn.close()

        return redirect(url_for('products'))

    return render_template("add_product.html")

@app.route('/delete_product/<int:product_id>')
def delete_product(product_id):
    if 'username' not in session or session['role'] != "Admin":
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Get image name first (to delete file)
    cursor.execute("SELECT image FROM products WHERE id=?", (product_id,))
    product = cursor.fetchone()

    if product and product[0]:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product[0])
        if os.path.exists(image_path):
            os.remove(image_path)

    cursor.execute("DELETE FROM products WHERE id=?", (product_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('products'))

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'username' not in session or session['role'] != "Admin":
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        stock = request.form['stock']

        cursor.execute("""
            UPDATE products
            SET name=?, price=?, stock=?
            WHERE id=?
        """, (name, price, stock, product_id))

        conn.commit()
        conn.close()
        return redirect(url_for('products'))

    cursor.execute("SELECT * FROM products WHERE id=?", (product_id,))
    product = cursor.fetchone()
    conn.close()

    return render_template("edit_product.html", product=product)

@app.route('/order/<int:product_id>', methods=['GET', 'POST'])
def order(product_id):
    if 'username' not in session or session['role'] != "Customer":
        return redirect(url_for('login'))

    if request.method == 'POST':
        quantity = int(request.form['quantity'])

        estimated_date = (datetime.now() + timedelta(days=3)).strftime("%Y-%m-%d")

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO orders (username, product_id, quantity, status, estimated_delivery, payment_status)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (session['username'], product_id, quantity, "Pending", estimated_date, "Unpaid"))

        conn.commit()
        conn.close()

        return redirect(url_for('products'))

    return render_template("place_order.html", product_id=product_id)

@app.route('/orders')
def view_orders():
    if 'username' not in session or session['role'] not in ["Admin", "Staff"]:
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT orders.id, orders.username, products.name,
               orders.quantity, orders.status,
               orders.estimated_delivery, orders.payment_status
        FROM orders
        JOIN products ON orders.product_id = products.id
    """)

    orders = cursor.fetchall()
    conn.close()

    return render_template("orders.html", orders=orders)

@app.route('/update_order/<int:order_id>/<status>')
def update_order(order_id, status):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT product_id, quantity, status, payment_status FROM orders WHERE id=?",
        (order_id,)
    )
    order = cursor.fetchone()

    if not order:
        conn.close()
        return redirect(url_for('view_orders'))

    product_id, quantity, current_status, payment_status = order
    role = session['role']

    # ADMIN
    if role == "Admin":

        if status == "Approved" and current_status == "Pending":

            cursor.execute("SELECT stock FROM products WHERE id=?", (product_id,))
            stock = cursor.fetchone()[0]

            if stock >= quantity:
                new_stock = stock - quantity
                cursor.execute("UPDATE products SET stock=? WHERE id=?", (new_stock, product_id))
                cursor.execute("UPDATE orders SET status=? WHERE id=?", ("Approved", order_id))
            else:
                conn.close()
                return "Insufficient stock"

        elif status == "Rejected" and current_status == "Pending":
            cursor.execute("UPDATE orders SET status=? WHERE id=?", ("Rejected", order_id))

    # STAFF
    elif role == "Staff":

        if status == "Processing" and current_status == "Approved":
            cursor.execute("UPDATE orders SET status=? WHERE id=?", ("Processing", order_id))

        elif status == "Shipped" and current_status == "Processing":
            cursor.execute("UPDATE orders SET status=? WHERE id=?", ("Shipped", order_id))

        elif status == "Delivered" and current_status == "Shipped":
            cursor.execute("UPDATE orders SET status=? WHERE id=?", ("Delivered", order_id))

    conn.commit()
    conn.close()

    return redirect(url_for('view_orders'))

@app.route('/pay/<int:order_id>')
def pay_order(order_id):
    if 'username' not in session or session['role'] != "Customer":
        return redirect(url_for('login'))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Ensure this order belongs to this customer
    cursor.execute("SELECT username, payment_status FROM orders WHERE id=?", (order_id,))
    order = cursor.fetchone()

    if not order:
        conn.close()
        return redirect(url_for('products'))

    order_username, payment_status = order

    if order_username != session['username']:
        conn.close()
        return redirect(url_for('products'))

    if payment_status == "Paid":
        conn.close()
        return redirect(url_for('products'))

    cursor.execute("UPDATE orders SET payment_status=? WHERE id=?", ("Paid", order_id))

    conn.commit()
    conn.close()

    return redirect(url_for('products'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run()