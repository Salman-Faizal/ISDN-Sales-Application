from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from functools import wraps
from uuid import uuid4
from email.message import EmailMessage
import smtplib

app = Flask(__name__)
app.secret_key = "secretkey123"
LOW_STOCK_THRESHOLD = 10

UPLOAD_FOLDER = "static/uploads"
PAYMENT_PROOF_FOLDER = "static/payment_proofs"
INVOICE_FOLDER = "static/invoices"
DATABASE_PATH = "database.db"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_PAYMENT_PROOF_SIZE"] = 5 * 1024 * 1024
ALLOWED_PAYMENT_PROOF_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}

# Creating the static file directories if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PAYMENT_PROOF_FOLDER, exist_ok=True)
os.makedirs(INVOICE_FOLDER, exist_ok=True)

# ---------- DATABASE SETUP ----------
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT
    )
    """
    )

    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        price REAL,
        stock INTEGER,
        image TEXT
    )
    """
    )

    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        product_id INTEGER,
        quantity INTEGER,
        order_status TEXT DEFAULT 'pending',
        estimated_delivery TEXT,
        payment_status TEXT DEFAULT 'unpaid',
        payment_proof_url TEXT,
        payment_verified_by INTEGER,
        payment_verified_at TEXT,
        invoice_url TEXT,
        cancellation_reason TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """
    )

    cursor.execute("PRAGMA table_info(orders)")
    order_columns = [column[1] for column in cursor.fetchall()]
    migration_columns = {
        "order_status": "TEXT DEFAULT 'pending'",
        "payment_status": "TEXT DEFAULT 'unpaid'",
        "payment_proof_url": "TEXT",
        "payment_verified_by": "INTEGER",
        "payment_verified_at": "TEXT",
        "invoice_url": "TEXT",
        "cancellation_reason": "TEXT",
        "created_at": "TEXT",
    }
    for column_name, definition in migration_columns.items():
        if column_name not in order_columns:
            cursor.execute(f"ALTER TABLE orders ADD COLUMN {column_name} {definition}")

    # Backward compatibility for old column names/status styles.
    if "status" in order_columns:
        cursor.execute("UPDATE orders SET order_status = LOWER(status) WHERE status IS NOT NULL")
    cursor.execute("UPDATE orders SET payment_status = LOWER(payment_status) WHERE payment_status IS NOT NULL")
    cursor.execute("UPDATE orders SET order_status = 'pending' WHERE order_status IS NULL OR order_status = ''")
    cursor.execute("UPDATE orders SET payment_status = 'unpaid' WHERE payment_status IS NULL OR payment_status = ''")
    cursor.execute("UPDATE orders SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")

    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "Admin"),
        )
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("staff", generate_password_hash("staff123"), "Staff"),
        )
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("customer", generate_password_hash("customer123"), "Customer"),
        )

    conn.commit()
    conn.close()


init_db()
# ------------------------------------

def allowed_file(filename, allowed_extensions):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def send_email_notification(recipient, subject, body, attachment_path=None):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_sender = os.getenv("SMTP_SENDER", "no-reply@sales.local")

    if smtp_host and smtp_user and smtp_password and recipient:
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = smtp_sender
        message["To"] = recipient
        message.set_content(body)

        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, "rb") as attachment_file:
                message.add_attachment(
                    attachment_file.read(),
                    maintype="application",
                    subtype="pdf",
                    filename=os.path.basename(attachment_path),
                )

        with smtplib.SMTP(smtp_host, smtp_port) as smtp:
            smtp.starttls()
            smtp.login(smtp_user, smtp_password)
            smtp.send_message(message)
        return

    app.logger.info("Email fallback | to=%s | subject=%s", recipient, subject)


def generate_invoice_file(order_row):
    invoice_filename = f"invoice_{order_row['id']}_{uuid4().hex[:8]}.pdf"
    invoice_path = os.path.join(INVOICE_FOLDER, invoice_filename)
    total = float(order_row["quantity"]) * float(order_row["price"])

    invoice_content = f"""INVOICE

Company: ISDN Sales
Order ID: {order_row['id']}
Date: {datetime.now().strftime('%Y-%m-%d')}

Customer: {order_row['username']}
Item: {order_row['product_name']}
Quantity: {order_row['quantity']}
Unit Price: ${order_row['price']:.2f}
Total: ${total:.2f}
Payment Status: VERIFIED
Estimated Delivery: {order_row['estimated_delivery']}
"""
    with open(invoice_path, "wb") as invoice_file:
        invoice_file.write(invoice_content.encode("utf-8"))

    return invoice_path


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    
    return wrapped_view


def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("login"))
            if session.get("role") not in allowed_roles:
                if session.get("role") == "Customer":
                    return redirect(url_for("products"))
                if session.get("role") == "Staff":
                    return redirect(url_for("staff_dashboard"))
                return redirect(url_for("dashboard"))
            return view_func(*args, **kwargs)
        
        return wrapped_view
    
    return decorator


def get_staff_dashboard_summary(cursor):
    return {
        "total_orders_today": cursor.execute(
            "SELECT COUNT(*) FROM orders WHERE DATE(created_at) = DATE('now', 'localtime')"
        ).fetchone()[0],
        "pending_preparation": cursor.execute(
            "SELECT COUNT(*) FROM orders WHERE order_status='confirmed'"
        ).fetchone()[0],
        "processing": cursor.execute(
            "SELECT COUNT(*) FROM orders WHERE order_status='processing'"
        ).fetchone()[0],
        "out_for_delivery": cursor.execute(
            "SELECT COUNT(*) FROM orders WHERE order_status='delivered'"
        ).fetchone()[0],
        "cancelled": cursor.execute(
            "SELECT COUNT(*) FROM orders WHERE order_status='cancelled'"
        ).fetchone()[0],
    }


def get_staff_low_stock(cursor):
    low_stock_rows = cursor.execute(
        """
        SELECT id, name, stock
        FROM products
        WHERE stock <= ?
        ORDER BY stock ASC, id ASC
        """,
        (LOW_STOCK_THRESHOLD,),
    ).fetchall()

    return [
        {
            "product_id": row[0],
            "product_name": row[1],
            "stock": row[2],
            "threshold": LOW_STOCK_THRESHOLD,
            "status": "LOW",
        }
        for row in low_stock_rows
    ]


def get_staff_notifications(cursor):
    notification_rows = cursor.execute(
        """
        SELECT id, order_status, payment_status, created_at
        FROM orders
        WHERE order_status IN ('confirmed', 'cancelled', 'processing', 'delivered')
           OR payment_status = 'paid'
        ORDER BY datetime(created_at) DESC
        LIMIT 10
        """
    ).fetchall()

    notifications = []
    for row in notification_rows:
        order_id, order_status, payment_status, created_at = row
        message = None
        if order_status == "confirmed":
            message = "Order confirmed and ready for preparation."
        elif order_status == "cancelled":
            message = "Order was cancelled."
        elif order_status in ("processing", "delivered"):
            message = f"Order assigned for {order_status}."
        elif payment_status == "paid":
            message = "Order payment completed."

        if message:
            notifications.append({"order_id": order_id, "message": message, "timestamp": created_at})

    return notifications

@app.route("/", methods=["GET", "POST"])
def login():
    error_message = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=? AND role=?", (username, role))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session["username"] = username
            session["role"] = role

            if role == "Customer":
                return redirect(url_for("products"))
            if role == "Staff":
                return redirect(url_for("staff_dashboard"))
            return redirect(url_for("dashboard"))
        error_message = "Username or password is incorrect."

    return render_template("login.html", error_message=error_message)


@app.route("/dashboard")
@role_required("Admin")
def dashboard():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    total_products = cursor.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    total_orders = cursor.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    total_stock = cursor.execute("SELECT SUM(stock) FROM products").fetchone()[0] or 0
    total_delivered = cursor.execute("SELECT COUNT(*) FROM orders WHERE order_status='delivered'").fetchone()[0]
    out_of_stock_products = cursor.execute(
        "SELECT id, name, image FROM products WHERE stock <= 0 ORDER BY id ASC"
    ).fetchall()

    sales_rows = cursor.execute(
        """
        SELECT DATE(created_at) AS order_day, COALESCE(SUM(quantity), 0)
        FROM orders
        WHERE DATE(created_at) >= DATE('now', '-29 days')
          AND order_status NOT IN ('cancelled')
        GROUP BY DATE(created_at)
        ORDER BY order_day ASC
        """
    ).fetchall()

    sales_by_day = {row[0]: row[1] for row in sales_rows if row[0]}
    sales_labels, sales_values = [], []
    for day_offset in range(29, -1, -1):
        current_day = (datetime.now() - timedelta(days=day_offset)).strftime("%Y-%m-%d")
        sales_labels.append(current_day)
        sales_values.append(sales_by_day.get(current_day, 0))

    top_products = cursor.execute(
        """
        SELECT products.name, COALESCE(SUM(orders.quantity), 0) AS sold_quantity
        FROM orders
        JOIN products ON orders.product_id = products.id
        WHERE DATE(orders.created_at) >= DATE('now', '-29 days')
          AND orders.order_status NOT IN ('cancelled')
        GROUP BY orders.product_id, products.name
        ORDER BY sold_quantity DESC
        LIMIT 5
        """
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        total_products=total_products,
        total_orders=total_orders,
        total_stock=total_stock,
        total_delivered=total_delivered,
        out_of_stock_products=out_of_stock_products,
        sales_labels=sales_labels,
        sales_values=sales_values,
        top_product_labels=[row[0] for row in top_products],
        top_product_values=[row[1] for row in top_products],
    )

@app.route("/staff/dashboard")
@role_required("Staff")
def staff_dashboard():
    return render_template("staff_dashboard.html", username=session["username"], role=session["role"])


@app.route("/staff/dashboard/summary")
@role_required("Staff")
def staff_dashboard_summary():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    summary = get_staff_dashboard_summary(cursor)
    conn.close()
    return jsonify(summary)


@app.route("/staff/dashboard/low-stock")
@role_required("Staff")
def staff_dashboard_low_stock():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    low_stock_items = get_staff_low_stock(cursor)
    conn.close()
    return jsonify(low_stock_items)


@app.route("/staff/dashboard/notifications")
@role_required("Staff")
def staff_dashboard_notifications():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    notifications = get_staff_notifications(cursor)
    conn.close()
    return jsonify(notifications)

@app.route("/products")
def products():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    product_search = request.args.get("product_name", "").strip()

    if session["role"] == "Customer" and product_search:
        cursor.execute("SELECT * FROM products WHERE LOWER(name) LIKE ?", (f"%{product_search.lower()}%",))
    else:
        cursor.execute("SELECT * FROM products")

    products_rows = cursor.fetchall()

    customer_orders = []

    if session["role"] == "Customer":
        cursor.execute(
            """
            SELECT
                orders.id,
                orders.order_status,
                orders.payment_status,
                COALESCE(products.name, 'Product Unavailable') AS product_name,
                orders.quantity,
                (orders.quantity * COALESCE(products.price, 0)) AS total_amount,
                orders.payment_proof_url,
                orders.cancellation_reason
            FROM orders
            LEFT JOIN products ON orders.product_id = products.id
            WHERE username=?
            ORDER BY orders.id DESC
        """,
            (session["username"],),
        )
        customer_orders = cursor.fetchall()

    conn.close()

    return render_template(
        "products.html",
         products=products_rows,
        role=session["role"],
        customer_orders=customer_orders,
        product_search=product_search,
    )



@app.route("/add_product", methods=["GET", "POST"])
def add_product():
    if "username" not in session or session["role"] != "Admin":
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form["name"]
        stock = request.form["stock"]
        image = request.files.get("image")

        try:
            price = float(request.form["price"])
        except (TypeError, ValueError):
            return render_template("add_product.html", error_message="Please enter a valid price.", form_data=request.form)

        if price <= 0:
            return render_template(
                "add_product.html", error_message="Price must be greater than zero.", form_data=request.form
            )

        if not image or image.filename == "":
            return render_template(
                "add_product.html", error_message="Please upload a product image.", form_data=request.form
            )

        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO products (name, price, stock, image) VALUES (?, ?, ?, ?)", (name, price, stock, filename))

        conn.commit()
        conn.close()

        return redirect(url_for("products"))

    return render_template("add_product.html", error_message=None, form_data={})

@app.route("/delete_product/<int:product_id>")
def delete_product(product_id):
    if "username" not in session or session["role"] != "Admin":
        return redirect(url_for("dashboard"))
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    # Get image name first (to delete file)
    cursor.execute("SELECT image FROM products WHERE id=?", (product_id,))
    product = cursor.fetchone()

    if product and product[0]:
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], product[0])
        if os.path.exists(image_path):
            os.remove(image_path)

    cursor.execute("DELETE FROM products WHERE id=?", (product_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("products"))


@app.route("/edit_product/<int:product_id>", methods=["GET", "POST"])
def edit_product(product_id):
    if "username" not in session or session["role"] != "Admin":
        return redirect(url_for("dashboard"))

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    if request.method == "POST":
        name = request.form["name"]
        stock = request.form["stock"]

        try:
            price = float(request.form["price"])
        except (TypeError, ValueError):
            cursor.execute("SELECT * FROM products WHERE id=?", (product_id,))
            product = cursor.fetchone()
            conn.close()
            return render_template("edit_product.html", product=product, error_message="Please enter a valid price.", form_data=request.form)

        if price <= 0:
            cursor.execute("SELECT * FROM products WHERE id=?", (product_id,))
            product = cursor.fetchone()
            conn.close()
            return render_template("edit_product.html", product=product, error_message="Price must be greater than zero.", form_data=request.form)

        cursor.execute("UPDATE products SET name=?, price=?, stock=? WHERE id=?", (name, price, stock, product_id))

        conn.commit()
        conn.close()
        return redirect(url_for("products"))

    cursor.execute("SELECT * FROM products WHERE id=?", (product_id,))
    product = cursor.fetchone()
    conn.close()

    return render_template("edit_product.html", product=product, error_message=None, form_data={})

@app.route("/order/<int:product_id>", methods=["GET", "POST"])
def order(product_id):
    if "username" not in session or session["role"] != "Customer":
        return redirect(url_for("login"))

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name, stock FROM products WHERE id=?", (product_id,))
    product = cursor.fetchone()

    if not product:
        conn.close()
        return redirect(url_for("products"))

    product_name, stock = product
    error = None

    if request.method == "POST":
        quantity = int(request.form["quantity"])
        if quantity <= 0:
            conn.close()
            return "Quantity must be greater than zero"

        if quantity > stock:
            error = f"Only {stock} item(s) available for {product_name}."
            conn.close()
            return render_template("place_order.html", product_id=product_id, product_name=product_name, stock=stock, error=error)

        estimated_date = (datetime.now() + timedelta(days=3)).strftime("%Y-%m-%d")
        cursor.execute("UPDATE products SET stock = stock - ? WHERE id=?", (quantity, product_id))

        cursor.execute(
            """
            INSERT INTO orders (username, product_id, quantity, order_status, estimated_delivery, payment_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (session["username"], product_id, quantity, "pending", estimated_date, "unpaid"),
        )

        conn.commit()
        conn.close()

        return redirect(url_for("products"))

    conn.close()
    return render_template("place_order.html", product_id=product_id, product_name=product_name, stock=stock, error=error)


@app.route('/orders')
def view_orders():
    if 'username' not in session or session['role'] not in ["Admin", "Staff"]:
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    order_search = request.args.get('order_id', '').strip()
    query = """
        SELECT orders.id, orders.username, products.name,
               orders.quantity, orders.order_status,
               orders.estimated_delivery, orders.payment_status,
               orders.payment_proof_url, orders.cancellation_reason
        FROM orders
        JOIN products ON orders.product_id = products.id
    """
    params = []

    if order_search:
        if order_search.isdigit():
            query += " WHERE orders.id = ?"
            params.append(int(order_search))
        else:
            query += " WHERE 1 = 0"

    cursor.execute(query, params)

    orders_rows = cursor.fetchall()
    conn.close()

    return render_template("orders.html", orders=orders_rows, order_search=order_search, role=session["role"])

@app.route('/update_order/<int:order_id>', methods=['POST'])
def update_order(order_id):
    if 'username' not in session or session['role'] not in ["Admin", "Staff"]:
        return redirect(url_for('login'))

    status = request.form.get("status", "").strip().lower()
    if not status:
        return redirect(url_for('view_orders'))

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT order_status, payment_status FROM orders WHERE id=?", (order_id,))
    order = cursor.fetchone()

    if not order:
        conn.close()
        return redirect(url_for('view_orders'))

    current_status, payment_status = order
    role = session["role"]

    if current_status == "cancelled":
        conn.close()
        return redirect(url_for("view_orders"))

    allowed_status_updates = {
        "Admin": {"pending": ["processing", "confirmed", "cancelled"], "confirmed": ["processing"]},
        "Staff": {"confirmed": ["processing"], "processing": ["delivered"]},
    }

    if role == "Staff" and payment_status != "paid":
        conn.close()
        return redirect(url_for("view_orders"))

    if status in allowed_status_updates.get(role, {}).get(current_status, []):
        cursor.execute("UPDATE orders SET order_status=? WHERE id=?", (status, order_id))

    conn.commit()
    conn.close()

    return redirect(url_for('view_orders'))

@app.route('/cancel_order/<int:order_id>')
def cancel_order(order_id):
    if 'username' not in session or session['role'] != "Customer":
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT username, product_id, quantity, order_status, payment_status FROM orders WHERE id=?", (order_id,)
    )
    order = cursor.fetchone()

    if not order:
        conn.close()
        return redirect(url_for('products'))

    order_username, product_id, quantity, status = order
    order_username, product_id, quantity, order_status, payment_status = order
    if order_username != session["username"]:
        conn.close()
        return redirect(url_for('products'))

    if order_status == "pending" and payment_status in ("unpaid", "failed"):
        cursor.execute(
            "UPDATE orders SET order_status='cancelled', cancellation_reason='Cancelled by customer.' WHERE id=?",
            (order_id,),
        )
        cursor.execute("UPDATE products SET stock = stock + ? WHERE id=?", (quantity, product_id))
        conn.commit()

    conn.close()
    return redirect(url_for('products'))

@app.route("/orders/<int:order_id>/upload-payment-proof", methods=["POST"])
def upload_payment_proof(order_id):
    if "username" not in session or session["role"] != "Customer":
        return redirect(url_for("login"))

    # Data Validation for pyament proof file
    proof = request.files.get("payment_proof")
    if not proof or proof.filename == "":
        return jsonify({"error": "Payment proof is required."}), 400

    if not allowed_file(proof.filename, ALLOWED_PAYMENT_PROOF_EXTENSIONS):
        return jsonify({"error": "Invalid file type. Only PNG/JPG/JPEG/PDF are allowed."}), 400

    proof.seek(0, os.SEEK_END)
    file_size = proof.tell()
    proof.seek(0)
    if file_size > app.config["MAX_PAYMENT_PROOF_SIZE"]:
        return jsonify({"error": "File is too large. Maximum size is 5MB."}), 400

    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, payment_status, order_status FROM orders WHERE id=?",
        (order_id,),
    )
    order = cursor.fetchone()

    if not order:
        conn.close()
        return jsonify({"error": "Order not found."}), 404

    order_owner, payment_status, order_status = order
    if order_owner != session["username"]:
        conn.close()
        return jsonify({"error": "Forbidden."}), 403


    if payment_status == "paid":
        conn.close()
        return jsonify({"error": "Payment already approved for this order."}), 409

    if order_status == "cancelled" and payment_status != "failed":
        conn.close()
        return jsonify({"error": "Cannot upload proof for cancelled order."}), 409

    filename = secure_filename(f"{order_id}_{uuid4().hex}_{proof.filename}")
    file_path = os.path.join(PAYMENT_PROOF_FOLDER, filename)
    proof.save(file_path)

    cursor.execute(
        """
        UPDATE orders
        SET payment_proof_url=?, payment_status='pending', order_status='pending',
            cancellation_reason=NULL, payment_verified_by=NULL, payment_verified_at=NULL
        WHERE id=?
        """,
        (filename, order_id),
    )

    conn.commit()
    conn.close()

    return jsonify(
        {
            "message": "Your order has been placed. Payment verification is pending. A confirmation email will be sent once the payment is verified.",
            "payment_status": "pending",
        }
    )


@app.route("/admin/orders/<int:order_id>/payment-proof")
@role_required("Admin")
def get_payment_proof(order_id):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT payment_proof_url FROM orders WHERE id=?", (order_id,))
    row = cursor.fetchone()
    conn.close()

    if not row or not row[0]:
        return jsonify({"error": "Payment proof not found."}), 404

    path = os.path.join(PAYMENT_PROOF_FOLDER, row[0])
    if not os.path.exists(path):
        return jsonify({"error": "Payment proof not found."}), 404

    return send_file(path)


def process_payment_decision(order_id, decision, admin_username, reason=None):
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        cursor.execute("BEGIN")
        order = cursor.execute(
            """
            SELECT o.*, p.name AS product_name, p.price
            FROM orders o
            JOIN products p ON p.id = o.product_id
            WHERE o.id=?
            """,
            (order_id,),
        ).fetchone()

        if not order:
            conn.rollback()
            return {"error": "Order not found."}, 404

        if not order["payment_proof_url"]:
            conn.rollback()
            return {"error": "Payment proof is missing."}, 400

        if order["payment_status"] in ("paid", "failed"):
            conn.rollback()
            return {"error": f"Payment already processed as {order['payment_status']}."}, 409

        admin = cursor.execute("SELECT id FROM users WHERE username=?", (admin_username,)).fetchone()
        admin_id = admin["id"] if admin else None

        if decision == "approve":
            invoice_path = generate_invoice_file(order)
            invoice_filename = os.path.basename(invoice_path)
            cursor.execute(
                """
                UPDATE orders
                SET payment_status='paid', order_status='confirmed', payment_verified_by=?,
                    payment_verified_at=?, invoice_url=?, cancellation_reason=NULL
                WHERE id=?
                """,
                (admin_id, datetime.now().isoformat(timespec="seconds"), invoice_filename, order_id),
            )

            body = (
                f"Order ID: {order_id}\n"
                f"Item: {order['product_name']}\n"
                f"Quantity: {order['quantity']}\n"
                f"Total amount: ${float(order['quantity']) * float(order['price']):.2f}\n"
                "Payment status: Verified\n"
                f"Estimated delivery date: {order['estimated_delivery']}"
            )
            send_email_notification(order["username"], "Payment Verified – Order Confirmed", body, invoice_path)

        elif decision == "reject":
            cancellation_reason = reason or "Payment proof could not be verified."
            cursor.execute(
                """
                UPDATE orders
                SET payment_status='failed', order_status='cancelled', cancellation_reason=?,
                    payment_verified_by=?, payment_verified_at=?
                WHERE id=?
                """,
                (cancellation_reason, admin_id, datetime.now().isoformat(timespec="seconds"), order_id),
            )
            cursor.execute("UPDATE products SET stock = stock + ? WHERE id=?", (order["quantity"], order["product_id"]))

            body = (
                f"Order ID: {order_id}\n"
                f"Reason for rejection: {cancellation_reason}\n"
                "Next steps: Please upload a valid payment proof and place a new order if needed."
            )
            send_email_notification(order["username"], "Payment Rejected – Order Cancelled", body)
        else:
            conn.rollback()
            return {"error": "Invalid decision."}, 400

        conn.commit()
        return {"message": f"Payment {decision}d successfully."}, 200
    except Exception as exc:
        conn.rollback()
        app.logger.exception("Failed to process payment decision: %s", exc)
        return {"error": "Payment processing failed."}, 500
    finally:
        conn.close()


@app.route("/admin/orders/<int:order_id>/approve-payment", methods=["PUT"])
@role_required("Admin")
def approve_payment(order_id):
    payload, status_code = process_payment_decision(order_id, "approve", session["username"])
    return jsonify(payload), status_code


@app.route("/admin/orders/<int:order_id>/reject-payment", methods=["PUT"])
@role_required("Admin")
def reject_payment(order_id):
    request_data = request.get_json(silent=True) or {}
    payload, status_code = process_payment_decision(
        order_id,
        "reject",
        session["username"],
        reason=request_data.get("reason"),
    )
    return jsonify(payload), status_code

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run()