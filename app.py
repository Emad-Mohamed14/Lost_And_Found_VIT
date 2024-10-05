from flask import Flask, request, redirect, render_template, session, url_for, flash
from flask_mysqldb import MySQL
import os
import bcrypt
from werkzeug.utils import secure_filename
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure file upload
UPLOAD_FOLDER = 'static/uploads'  # Folder to save uploaded product images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

logging.basicConfig(filename='check.log',  # Specify the log file
                    level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

logging.debug("Logging is working!")

# MySQL configurations
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = "tsee12345"
app.config['MYSQL_DB'] = "lost_and_found"

mysql = MySQL(app)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_db_connection():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return True
    except Exception as e:
        logging.error(f"Database connection error: {str(e)}")
        return False

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Collecting form data
        reg = request.form['reg']
        student_name = request.form['student_name']
        student_type = request.form['student_type']
        phone = request.form['phone']
        email = request.form['email']
        address = request.form['address']
        password = request.form['password'].encode('utf-8')  # Encode password for hashing
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())  # Hash the password
        
        try:
            # Insert user into the database
            cur = mysql.connection.cursor()
            cur.execute('INSERT INTO users (reg, student_name, student_type, phone, email, address, password1) VALUES (%s, %s, %s, %s, %s, %s, %s)', 
                        (reg, student_name, student_type, phone, email, address, hashed_password))
            mysql.connection.commit()
            cur.close()
        except Exception as e:
            app.logger.error(f"Error inserting into database: {e}")
            return "Error occurred", 500
        
        return redirect(url_for('login'))  # Redirect to login after signup

    return render_template('signup.html')  # Render signup form

@app.route('/login', methods=['GET', 'POST'])
def login():
    logging.debug("Login route accessed.")

    if request.method == 'POST':
        logging.debug("POST request detected.")
        reg = request.form['reg']
        password = request.form['password']
        logging.debug(f"Form submitted with reg: {reg}")

        try:
            cur = mysql.connection.cursor()
            cur.execute('SELECT * FROM users WHERE reg = %s', (reg,))
            user = cur.fetchone()
            cur.close()

            # Log result from the database
            if user:
                logging.debug(f"User found: {user}")
            else:
                logging.debug(f"No user found with reg: {reg}")

            if user and bcrypt.checkpw(password.encode('utf-8'), user[6].encode('utf-8')):
                session['user_id'] = user[0]
                logging.debug(f"User {reg} logged in successfully.")
                return redirect('/first_webpage')
            else:
                logging.warning(f"Login failed for username: {reg} - Invalid credentials")
                return "Invalid credentials", 401
            
        except Exception as e:
            logging.error(f"Error occurred during login: {str(e)}")
            return "Error occurred", 500
    
    return render_template('login.html')  # Render login form

@app.route('/post_lost', methods=['GET', 'POST'])
def post_lost():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get lost item details from form
        item_name = request.form['item_name']
        item_type = request.form['item_type']
        item_description = request.form['item_description']
        lost_date = request.form['lost_date']
        location_type = request.form['location_type']
        block_name = request.form['block_name']
        floor_no = request.form['floor_no']
        room_no = request.form['room_no']
        location_details = request.form['location_details']

        # Handle file upload for product image
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
        else:
            flash("Invalid image format. Please upload a PNG, JPG, or GIF file.", "danger")
            return redirect(url_for('report_lost'))

        try:
            cur = mysql.connection.cursor()
            # Insert product details into the database
            cur.execute('INSERT INTO lost_items (item_name, item_type, item_description, lost_date, location_type, block_name, floor_no, room_no, location_details, image_url, owner_id) '
                        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                        (item_name, item_type, item_description, lost_date, location_type, block_name, floor_no, room_no, location_details, file_path, session['user_id']))
            mysql.connection.commit()
            cur.close()
            flash('Lost item posted successfully!', 'success')
        except Exception as e:
            app.logger.error(f"Error posting Lost item: {e}")
            return "Error occurred", 500
        
        return redirect(url_for('first_webpage'))

    return render_template('post_lost.html')

@app.route('/post_found', methods=['GET', 'POST'])
def post_found():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get lost item details from form
        item_name = request.form['item_name']
        item_type = request.form['item_type']
        item_description = request.form['item_description']
        found_date = request.form['found_date']
        location_type = request.form['location_type']
        block_name = request.form['block_name']
        floor_no = request.form['floor_no']
        room_no = request.form['room_no']
        location_details = request.form['location_details']

        # Handle file upload for product image
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
        else:
            flash("Invalid image format. Please upload a PNG, JPG, or GIF file.", "danger")
            return redirect(url_for('report_found'))

        try:
            cur = mysql.connection.cursor()
            # Insert product details into the database
            cur.execute('INSERT INTO found_items (item_name, item_type, item_description, found_date, location_type, block_name, floor_no, room_no, location_details, image_url, owner_id) '
                        'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                        (item_name, item_type, item_description, found_date, location_type, block_name, floor_no, room_no, location_details, file_path, session['user_id']))
            mysql.connection.commit()
            cur.close()
            flash('Found item posted successfully!', 'success')
        except Exception as e:
            app.logger.error(f"Error posting Found item: {e}")
            return "Error occurred", 500
        
        return redirect(url_for('first_webpage'))

    return render_template('post_found.html')

@app.route('/user_profile', methods=['GET'])
def user_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    # Fetch user information and the count of products from the database
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT reg, student_name, student_type, phone, email, address, COUNT(found_items.id) as found_items_count
        FROM users 
        LEFT JOIN found_items ON users.reg = found_items.owner_id 
        WHERE users.reg = %s 
        GROUP BY users.reg
    """, (user_id,))
    user_info = cur.fetchone()
    
    cur.close()
    
    if user_info:
        reg, student_name, student_type, phone, email, address, found_items_count = user_info
    else:
        reg = student_name = student_type = phone = email = address = found_items_count = None

    return render_template('user_profile.html', 
                           reg=reg,
                           student_name=student_name, 
                           student_type=student_type, 
                           phone=phone, 
                           email=email, 
                           address=address, 
                           found_items_count=found_items_count)

@app.route('/product_details/<int:id>', methods=['GET', 'POST'])
def product_details(id):
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM found_items LEFT JOIN users on found_items.owner_id=users.reg WHERE id = %s', (id,))
    found = cur.fetchone()
    cur.close()

    if found:
        return render_template('product_details.html', found=found)
    else:
        return "Product not found", 404
    
@app.route('/product_details2/<int:id>', methods=['GET', 'POST'])
def product_details2(id):
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM lost_items LEFT JOIN users on lost_items.owner_id=users.reg WHERE id = %s', (id,))
    found = cur.fetchone()
    cur.close()

    if found:
        return render_template('product_details2.html', found=found)
    else:
        return "Product not found", 404

@app.route('/my_products')
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    try:
        # Query to get products posted by the logged-in user
        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM found_items WHERE owner_id = %s', (user_id,))
        user_products = cur.fetchall()
        cur.close()

        return render_template('my_products.html', products=user_products)

    except Exception as e:
        logging.error(f"Error fetching products: {e}")
        return "Error occurred", 500

@app.route('/items_found', methods=['GET','POST'])
def items_found():
    if 'user_id' not in session:  # Check if user is not logged in
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM found_items LEFT JOIN users on found_items.owner_id=users.reg")  # Adjust the query as needed
    found = cur.fetchall()  # Get all products
    cur.close()
    return render_template('items_found.html', found=found)

@app.route('/items_lost', methods=['GET','POST'])
def items_lost():
    if 'user_id' not in session:  # Check if user is not logged in
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM lost_items LEFT JOIN users on lost_items.owner_id=users.reg")  # Adjust the query as needed
    lost = cur.fetchall()  # Get all products
    cur.close()
    return render_template('items_lost.html', lost=lost)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # Clear session
    return redirect(url_for('login'))  # Redirect to login page

@app.route('/first_webpage')
def first_webpage():
    if 'user_id' not in session:  # Check if user is not logged in
        return redirect(url_for('login'))
    return render_template('first_webpage.html')

if __name__ == '__main__':
    app.run(debug=True)
