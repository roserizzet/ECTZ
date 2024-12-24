# import streamlit as st
# import sqlite3
# import hashlib
# import time
# from io import BytesIO
# from PIL import Image
# import smtplib
# import bcrypt

# def hash_password(password):
#     return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# # Database Utility Functions
# def get_connection():
#     return sqlite3.connect("marketplace.db", check_same_thread=False)

# def execute_query(query, params=()):
#     with get_connection() as conn:
#         c = conn.cursor()
#         c.execute(query, params)
#         conn.commit()

# def fetch_all(query, params=()):
#     with get_connection() as conn:
#         c = conn.cursor()
#         c.execute(query, params)
#         return c.fetchall()

# def fetch_one(query, params=()):
#     with get_connection() as conn:
#         c = conn.cursor()
#         c.execute(query, params)
#         return c.fetchone()

# # Utility Functions
# def hash_password(password):
#     return hashlib.sha256(password.encode()).hexdigest()

# def verify_credentials(username, password):
#     query = "SELECT * FROM users WHERE username=? AND password=?"
#     return fetch_one(query, (username, hash_password(password)))

# def is_verified(username):
#     query = "SELECT verified FROM users WHERE username=?"
#     result = fetch_one(query, (username,))
#     return result and result[0]

# def send_verification_email(seller_name, seller_email):
#     try:
#         sender_email = "your_email@example.com"
#         sender_password = "your_password"
#         subject = "Verification Approved"
#         message = f"Dear {seller_name},\n\nYour seller account has been verified! You can now list products.\n\nBest regards,\nMarketplace Admin"
#         email_message = f"Subject: {subject}\n\n{message}"

#         with smtplib.SMTP("smtp.gmail.com", 587) as server:
#             server.starttls()
#             server.login(sender_email, sender_password)
#             server.sendmail(sender_email, seller_email, email_message)
#         return True
#     except Exception as e:
#         st.error(f"Error sending email: {e}")
#         return False

# # Authentication Pages
# def sign_up():
#     st.subheader("Sign Up")
#     username = st.text_input("Username")
#     email = st.text_input("Email")
#     password = st.text_input("Password", type="password")
#     role = st.selectbox("Role", ["user", "admin"])
#     if st.button("Sign Up"):
#         existing_user = fetch_one("SELECT username FROM users WHERE username=?", (username,))
#         if existing_user:
#             st.error("Username already exists.")
#         else:
#             execute_query("INSERT INTO users (username, email, password, role, verified) VALUES (?, ?, ?, ?, ?)",
#                           (username, email, password, role, 0 if role == "user" else 1))
#             st.success("Sign-up successful! You can now log in.")
#             st.experimental_rerun()  # Redirect to the login screen after sign-up


# def login():
#     st.subheader("Login")
#     username = st.text_input("Username")
#     password = st.text_input("Password", type="password")
#     if st.button("Login"):
#         user = fetch_one("SELECT username, password, role FROM users WHERE username=?", (username,))
#         if user and user[1] == password:
#             st.session_state.logged_in_user = user[0]
#             st.session_state.user_role = user[2]
#             st.success(f"Logged in as {user[2]}!")
#             st.experimental_rerun()  # Refresh the app to load the main navigation
#         else:
#             st.error("Invalid username or password.")


# # App Initialization
# def initialize_database():
#     execute_query('''CREATE TABLE IF NOT EXISTS users (
#         username TEXT PRIMARY KEY,
#         email TEXT UNIQUE,
#         password TEXT,
#         role TEXT,
#         verified BOOLEAN
#     )''')
#     execute_query('''CREATE TABLE IF NOT EXISTS products (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         name TEXT,
#         price REAL,
#         description TEXT,
#         category TEXT,
#         city TEXT,
#         seller TEXT,
#         image BLOB
#     )''')
#     execute_query('''CREATE TABLE IF NOT EXISTS messages (
#         id INTEGER PRIMARY KEY AUTOINCREMENT,
#         sender TEXT,
#         receiver TEXT,
#         message TEXT,
#         timestamp TEXT
#     )''')
#     # Create admin user
#     try:
#         hashed_pw = hash_password("admin123")
#         execute_query("INSERT INTO users (username, email, password, role, verified) VALUES (?, ?, ?, ?, ?)",
#                       ("admin", "admin@example.com", hashed_pw, "admin", True))
#     except sqlite3.IntegrityError:
#         pass

# # Run the Initialization
# initialize_database()

# # Main App
# if "logged_in_user" not in st.session_state:
#     st.session_state.logged_in_user = None
#     st.session_state.user_role = None

# if st.session_state.logged_in_user:
#     # Navigation
#     st.sidebar.title("Navigation")
#     if st.session_state.user_role == "admin":
#         page = st.sidebar.radio("Go to", ["Admin Panel", "Logout"], key="admin_nav")
#     else:
#         page = st.sidebar.radio("Go to", ["Home", "Add Product", "Chat", "Logout"], key="user_nav")

#     # Page Content Based on Navigation
#     if page == "Logout":
#         st.session_state.logged_in_user = None
#         st.session_state.user_role = None
#         st.success("You have been logged out.")
#         st.experimental_rerun()

#     elif page == "Admin Panel" and st.session_state.user_role == "admin":
#         st.subheader("Admin Panel - Pending Verifications")
#         pending_users = fetch_all("SELECT username, email FROM users WHERE verified=0 AND role='user'")
#         for username, email in pending_users:
#             st.write(f"Seller: {username}, Email: {email}")
#             if st.button(f"Verify {username}", key=f"verify_{username}"):
#                 execute_query("UPDATE users SET verified=1 WHERE username=?", (username,))
#                 send_verification_email(username, email)
#                 st.success(f"{username} has been verified!")

#     elif page == "Home" and st.session_state.user_role == "user":
#         st.subheader("Product Listings")
#         products = fetch_all("SELECT * FROM products")
#         for prod in products:
#             st.write(f"**{prod[1]}** - {prod[2]} TZS")

#     elif page == "Add Product" and st.session_state.user_role == "user":
#         st.subheader("Add Product")
#         name = st.text_input("Product Name")
#         price = st.number_input("Price (TZS)", min_value=0.0, step=0.1)
#         description = st.text_area("Description")
#         category = st.text_input("Category")
#         city = st.text_input("City")
#         image_file = st.file_uploader("Upload Product Image", type=["png", "jpg", "jpeg"])
#         if st.button("Add Product"):
#             if name and price and description and category and city and image_file:
#                 image = Image.open(image_file)
#                 image_bytes = BytesIO()
#                 image.save(image_bytes, format="PNG")
#                 execute_query("INSERT INTO products (name, price, description, category, city, seller, image) VALUES (?, ?, ?, ?, ?, ?, ?)",
#                               (name, price, description, category, city, st.session_state.logged_in_user, image_bytes.getvalue()))
#                 st.success("Product added successfully!")
#             else:
#                 st.error("Please fill all the fields and upload an image.")

#     elif page == "Chat" and st.session_state.user_role == "user":
#         st.subheader("Chat")
#         users = fetch_all("SELECT username FROM users WHERE username != ?", (st.session_state.logged_in_user,))
#         receiver = st.selectbox("Select User to Chat With", [u[0] for u in users])
#         message = st.text_area("Your Message")
#         if st.button("Send Message"):
#             if receiver and message:
#                 timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
#                 execute_query("INSERT INTO messages (sender, receiver, message, timestamp) VALUES (?, ?, ?, ?)",
#                               (st.session_state.logged_in_user, receiver, message, timestamp))
#                 st.success("Message sent!")
#             else:
#                 st.error("Please select a user and write a message.")

#         st.subheader("Chat History")
#         chat_history = fetch_all("SELECT sender, message, timestamp FROM messages WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) ORDER BY timestamp",
#                                  (st.session_state.logged_in_user, receiver, receiver, st.session_state.logged_in_user))
#         for sender, msg, ts in chat_history:
#             st.write(f"**{sender}**: {msg} ({ts})")

# else:
#     # Authentication Pages
#     auth_choice = st.sidebar.radio("Choose", ["Login", "Sign Up"], key="auth")
#     if auth_choice == "Login":
#         login()
#     else:
#         sign_up()
###################################################

import os
import sqlite3
import bcrypt
import streamlit as st
from PIL import Image
from io import BytesIO
import time
import base64
import pandas as pd

# Database Configuration
DB_PATH = "app.db"

# Hashing Function
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Password Verification Function
def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Execute Query Function
def execute_query(query, params=None):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        if params:
            c.execute(query, params)
        else:
            c.execute(query)
        conn.commit()
        return c.fetchall()

# Fetch all function
def fetch_all(query, params=None):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute(query, params if params else [])
        return c.fetchall()

# Initialize Database
def initialize_database():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        # Create Users Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user')),
                verified BOOLEAN NOT NULL DEFAULT 0
            )
        """)

        # Create Products Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                description TEXT,
                category TEXT,
                city TEXT,
                seller TEXT NOT NULL,
                image BLOB
            )
        """)

        # Create Messages Table
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)
        conn.commit()

        # Insert Admin User
        try:
            hashed_pw = hash_password("admin123")
            c.execute("""
                INSERT INTO users (username, email, password, role, verified) 
                VALUES (?, ?, ?, ?, ?)
            """, ("admin", "admin@example.com", hashed_pw, "admin", True))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Admin user already exists

# Login Function
def login_user(username, password):
    user = execute_query("SELECT id, username, password, role, verified FROM users WHERE username = ?", (username,))
    if user:
        db_id, db_username, db_password, role, verified = user[0]
        if verify_password(password, db_password):
            if verified:
                return {"id": db_id, "username": db_username, "role": role}
            else:
                return None  # Account not verified
    return None

# Function to save uploaded image to a local directory and return the file path
def save_uploaded_image(uploaded_file):
    if uploaded_file is not None:
        # Ensure the upload directory exists
        upload_dir = "uploaded_images"
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate the file path
        file_path = os.path.join(upload_dir, uploaded_file.name)
        
        # Save the file to the directory
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        return file_path
    return None

# Function to load image from file path and convert it to bytes
def get_image_bytes(image_path):
    image = Image.open(image_path)
    image_bytes = BytesIO()
    image.save(image_bytes, format="PNG")
    return image_bytes.getvalue()

# Function to display images from the database or uploaded files
def display_product_image(image_data):
    try:
        if isinstance(image_data, str):
            image_data = fix_base64_padding(image_data)
            image_data = base64.b64decode(image_data)
            image = Image.open(BytesIO(image_data))
        elif isinstance(image_data, bytes):
            image = Image.open(BytesIO(image_data))
        else:
            raise ValueError("Invalid image data")
        st.image(image, use_container_width=True)
    except Exception as e:
        st.error(f"Error decoding image: {e}")
        st.write(f"Raw image data: {image_data[:100]}")


# Admin Dashboard
def admin_dashboard():
    st.title("Tanzania Market place")
    st.write("Welcome, Admin!")
    
    # Fetch all products with the option to filter by category
    categories = ["All", "Electronics", "Kitchen", "Bedroom", "Vehicles"]
    selected_category = st.selectbox("Filter by Category", categories)
    
    # SQL query based on the category filter
    if selected_category == "All":
        products = execute_query("SELECT * FROM products")
    else:
        products = execute_query("SELECT * FROM products WHERE category = ?", (selected_category,))

    # Create a DataFrame for displaying products in a table format
    if products:
        product_data = []
        for product in products:
            product_data.append([product[1], product[2], product[3], product[4], product[5], product[0]])  # Add product id
            
        # Create a Pandas DataFrame
        df = pd.DataFrame(product_data, columns=["Name", "Price (TZS)", "Description", "Category", "City", "Product ID"])
        
        # Display the product table
        st.dataframe(df)

        # Adding Edit and Delete buttons for each product
        for product in products:
            product_id = product[0]
            name = product[1]
            price = product[2]
            description = product[3]
            category = product[4]
            city = product[5]
            image_data = product[6]

            # Edit Button
            if st.button(f"Edit {name}", key=f"edit_{product_id}"):
                st.session_state.product_to_edit = product_id
                st.session_state.action = "edit"  # Set an action to trigger edit logic
                st.session_state.page = "Edit Product"  # Trigger rerun by setting page to Edit Product
                break  # Exit the loop to avoid rendering multiple Edit forms

            # Delete Button
            if st.button(f"Delete {name}", key=f"delete_{product_id}"):
                # Confirm deletion
                confirm_delete = st.checkbox(f"Are you sure you want to delete {name}?")
                if confirm_delete:
                    execute_query("DELETE FROM products WHERE id = ?", (product_id,))
                    st.success(f"Product {name} deleted successfully!")
                    st.session_state.page = None  # Reset the page after deletion
                    st.experimental_rerun()

            # Display the product image
            if image_data:
                display_product_image(image_data)

    else:
        st.write("No products found.")



def user_dashboard():
    st.title("Tanzania Market place")
    st.write("Welcome to your dashboard!")
    
    # Sidebar Menu
    menu = ["Home", "Add Product", "Chat", "Logout"]
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Logout":
        st.session_state.logged_in_user = None
        st.session_state.user_role = None
        st.success("You have been logged out.")
        st.session_state.page = None

    elif choice == "Home":
        categories = ["All", "Electronics", "Kitchen", "Bedroom", "Vehicles"]
        selected_category = st.selectbox("Select Category", categories)

        st.subheader("Product Listings")

        if selected_category == "All":
            products = execute_query("SELECT * FROM products WHERE seller = ?", (st.session_state.logged_in_user,))
        else:
            products = execute_query("SELECT * FROM products WHERE seller = ? AND category = ?", 
                                      (st.session_state.logged_in_user, selected_category))

        if products:
            product_data = []
            for product in products:
                product_data.append([product[1], product[2], product[3], product[4], product[5], product[0]])

            df = pd.DataFrame(product_data, columns=["Name", "Price (TZS)", "Description", "Category", "City", "Product ID"])
            st.dataframe(df)

            # Adding Edit and Delete buttons for each product
            for product in products:
                product_id = product[0]
                name = product[1]
                price = product[2]
                description = product[3]
                category = product[4]
                city = product[5]
                image_data = product[6]

                col1, col2 = st.columns([4, 1])

                with col2:
                    if st.button(f"Edit {name}", key=f"edit_{product_id}"):
                        st.session_state.product_to_edit = product_id
                        st.session_state.action = "edit"
                        st.session_state.page = "Edit Product"
                        st.experimental_rerun()

                    if st.button(f"Delete {name}", key=f"delete_{product_id}"):
                        confirm_delete = st.checkbox(f"Are you sure you want to delete {name}?", key=f"confirm_{product_id}")
                        if confirm_delete:
                            execute_query("DELETE FROM products WHERE id = ?", (product_id,))
                            st.success(f"Product {name} deleted successfully!")
                            st.experimental_rerun()

                if image_data:
                    display_product_image(image_data)

        else:
            st.write("No products found for this category.")

    elif choice == "Add Product":
        st.subheader("Add Product")
        name = st.text_input("Product Name")
        price = st.number_input("Price (TZS)", min_value=0.0, step=0.1)
        description = st.text_area("Description")
        
        # Dropdown for selecting category
        category = st.selectbox("Category", ["Electronics", "Kitchen", "Bedroom", "Vehicles", "Clothing", "Others"])
        
        city = st.text_input("City")
        
        # Image file upload with supported formats (jpeg, jpg, png)
        image_file = st.file_uploader("Upload Product Image (PNG, JPG, JPEG only)", type=["png", "jpg", "jpeg"])

        if st.button("Add Product"):
            if name and price and description and category and city and image_file:
                if image_file.type not in ["image/png", "image/jpeg", "image/jpg"]:
                    st.error("Please upload an image in PNG, JPG, or JPEG format.")
                else:
                    image = Image.open(image_file)
                    image_bytes = BytesIO()
                    image.save(image_bytes, format=image.format)
                    image_bytes = image_bytes.getvalue()

                    execute_query("""
                        INSERT INTO products (name, price, description, category, city, seller, image) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (name, price, description, category, city, st.session_state.logged_in_user, image_bytes))

                    st.success("Product added successfully!")
            else:
                st.error("Please fill all fields and upload an image.")

    elif choice == "Chat":
        st.subheader("Chat")
        users = execute_query("SELECT username FROM users WHERE username != ?", (st.session_state.logged_in_user,))
        receiver = st.selectbox("Select User to Chat With", [u[0] for u in users])
        message = st.text_area("Your Message")
        
        if st.button("Send Message"):
            if receiver and message:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                execute_query("""
                    INSERT INTO messages (sender, receiver, message, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (st.session_state.logged_in_user, receiver, message, timestamp))
                st.success("Message sent!")
            else:
                st.error("Please select a user and write a message.")

        st.subheader("Chat History")
        chat_history = execute_query("""
            SELECT sender, message, timestamp FROM messages
            WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
            ORDER BY timestamp
        """, (st.session_state.logged_in_user, receiver, receiver, st.session_state.logged_in_user))
        
        for sender, msg, ts in chat_history:
            st.write(f"**{sender}**: {msg} ({ts})")

# Edit Product Form
if "product_to_edit" in st.session_state and st.session_state.page == "Edit Product":
    product_id = st.session_state.product_to_edit
    product = execute_query("SELECT * FROM products WHERE id = ?", (product_id,))[0]

    name = st.text_input("Product Name", product[1])
    price = st.number_input("Price (TZS)", min_value=0.0, step=0.1, value=product[2])
    description = st.text_area("Description", product[3])
    category = st.text_input("Category", product[4])
    city = st.text_input("City", product[5])
    image_file = st.file_uploader("Upload Product Image", type=["png", "jpg", "jpeg"], key="edit_image")

    if st.button("Update Product"):
        if name and price and description and category and city:
            if image_file:
                image = Image.open(image_file)
                image_bytes = BytesIO()
                image.save(image_bytes, format="PNG")
                image_bytes = image_bytes.getvalue()
            else:
                image_bytes = product[6]

            execute_query("""
                UPDATE products 
                SET name = ?, price = ?, description = ?, category = ?, city = ?, image = ? 
                WHERE id = ?
            """, (name, price, description, category, city, image_bytes, product_id))

            st.success("Product updated successfully!")
            del st.session_state.product_to_edit
            st.session_state.page = None
            st.experimental_rerun()

# Authentication Pages
def login():
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = login_user(username, password)
        if user:
            st.session_state.logged_in_user = user["username"]
            st.session_state.user_role = user["role"]
            st.success(f"Logged in as {user['username']}!")
            if user["role"] == "admin":
                admin_dashboard()
            else:
                user_dashboard()
        else:
            st.error("Invalid credentials or account not verified.")

    pass

def sign_up():
    st.subheader("Sign Up")
    username = st.text_input("Choose a Username")
    email = st.text_input("Enter Email")
    password = st.text_input("Choose a Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")


    if st.button("Sign Up"):
        if password != confirm_password:
            st.error("Passwords do not match.")
        else:
            try:
                hashed_pw = hash_password(password)
                execute_query("""
                    INSERT INTO users (username, email, password, role, verified)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, email, hashed_pw, "user", False))
                st.success("Account created successfully. Please log in.")
            except sqlite3.IntegrityError:
                st.error("Username or email already exists.")

    pass

def main_app():
     if "logged_in_user" not in st.session_state:
       st.session_state.logged_in_user = None
       st.session_state.user_role = None
     if st.session_state.logged_in_user:
         # Display pages based on user role
         if st.session_state.user_role == "admin":
             admin_dashboard()
         else:
             user_dashboard()
     else:
         # Authentication Pages (Login or Signup)
         auth_choice = st.sidebar.radio("Choose", ["Login", "Sign Up"], key="auth")
         if auth_choice == "Login":
             login()
         else:
             sign_up()
     pass

if __name__ == "__main__":
    initialize_database()
    main_app()


