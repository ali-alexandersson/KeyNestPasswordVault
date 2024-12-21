import secrets
import string
import os
import mysql.connector
import customtkinter
import bcrypt
from cryptography.fernet import Fernet
from tkinter import ttk
from tkinter import PhotoImage
from dotenv import load_dotenv
from contextlib import contextmanager
from datetime import datetime

# Load environment variables
load_dotenv()

# Retrieve database credentials from .env
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME')
}

# Retrieve keys from .env
DECRYPTION_KEY = os.getenv('DECRYPTION_KEY')
ENCRYPTED_MASTER_KEY = os.getenv('ENCRYPTED_MASTER_KEY')

# Ensure all environment variables are set
required_env_vars = ["DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME", "DECRYPTION_KEY", "ENCRYPTED_MASTER_KEY"]
for var in required_env_vars:
    if not os.getenv(var):
        raise ValueError(f"Missing environment variable: {var}")

# Convert encryption keys from strings to bytes
if not DECRYPTION_KEY or not ENCRYPTED_MASTER_KEY:
    raise ValueError("Missing one or more encryption keys in environment variables.")

decryption_key = DECRYPTION_KEY.encode()
encrypted_master_key = ENCRYPTED_MASTER_KEY.encode()

# Decrypt the master key using the decryption key
cipher_suite = Fernet(decryption_key)
master_key = cipher_suite.decrypt(encrypted_master_key)  # Decrypt the master key
cipher_suite_for_data = Fernet(master_key)  # Cipher suite for encrypting/decrypting user data

# Utility Functions
@contextmanager
def get_db_connection():
    """
    A reusable function to manage database connections.
    Automatically closes the connection after use.
    """
    conn = mysql.connector.connect(**DB_CONFIG)
    try:
        yield conn
    finally:
        conn.close()

def generate_random_password(length=12, exclude_special=False):
    """
    Generate a random password based on length and whether special characters are excluded.

    Args:
        length (int): Desired password length.
        exclude_special (bool): Whether to exclude special characters.

    Returns:
        str: A randomly generated password.
    """
    # Define the pool of allowed characters
    allowed_characters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    if not exclude_special:  # Add special characters if not excluded
        allowed_characters += "!@#$%^&*()_+-=[]{}|:,.<>?/~`"

    # Exclude specific characters
    excluded_characters = {";", "'", "--", "\"", "\\"}
    allowed_characters = ''.join(c for c in allowed_characters if c not in excluded_characters)

    # Generate the password
    password = ''.join(secrets.choice(allowed_characters) for _ in range(length))
    return password

# Define application
app = customtkinter.CTk()
app.geometry("600x400")
app.title("KeyNest")

# Define frames
initial_frame = customtkinter.CTkFrame(master=app)
login_frame = customtkinter.CTkFrame(master=app)
create_user_frame = customtkinter.CTkFrame(master=app)

def setup_initial_screen():
    app.geometry("450x254")  # Set the size of the initial window

    # Clear the existing frame and set up the background
    clear_frame(initial_frame)
    initial_frame.pack(fill="both", expand=True)

    # Create a Canvas for adding a background image
    canvas = customtkinter.CTkCanvas(master=initial_frame, width=450, height=300)
    canvas.pack(fill="both", expand=True)

    # Load the background image from root folder
    background_image = PhotoImage(file="background.png")
    canvas.create_image(0, 0, image=background_image, anchor="nw")

    # Personalized text on top of the image
    canvas.create_text(225, 50, text="KeyNest Prototype", font=("Arial", 20, "bold"), fill="white")

    # Buttons on top of the image
    login_button = customtkinter.CTkButton(master=canvas, text="Login", command=setup_login_screen)
    canvas.create_window(225, 150, window=login_button)  # Positioning the button at the center

    create_user_button = customtkinter.CTkButton(master=canvas, text="Create New User", command=setup_create_user_screen)
    canvas.create_window(225, 200, window=create_user_button)  # Positioning the button below the login button

    # Store the image reference to avoid garbage collection
    canvas.image = background_image

def setup_login_screen():
    app.geometry("400x350") # Set the size of the login window
    clear_frame(initial_frame)
    login_frame.pack(pady=20, padx=10, fill="both", expand=True)

    username_label = customtkinter.CTkLabel(master=login_frame, text="Username:")
    username_label.pack(pady=5, padx=10)
    username_entry = customtkinter.CTkEntry(master=login_frame, placeholder_text="Enter username")
    username_entry.pack(pady=5, padx=10)

    password_label = customtkinter.CTkLabel(master=login_frame, text="Master Password:")
    password_label.pack(pady=5, padx=10)
    password_entry = customtkinter.CTkEntry(master=login_frame, placeholder_text="Enter master password", show="*")
    password_entry.pack(pady=5, padx=10)

    feedback_label = customtkinter.CTkLabel(master=login_frame, text="")
    feedback_label.pack(pady=10)

    login_button = customtkinter.CTkButton(master=login_frame, text="Login", command=lambda: handle_login(username_entry.get(), password_entry.get(), feedback_label))
    login_button.pack(pady=10)

def setup_create_user_screen():
    clear_frame(initial_frame)
    
    app.geometry("600x500")  # Set the size of the create user window
    
    create_user_frame.pack(pady=20, padx=10, fill="both", expand=True)

    username_label = customtkinter.CTkLabel(master=create_user_frame, text="Username:")
    username_label.pack(pady=5, padx=10)
    username_entry = customtkinter.CTkEntry(master=create_user_frame, placeholder_text="Enter username")
    username_entry.pack(pady=5, padx=10)

    password_label = customtkinter.CTkLabel(master=create_user_frame, text="Master Password:")
    password_label.pack(pady=5, padx=10)
    password_entry = customtkinter.CTkEntry(master=create_user_frame, placeholder_text="Enter master password", show="*")
    password_entry.pack(pady=5, padx=10)

    confirm_password_label = customtkinter.CTkLabel(master=create_user_frame, text="Confirm Master Password:")
    confirm_password_label.pack(pady=5, padx=10)
    confirm_password_entry = customtkinter.CTkEntry(master=create_user_frame, placeholder_text="Confirm master password", show="*")
    confirm_password_entry.pack(pady=5, padx=10)

    # Feedback label
    feedback_label = customtkinter.CTkLabel(master=create_user_frame, text="")
    feedback_label.pack(pady=10)

    # Password requirements message
    password_requirements = customtkinter.CTkLabel(
        master=create_user_frame,
        text="Password Requirements:\n- At least 10 characters\n- One uppercase letter\n- One lowercase letter\n- One symbol",
        text_color="gray",
        justify="left"
    )
    password_requirements.pack(pady=10)

    # Create user button
    create_user_button = customtkinter.CTkButton(
        master=create_user_frame,
        text="Create",
        command=lambda: create_new_user(username_entry.get(), password_entry.get(), confirm_password_entry.get(), feedback_label)
    )
    create_user_button.pack(pady=10)


def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()
    frame.pack_forget()

def create_new_user(username, password, confirm_password, feedback_label):
    if not username or not password or not confirm_password:
        feedback_label.configure(text="Username, password, and confirmation cannot be empty.", text_color="red")
        return

    # Validate username (Can contain only lowercase letters + numbers are allowed)
    if not username.islower() or " " in username or not username.isalnum():
        feedback_label.configure(text="Username must contain only lowercase letters and numbers, without spaces.", text_color="red")
        return

    # Define excluded characters for SQL injection prevention
    excluded_characters = {";", "'", "--", "\"", "\\"}

    # Check for excluded characters in username
    if any(char in username for char in excluded_characters):
        feedback_label.configure(text="Username contains invalid characters.", text_color="red")
        return

    # Validate password
    if len(password) < 10:
        feedback_label.configure(text="Password must be at least 10 characters long.", text_color="red")
        return
    if not any(c.islower() for c in password):
        feedback_label.configure(text="Password must include at least one lowercase letter.", text_color="red")
        return
    if not any(c.isupper() for c in password):
        feedback_label.configure(text="Password must include at least one uppercase letter.", text_color="red")
        return
    if not any(c in "!@#$%^&*()_+-=[]{}|:,.<>?/~`" for c in password):
        feedback_label.configure(text="Password must include at least one symbol.", text_color="red")
        return
    if " " in password:  # Check for spaces in the password
        feedback_label.configure(text="Password cannot contain spaces.", text_color="red")
        return

    # Check for excluded characters in password
    if any(char in password for char in excluded_characters):
        feedback_label.configure(text="Password contains invalid characters.", text_color="red")
        return

    # Check if passwords match
    if password != confirm_password:
        feedback_label.configure(text="Passwords do not match.", text_color="red")
        return

    with get_db_connection() as conn:
        cursor = conn.cursor()

        try:
            # Step 1: Hash the password using bcrypt
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

            # Step 2: Generate a new master key for the user
            new_user_master_key = Fernet.generate_key()
            local_encrypted_master_key = cipher_suite.encrypt(new_user_master_key).decode()

            # Step 3: Store the hashed password and encrypted master key in the database
            cursor.execute(
                "INSERT INTO users (username, master_password, encrypted_master_key) VALUES (%s, %s, %s)",
                (username, hashed_password, local_encrypted_master_key)
            )
            conn.commit()

            new_user_id = cursor.lastrowid  # Capture the new user ID
            feedback_label.configure(text="User created successfully. Logging you in...", text_color="green")

            # Delay of 2 seconds before transitioning to the main screen
            feedback_label.after(2000, lambda: [clear_frame(create_user_frame), display_main_screen(new_user_id)])

        except mysql.connector.Error as e:
            feedback_label.configure(text="A database error occurred. Please try again.", text_color="red")
            print(f"Database error: {e}")  # Log error for debugging

 
def display_main_screen(user_id):
    app.geometry("350x250")  # Set the size of the main screen window
    clear_frame(login_frame)  # Clear the login frame

    # Create the main screen frame
    main_frame = customtkinter.CTkFrame(master=app)
    main_frame.pack(pady=20, padx=10, fill="both", expand=True)

    # Button to view passwords
    view_passwords_button = customtkinter.CTkButton(master=main_frame, text="View Passwords", command=lambda: display_passwords(user_id))
    view_passwords_button.pack(pady=10)

    # Button to add a new password
    add_password_button = customtkinter.CTkButton(master=main_frame, text="Add New Password", command=lambda: add_new_password(user_id))
    add_password_button.pack(pady=10)

def handle_login(username, password, feedback_label):
    if not username or not password:
        feedback_label.configure(text="Both username and master password are required!", text_color="red")
        return

    with get_db_connection() as conn:
        cursor = conn.cursor()

        try:
            # Step 1: Check if the user exists
            cursor.execute("SELECT id, master_password, encrypted_master_key FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user:
                user_id, stored_hashed_password, user_encrypted_master_key = user

                # Step 2: Verify the password using bcrypt
                if bcrypt.checkpw(password.encode(), stored_hashed_password.encode()):
                    # Step 3: Decrypt the user's personal master key
                    cipher_suite.decrypt(user_encrypted_master_key.encode())

                    # Display success message and delay before transitioning
                    feedback_label.configure(text="Login successful... Entering the vault", text_color="green")
                    feedback_label.after(2000, lambda: display_main_screen(user_id))  # 2-second delay
                else:
                    feedback_label.configure(text="Incorrect master password.", text_color="red")
            else:
                feedback_label.configure(text="User does not exist.", text_color="red")
        except mysql.connector.Error as err:
            feedback_label.configure(text=f"Database error: {err}", text_color="red")


def update_password(password_id, new_username, new_password, feedback_label, tree, selected_item):
    try:
        # Ensure password_id is an integer
        password_id = int(password_id)
    except ValueError:
        feedback_label.configure(text="Invalid ID format.")
        return

    with get_db_connection() as conn:
        cursor = conn.cursor()

        try:
            # Fetch the user's encrypted master key
            cursor.execute("SELECT encrypted_master_key FROM users WHERE id = (SELECT user_id FROM passwords WHERE id = %s)", (password_id,))
            user_encrypted_master_key = cursor.fetchone()[0]

            # Decrypt the user's master key
            user_master_key = cipher_suite.decrypt(user_encrypted_master_key.encode())
            user_cipher_suite = Fernet(user_master_key)

            # Encrypt the new password
            encrypted_password = user_cipher_suite.encrypt(new_password.encode()).decode()

            # Perform the database update
            cursor.execute("UPDATE passwords SET username=%s, password=%s WHERE id=%s", (new_username, encrypted_password, password_id))
            conn.commit()

            # Fetch the updated "Last Edited" timestamp
            cursor.execute("SELECT updated_at FROM passwords WHERE id = %s", (password_id,))
            updated_timestamp = cursor.fetchone()[0]  # Fetch the updated timestamp

            # Format the "Last Edited" timestamp
            if updated_timestamp:
                formatted_date = datetime.strptime(str(updated_timestamp), "%Y-%m-%d %H:%M:%S").strftime("%d-%b-%Y %H:%M")
            else:
                formatted_date = "N/A"

            # Update the Treeview row
            tree.item(selected_item, values=(password_id, tree.item(selected_item, 'values')[1], new_username, new_password, formatted_date))

            # Update the feedback label
            feedback_label.configure(text="Password updated successfully!")

        except mysql.connector.Error as err:
            feedback_label.configure(text=f"Failed to update password: {err}")


def edit_password(tree):
    if not tree.selection():
        return  # No selection made, exit the function

    selected_item = tree.selection()[0]  # Get the selected item
    values = tree.item(selected_item, 'values')  # Retrieve the values for the selected row

    # Extract only the relevant fields for editing (ignore "Last Edited")
    password_id, website, current_username, current_password = values[:4]

    # Create the edit window
    edit_window = customtkinter.CTkToplevel(app)
    edit_window.title("Edit Password")
    edit_window.geometry("400x550")  # Adjusted height for the new slider and checkbox

    # Username label and entry field
    customtkinter.CTkLabel(master=edit_window, text="Service/Website:").pack(pady=(10, 0))
    website_entry = customtkinter.CTkEntry(master=edit_window, placeholder_text="Service/Website")
    website_entry.insert(0, website)
    website_entry.pack(pady=5)

    customtkinter.CTkLabel(master=edit_window, text="Username:").pack(pady=(10, 0))
    username_entry = customtkinter.CTkEntry(master=edit_window, placeholder_text="Username")
    username_entry.insert(0, current_username)
    username_entry.pack(pady=5)

    # Password label and entry field
    customtkinter.CTkLabel(master=edit_window, text="Password:").pack(pady=(10, 0))
    password_entry = customtkinter.CTkEntry(master=edit_window, placeholder_text="Password")
    password_entry.insert(0, current_password)  # Insert the current password in clear text
    password_entry.pack(pady=5)

    # Slider for password length
    length_label = customtkinter.CTkLabel(master=edit_window, text="Password Length:")
    length_label.pack(pady=(10, 0))
    length_slider = customtkinter.CTkSlider(master=edit_window, from_=12, to=20, number_of_steps=8)
    length_slider.set(12)  # Default value
    length_slider.pack(pady=(5, 0))

    # Label to display the current slider value
    slider_value_label = customtkinter.CTkLabel(master=edit_window, text=f"Length: {int(length_slider.get())}")
    slider_value_label.pack(pady=(0, 10))

    # Function to update the slider value label dynamically
    def update_slider_value(value):
        slider_value_label.configure(text=f"Length: {int(float(value))}")

    # Bind the slider to update the label
    length_slider.configure(command=update_slider_value)

    # Add a checkbox to exclude special characters
    exclude_special_var = customtkinter.StringVar(value="False")  # Default: include special characters
    exclude_special_checkbox = customtkinter.CTkCheckBox(
        master=edit_window,
        text="Exclude Special Characters",
        variable=exclude_special_var,
        onvalue="True",
        offvalue="False"
    )
    exclude_special_checkbox.pack(pady=(10, 10))

    # Function to generate a random password and insert it in clear text
    def fill_random_password():
        password_length = int(length_slider.get())  # Get the selected length
        exclude_special = exclude_special_var.get() == "True"  # Check if special characters should be excluded
        random_password = generate_random_password(length=password_length, exclude_special=exclude_special)  # Generate password
        password_entry.delete(0, 'end')  # Clear existing content
        password_entry.insert(0, random_password)  # Insert the new password

    # Add "Generate Random Password" button
    generate_button = customtkinter.CTkButton(
        master=edit_window,
        text="Generate Randomized Password",
        command=fill_random_password
    )
    generate_button.pack(pady=10)

    # Feedback label
    feedback_label = customtkinter.CTkLabel(master=edit_window, text="")
    feedback_label.pack(pady=10)

    # Save changes function
    def save_changes():
        new_website = website_entry.get().strip()
        new_username = username_entry.get().strip()
        new_password = password_entry.get().strip()

        # Define excluded characters for SQL injection prevention
        excluded_characters = {";", "'", "--", "\"", "\\"}

        # Validation for empty fields
        if not new_website or not new_username or not new_password:
            feedback_label.configure(text="All fields are required!", text_color="red")
            return
        if any(char in new_website for char in excluded_characters):
            feedback_label.configure(text="Website contains invalid characters.", text_color="red")
            return
        if any(char in new_username for char in excluded_characters):
            feedback_label.configure(text="Username contains invalid characters.", text_color="red")
            return
        if any(char in new_password for char in excluded_characters):
            feedback_label.configure(text="Password contains invalid characters.", text_color="red")
            return
        if " " in new_username:
            feedback_label.configure(text="Username cannot contain spaces.", text_color="red")
            return
        if " " in new_password:
            feedback_label.configure(text="Password cannot contain spaces.", text_color="red")
            return

        # Call the update_password function
        update_password(password_id, new_username, new_password, feedback_label, tree, selected_item)

        # Delay window close after showing success message
        if feedback_label.cget("text") == "Password updated successfully!":
           feedback_label.configure(text="Password updated successfully!", text_color="green")
           feedback_label.after(2000, edit_window.destroy)  # Wait 2 seconds, then close window

    # Save button
    save_button = customtkinter.CTkButton(
        master=edit_window,
        text="Save Changes",
        command=save_changes
    )
    save_button.pack(pady=10)


def delete_password(tree, user_id, feedback_label):
    # Check if any row is selected
    if not tree.selection():
        feedback_label.configure(text="No row selected.", text_color="red")
        return

    selected_item = tree.selection()[0]  # Get the selected item
    values = tree.item(selected_item, 'values')  # Retrieve the values for the selected row
    password_id = values[0]  # Get the password ID from the first column

    with get_db_connection() as conn:
        cursor = conn.cursor()

        try:
            # Delete the password from the database
            cursor.execute("DELETE FROM passwords WHERE id = %s AND user_id = %s", (password_id, user_id))
            conn.commit()

            # Remove the row from the Treeview
            tree.delete(selected_item)

            # Update the feedback label
            feedback_label.configure(text="Password deleted successfully!", text_color="green")

        except mysql.connector.Error as err:
            feedback_label.configure(text=f"Failed to delete password: {err}", text_color="red")


def add_new_password(user_id):
    add_window = customtkinter.CTkToplevel(app)
    add_window.title("Add New Password")
    add_window.geometry("400x550")  # Set the size of the add new password window

    # Input fields for website, username, and password
    customtkinter.CTkLabel(master=add_window, text="Service/Website:").pack(pady=(10, 0))
    website_entry = customtkinter.CTkEntry(master=add_window, placeholder_text="Service/Website")
    website_entry.pack(pady=5)

    customtkinter.CTkLabel(master=add_window, text="Username:").pack(pady=(10, 0))
    username_entry = customtkinter.CTkEntry(master=add_window, placeholder_text="Username")
    username_entry.pack(pady=5)

    customtkinter.CTkLabel(master=add_window, text="Password:").pack(pady=(10, 0))
    password_entry = customtkinter.CTkEntry(master=add_window, placeholder_text="Password")
    password_entry.pack(pady=5)

    # Add a slider for password length
    length_label = customtkinter.CTkLabel(master=add_window, text="Password Length:")
    length_label.pack(pady=(10, 0))
    length_slider = customtkinter.CTkSlider(master=add_window, from_=12, to=20, number_of_steps=8)
    length_slider.set(12)  # Default value
    length_slider.pack(pady=(5, 0))

    # Label to display the current slider value
    slider_value_label = customtkinter.CTkLabel(master=add_window, text=f"Length: {int(length_slider.get())}")
    slider_value_label.pack(pady=(0, 10))

    # Function to update the slider value label dynamically
    def update_slider_value(value):
        slider_value_label.configure(text=f"Length: {int(float(value))}")

    # Bind the slider to update the label
    length_slider.configure(command=update_slider_value)

    # Add a checkbox to exclude special characters
    exclude_special_var = customtkinter.StringVar(value="False")  # Default: include special characters
    exclude_special_checkbox = customtkinter.CTkCheckBox(
        master=add_window,
        text="Exclude Special Characters",
        variable=exclude_special_var,
        onvalue="True",
        offvalue="False"
    )
    exclude_special_checkbox.pack(pady=(10, 10))

    # Add "Generate Password" button
    def fill_random_password():
        password_length = int(length_slider.get())  # Get the selected length
        exclude_special = exclude_special_var.get() == "True"  # Check if special characters should be excluded
        random_password = generate_random_password(length=password_length, exclude_special=exclude_special)  # Generate password
        password_entry.delete(0, 'end')  # Clear existing content
        password_entry.insert(0, random_password)  # Insert the new password

    generate_button = customtkinter.CTkButton(
        master=add_window,
        text="Generate Randomized Password",
        command=fill_random_password
    )
    generate_button.pack(pady=10)

    # Feedback label for success/error messages
    feedback_label = customtkinter.CTkLabel(master=add_window, text="")
    feedback_label.pack(pady=10)

    # Save functionality
    def save_new_password():
        website = website_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()

        # Define excluded characters for SQL injection prevention
        excluded_characters = {";", "'", "--", "\"", "\\"}

        # Validate fields
        if not website or not username or not password:
            feedback_label.configure(text="All fields are required!", text_color="red")
            return
        if any(char in website for char in excluded_characters):
            feedback_label.configure(text="Website contains invalid characters.", text_color="red")
            return
        if any(char in username for char in excluded_characters):
            feedback_label.configure(text="Username contains invalid characters.", text_color="red")
            return
        if any(char in password for char in excluded_characters):
            feedback_label.configure(text="Password contains invalid characters.", text_color="red")
            return
        if " " in username:
            feedback_label.configure(text="Username cannot contain spaces.", text_color="red")
            return
        if " " in password:
            feedback_label.configure(text="Password cannot contain spaces.", text_color="red")
            return 

        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                # Fetch the user's encrypted master key
                cursor.execute("SELECT encrypted_master_key FROM users WHERE id = %s", (user_id,))
                user_encrypted_master_key = cursor.fetchone()[0]

                # Decrypt the user's master key
                user_master_key = cipher_suite.decrypt(user_encrypted_master_key.encode())
                user_cipher_suite = Fernet(user_master_key)

                # Encrypt the password with the user's master key
                encrypted_password = user_cipher_suite.encrypt(password.encode()).decode()

                # Generate a unique encryption key for this password
                password_encryption_key = Fernet.generate_key().decode()

                # Insert the password and its encryption key into the database
                cursor.execute(
                    "INSERT INTO passwords (user_id, description, username, password, encryption_key) VALUES (%s, %s, %s, %s, %s)",
                    (user_id, website, username, encrypted_password, password_encryption_key)
                )
                conn.commit()
                feedback_label.configure(text="Password added successfully!", text_color="green")
            except mysql.connector.Error as err:
                feedback_label.configure(text=f"Failed to add password: {err}", text_color="red")


    save_button = customtkinter.CTkButton(master=add_window, text="Save", command=save_new_password)
    save_button.pack(pady=(20, 10))


def display_passwords(user_id):
    password_window = customtkinter.CTkToplevel(app)
    password_window.title("Saved Passwords")
    password_window.geometry("900x650")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#333333", fieldbackground="#333333", foreground="white")
    style.configure("Treeview.Heading", background="#333333", foreground="white")

    # Define Treeview with additional "Last Edited" column
    tree = ttk.Treeview(password_window, columns=('ID', 'Website', 'Username', 'Password', 'Last Edited'), show='headings', selectmode='browse')

    # Hide the "ID" column by setting its width to 0
    tree.heading('ID', text='')  # Empty header for "ID"
    tree.column('ID', width=0, minwidth=0, stretch=False)  # Hidden column

    # Visible columns
    tree.heading('Website', text='Service/Website')
    tree.heading('Username', text='Username')
    tree.heading('Password', text='Password')
    tree.heading('Last Edited', text='Last Edited')
    tree.column('Website', width=200)
    tree.column('Username', width=200)
    tree.column('Password', width=200)
    tree.column('Last Edited', width=200)
    tree.pack(expand=True, fill='both', padx=10, pady=10)

    # Feedback label
    feedback_label = customtkinter.CTkLabel(master=password_window, text="")
    feedback_label.pack(pady=(5, 10))

    # Dictionary to store decrypted passwords
    passwords_dict = {}

    # Checkbox for toggling selected password visibility
    show_password_selected = customtkinter.BooleanVar(value=False)

    def toggle_selected_password():
        selected_item = tree.selection()
        if not selected_item:
            feedback_label.configure(text="No row selected.", text_color="red")
            return

        item_id = selected_item[0]  # Get the selected item
        values = tree.item(item_id, 'values')  # Get the row values
        if len(values) < 4:
            feedback_label.configure(text="Invalid selection.", text_color="red")
            return

        # Get the decrypted password from the passwords_dict
        actual_password = passwords_dict.get(item_id, "******")

        # Toggle password visibility for the selected row
        display_password = actual_password if show_password_selected.get() else "******"
        tree.item(item_id, values=(values[0], values[1], values[2], display_password, values[4]))

    toggle_visibility_checkbox = customtkinter.CTkCheckBox(
        master=password_window,
        text="Show/Hide Selected Password",
        variable=show_password_selected,
        command=toggle_selected_password
    )
    toggle_visibility_checkbox.pack(pady=(5, 10))

    # Search bar and button
    search_label = customtkinter.CTkLabel(password_window, text="Search:")
    search_label.pack(pady=(5, 0))

    search_entry = customtkinter.CTkEntry(password_window, placeholder_text="Enter search query")
    search_entry.pack(pady=(5, 0))

    search_button = customtkinter.CTkButton(password_window, text="Search", command=lambda: filter_tree(search_entry.get()))
    search_button.pack(pady=(5, 10))

    # Function to filter the Treeview based on search
    def filter_tree(query=""):
        for item in tree.get_children():
            tree.delete(item)
        passwords_dict.clear()

        with get_db_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT encrypted_master_key FROM users WHERE id = %s", (user_id,))
                user_encrypted_master_key = cursor.fetchone()[0]
                user_master_key = cipher_suite.decrypt(user_encrypted_master_key.encode())
                user_cipher_suite = Fernet(user_master_key)

                cursor.execute("SELECT id, description, username, password, updated_at FROM passwords WHERE user_id = %s", (user_id,))
                for password_id, website, username, encrypted_password, last_edited in cursor.fetchall():
                    decrypted_password = user_cipher_suite.decrypt(encrypted_password.encode()).decode()
                    if query.lower() in website.lower() or query.lower() in username.lower():
                        display_password = "******"
                        formatted_date = datetime.strptime(str(last_edited), "%Y-%m-%d %H:%M:%S").strftime("%d-%b-%Y %H:%M") if last_edited else "N/A"
                        item = tree.insert("", 'end', values=(password_id, website, username, display_password, formatted_date))
                        passwords_dict[item] = decrypted_password
            except mysql.connector.Error as db_err:
                feedback_label.configure(text=f"Database error: {db_err}", text_color="red")
            except ValueError as val_err:
                feedback_label.configure(text=f"Value error: {val_err}", text_color="red")
            except Exception as err:  # Catch-all for unexpected errors
                feedback_label.configure(text=f"Unexpected error: {err}", text_color="red")

    # Copy to Clipboard button
    def copy_password_to_clipboard():
        selected_item = tree.selection()
        if not selected_item:
            feedback_label.configure(text="No password selected.", text_color="red")
            return
        item_id = selected_item[0]
        actual_password = passwords_dict.get(item_id, "******")
        if actual_password == "******":
            feedback_label.configure(text="Password is hidden. Please show it before copying.", text_color="red")
            return
        app.clipboard_clear()
        app.clipboard_append(actual_password)
        app.update()
        feedback_label.configure(text="Password copied sucessfully!", text_color="green")

    copy_button = customtkinter.CTkButton(password_window, text="Copy Password", command=copy_password_to_clipboard)
    copy_button.pack(pady=10)

    # Edit and Delete buttons
    edit_button = customtkinter.CTkButton(password_window, text="Edit Selected", command=lambda: edit_password(tree))
    edit_button.pack(pady=10)

    delete_button = customtkinter.CTkButton(password_window, text="Delete Selected", command=lambda: delete_password(tree, user_id, feedback_label))
    delete_button.pack(pady=10)

    # Initially load all passwords as `******`
    filter_tree()


setup_initial_screen()

app.mainloop()
