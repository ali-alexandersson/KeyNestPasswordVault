# KeyNest Password Vault  
A secure and user-friendly password management application built with Python and MySQL.

## Features
- **Secure User Authentication**: Uses bcrypt hashing+salting to securely store master passwords.  
- **Password Encryption**: Utilizes cryptography with Fernet encryption to protect stored passwords.  
- **User-Friendly GUI**: Built with CustomTkinter for a sleek, modern interface.  
- **Database Storage**: Credentials and user data are securely stored in a MySQL database.  
- **Environment Variables**: Sensitive data like database credentials and encryption keys are stored in a `.env` file.  
- **Principle of Least Privilege**: A limited database user (`vault_admin`) improves security.  

## Requirements
- **Python 3.12.3**  
- **MySQL Server 8.0.40**  
- **Visual Studio Code** (or another code editor)  

## Installation

1. **Clone the repository**:  
    ```bash
    git clone https://github.com/your_username/KeyNestPasswordVault.git
    cd KeyNestPasswordVault
    ```

2. **Install required libraries**:  
    Run the following command:  
    ```bash
    pip install bcrypt==4.2.1 cryptography==44.0.0 mysql-connector-python==9.1.0 customtkinter==5.2.2 python-dotenv==1.0.1
    ```

3. **Set up a MySQL database**:  
    Run the following SQL commands in your MySQL command line or MySQL Workbench:  
    ```sql
    CREATE DATABASE password_vault;
    USE password_vault;

    CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        master_password TEXT NOT NULL, 
        encrypted_master_key TEXT NOT NULL, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE passwords (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        description VARCHAR(255) NOT NULL,
        username VARCHAR(255) NOT NULL,
        password TEXT NOT NULL,         
        encryption_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    ```

4. **Create a `.env` file**:  
    In the root directory, create a `.env` file with the following content:  
    ```plaintext
    DB_HOST=localhost
    DB_USER=vault_admin
    DB_PASSWORD=your_password
    DB_NAME=password_vault
    DECRYPTION_KEY=your_decryption_key
    ENCRYPTED_MASTER_KEY=your_encrypted_master_key
    ```

5. **Run the program**:  
    Execute the Python script using:  
    ```bash
    python your_script_name.py
    ```

## Notes:
- Replace `your_password` and `your_decryption_key` with secure values.  
- Ensure **MySQL Server** is running locally before starting the application.

---

## Example Output
- The program will allow users to:
    - Create an account with a master password.  
    - Log in and securely store/view/manage passwords for various accounts.  
    - Use encryption and hashing for enhanced security.  

---

## Contributing
If you'd like to contribute to this project, please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License.

## Project Repository
[Link to GitHub Repository](https://github.com/your_username/KeyNestPasswordVault)
