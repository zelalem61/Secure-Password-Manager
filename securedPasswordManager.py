import base64
import random
import string
import tkinter as tk
from tkinter import messagebox
import hashlib
from getpass import getpass
from cryptography.fernet import Fernet
import json
import os


class SecurePasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password.encode()
        self.passwords = {}
        self.key = None

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def load_passwords(self):
        if os.path.exists('passwords.json'):
            with open('passwords.json', 'rb') as file:
                encrypted_data = file.read()

            if encrypted_data:
                f = Fernet(self.key)
                decrypted_data = f.decrypt(encrypted_data)
                self.passwords = json.loads(decrypted_data)
            else:
                self.passwords = {}


    def save_passwords(self):
        f = Fernet(self.key)
        data = json.dumps(self.passwords).encode()
        encrypted_data = f.encrypt(data)

        with open('passwords.json', 'wb') as file:
            file.write(encrypted_data)
            

    def generate_key(self):
        salt = b'\x8f~\xb6a\xd3}\x8d\xcb\xb4\xb3{\xddt\x0b\x8a'
        key = hashlib.pbkdf2_hmac('sha256', self.master_password, salt, 100000)
        self.key = base64.urlsafe_b64encode(key)


    def add_password(self, service, username, password):
        self.passwords[service] = {'username': username, 'password': password}
        self.save_passwords()
        
        

    def get_password(self, service):
        if service in self.passwords:
            return self.passwords[service]['password']
        else:
            return None

    def remove_password(self, service):
        if service in self.passwords:
            del self.passwords[service]
            self.save_passwords()

    def list_passwords(self):
        passwords_info = ""
        for service, details in self.passwords.items():
            passwords_info += f"Service: {service}\n"
            passwords_info += f"Username: {details['username']}\n"
            passwords_info += f"Password: {details['password']}\n"
            passwords_info += "*****************\n"
        return passwords_info


def show_password_manager():
    password_window.withdraw()

    manager = SecurePasswordManager(password_entry.get())

    manager.generate_key()
    manager.load_passwords()

    manager_window = tk.Toplevel()

    manager_window.title("Secure Password Manager")
    manager_window.geometry("700x450")
    manager_window.resizable(False, False)
    manager_window.configure(bg="#191C32")
    
    label_style = {"font": ("poppins", 12, "bold"), "bg": "#191C32", "fg": "white"}
    entry_style = {"font": ("poppins", 12), "width": 30, "bg" : "#307D6B", "fg" : "white"}
    button_style = {"font": ("poppins", 12), "bg": "#18D9A3",
                    "fg": "black", "relief": tk.FLAT, "width" : 25,"padx": 5, "pady": 3}

    def add_password():
        service = service_entry.get()
        username = username_entry.get()
        password = password_entry2.get()

        messagebox.showinfo("Success", "Password added successfully.")
        manager.add_password(service, username, password)
        username_entry.delete(0, tk.END)
        password_entry2.delete(0, tk.END)
       
        
        

    def retrieve_password():
        service = service_entry.get()
        password = manager.get_password(service)

        if password:
            messagebox.showinfo(
                "Password", f"Service: {service}\nPassword: {password}")
        else:
            messagebox.showwarning("Not Found", "Password not found.")
        service_entry.delete(0, tk.END)

        

    def remove_password():
        service = service_entry.get()
        manager.remove_password(service)
        messagebox.showinfo("Success", "Password removed successfully.")
        password_entry.delete(0, tk.END)
        username_entry.delete(0, tk.END)
        service_entry.delete(0, tk.END)
        
        

    def list_passwords():
        passwords = manager.list_passwords()
        messagebox.showinfo("Stored Passwords", passwords)

    def generate_password():
        password = manager.generate_password() 
        password_entry2.insert(0, password)
        messagebox.showinfo("Generated Password", password)

    def exit_manager():
        manager.save_passwords()
        manager_window.destroy()
        password_window.quit()

   
    left_frame = tk.Frame(manager_window, bg="#191C32")
    left_frame.grid(row=0, column=0, padx=10, pady=10)

    service_label = tk.Label(left_frame, text="Service:", **label_style)
    service_label.grid(row=0, column=0, sticky="w")
    service_entry = tk.Entry(left_frame, **entry_style)
    service_entry.grid(row=1, column=0, padx=10, pady=5)

    username_label = tk.Label(left_frame, text="Username:", **label_style)
    username_label.grid(row=2, column=0, sticky="w")
    username_entry = tk.Entry(left_frame, **entry_style)
    username_entry.grid(row=3, column=0, padx=10, pady=5)

    password_label = tk.Label(left_frame, text="Password:", **label_style)
    password_label.grid(row=4, column=0, sticky="w")
    password_entry2 = tk.Entry(left_frame, show="*", **entry_style)
    password_entry2.grid(row=5, column=0, padx=10, pady=5)

    right_frame = tk.Frame(manager_window, bg="#191C32")
    right_frame.grid(row=0, column=1, padx=10, pady=10)
    
    add_button = tk.Button(right_frame, text="Add a Password",
                           command=add_password, **button_style,)
    add_button.grid(row=0, column=0, padx=10, pady=5)

    retrieve_button = tk.Button(
        right_frame, text="Retrieve a Password", command=retrieve_password, **button_style)
    retrieve_button.grid(row=1, column=0, padx=10, pady=5)

    remove_button = tk.Button(
        right_frame, text="Remove a Password", command=remove_password, **button_style)
    remove_button.grid(row=2, column=0, padx=10, pady=5)

    list_button = tk.Button(
        right_frame, text="List Stored Passwords", command=list_passwords, **button_style)
    list_button.grid(row=3, column=0, padx=10, pady=5)

    generate_button = tk.Button(
        right_frame, text="Generate a Password", command=generate_password, **button_style)
    generate_button.grid(row=4, column=0, padx=10, pady=5)

    exit_button = tk.Button(right_frame, text="Exit",
                        command=exit_manager, **button_style)

    exit_button.grid(row=5, column=0, padx=10, pady=5)


    
password_window = tk.Tk()
password_window.title("Enter Master Password")
password_window.geometry("600x300")
password_window.resizable(False, False)
password_window.configure(bg='#191C32')

label = tk.Label(password_window, text="Enter master password:",
                 font=("poppins", 14), fg="white", bg="#191C32",)
label.pack(pady=10)

password_entry = tk.Entry(password_window, show="*",
                          font=("poppins", 12), bg="#307D6B", fg="black", relief=tk.SOLID)
password_entry.pack(pady=10, padx=10)



def submit_password():
    password = password_entry.get()
    if password == "mypassword":
        show_password_manager()
    else:
        messagebox.showerror("Error", "Invalid password")


submit_button = tk.Button(password_window, text="Submit", command=submit_password, font=("poppins", 12, "normal"),
                          bg="#18D9A3", fg="black", relief=tk.FLAT, padx=5, pady=5)
submit_button.pack(pady=5, padx=5)

password_window.mainloop()
