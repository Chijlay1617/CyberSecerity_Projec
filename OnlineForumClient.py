import tkinter as tk
from time import sleep
from tkinter import *
import tkinter.messagebox
import re
import socket
import ssl

def on_closing():
    try:
        ssl_client.send("4".encode("UTF-8"))
        ssl_client.send("0".encode("UTF-8"))
    except OSError:
        pass
    except Exception:
        pass
    app.destroy()

def detect_sql_injection(input_str):
    # Define a list of SQL keywords to check for
    sql_keywords = ['GRANT ','SELECT ', 'INSERT ', 'UPDATE ', 'DELETE ', 'DROP ', 'CREATE ', 'ALTER ', 'UNION ', 'BY ', 'FROM ', 'SET ']
    count = 0
    # Use regular expression to find any SQL keywords in the input string
    for keyword in sql_keywords:
        pattern = re.compile(rf"\b{keyword}\b", re.IGNORECASE)
        match = pattern.search(input_str)
        if match:
            count+=1
    if count>=2:
        return True
    else:
        return False

class Application(tk.Tk):

    def __init__(self):
        super().__init__()
        self.wm_title("Online Forum")
        self.geometry("1280x720")
        self.resizable(width=True, height=True)
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.frames = {}
        for F in (ConnectPage,StartPage):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(ConnectPage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise() # switch

class ConnectPage(tk.Frame):

    def __init__(self, parent, root):
        super().__init__(parent)

        def login():
            fun_id = "1"
            get_username = AccountEntry.get()
            if not get_username:
                return
            get_pwd = PasswordEntry.get()
            if not get_pwd:
                return
            if detect_sql_injection(get_username) or detect_sql_injection(get_pwd):
                tk.messagebox.showerror('Error', message='Do use SQL injection attack')
                return
            ssl_client.send(fun_id.encode("UTF-8"))
            ssl_client.send(get_username.encode("UTF-8"))
            ssl_client.send(get_pwd.encode("UTF-8"))
            flag = ssl_client.recv(4096).decode("UTF-8")

            if flag=="0":
                tk.messagebox.showinfo('Info',message=f'You are authenticated, Welcome <{get_username}>')
                root.show_frame(StartPage)

            elif flag=="404":
                tk.messagebox.showerror('Connection Error', message='Sorry, Server is not available right now.')

            elif flag=="2":
                tk.messagebox.showerror('Error', message='Please enter correct username.')

            elif flag=="3":
                tk.messagebox.showerror('Error', message='Please enter correct password.')

        def sign_up():
            fun_id = "2"
            get_username = AccountEntry.get()
            if not get_username:
                return
            get_pwd = PasswordEntry.get()
            if not get_pwd:
                return
            if detect_sql_injection(get_username) or detect_sql_injection(get_pwd):
                tk.messagebox.showerror('Error', message='Do use SQL injection attack')
                return
            ssl_client.send(fun_id.encode("UTF-8"))
            ssl_client.send(get_username.encode("UTF-8"))
            ssl_client.send(get_pwd.encode("UTF-8"))
            flag = ssl_client.recv(4096).decode("UTF-8")

            if flag=="0":
                tk.messagebox.showinfo('Info',message='Registration Successful!')

            elif flag=="404":
                tk.messagebox.showerror('Connection Error', message='Sorry, Server is not available right now.')

            elif flag=="2":
                tk.messagebox.showerror('Error', message='User name has been used.')

            elif flag=="3":
                tk.messagebox.showerror('Error', message='The password must be longer than eight digits and include upper and lower case alphanumeric characters and special symbols.')

        header = tk.Label(self,
                          text="User Login",
                          font=("Microsoft YaHei", 40, "bold")
                          )
        header.pack()
        header.place(x=500, y=70)

        Account = tk.Label(self,
                           text="Account:",
                           font=("Microsoft YaHei", 25)
                           )
        Account.pack(padx=5, pady=10, side=tk.LEFT)
        Account.place(x=350, y=300)


        AccountEntry = Entry(self,
                   width=20,
                   font=("Microsoft YaHei", 22)
                   )
        AccountEntry.pack()
        AccountEntry.place(x=600, y=310)

        # Login password
        password = tk.Label(self,
                            text="Password:",
                            font=("Microsoft YaHei", 25)
                            )
        password.pack(padx=5, pady=10, side=tk.LEFT)
        password.place(x=350, y=400)

        PasswordEntry = Entry(self,
                              show="*",
                              width=20,
                              font=("Microsoft YaHei", 22)
                              )
        PasswordEntry.pack()
        PasswordEntry.place(x=600, y=410)

        # login design
        login_button = tk.Button(self,
                              text="Login",
                              font=("Microsoft YaHei", 20),
                              width=10,
                              height=3,
                              activeforeground="red",
                              command=login
                              )
        login_button.pack(padx=5, pady=10, side=tk.LEFT)
        login_button.place(x=400, y=530)

        Sign_up_button = tk.Button(self,
                                   text="Sign Up",
                                   font=("Microsoft YaHei", 20),
                                   width=10,
                                   height=3,
                                   activeforeground="red",
                                   command=sign_up
                                   )
        Sign_up_button.pack(padx=5, pady=10, side=tk.LEFT)
        Sign_up_button.place(x=800, y=530)

class StartPage(tk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent)

        def get_question():
            fun_id = "3"

        def logout():
            fun_id = "4"
            ssl_client.send(fun_id.encode("UTF-8"))
            root.show_frame(ConnectPage)


        header = tk.Label(self,
                          text="Forum",
                          font=("Microsoft YaHei", 40, "bold")
                          )
        header.pack()
        header.place(x=500, y=70)

        logout_button = tk.Button(self,
                                  text="Logout",
                                  font=("Microsoft YaHei", 20),
                                  width=10,
                                  height=3,
                                  activeforeground="red",
                                  command=logout
                                  )
        logout_button.pack(padx=5, pady=10, side=tk.LEFT)
        logout_button.place(x=960, y=20)

if __name__ == "__main__":

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_client = ssl.wrap_socket(client)
    try:
        ssl_client.connect(('127.0.0.1', 8000))
    except:
        tk.messagebox.showerror('Connection Error', message='Sorry, Can not connect to server.')
        sleep(2)
        exit(-1)

    app = Application()
    app.protocol("WM_DELETE_WINDOW", on_closing)
    app.mainloop()

