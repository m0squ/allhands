# /usr/bin python3
import re

if __name__ == "__main__":
    print("Program started. Press anytime ^C to quit. To get help about the CLI arguments, use -h or --help")

import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import ImageTk, Image
from flask import __version__
import argparse, os, sys, platform, socket, requests, threading, time, datetime, random, easygui, plyer, textwrap, \
    pathlib, json
from models import gloder_lib
from styles import button


class Chatroom:
    def __init__(self):
        self.home_dir = pathlib.Path.home()
        self.username = ""
        self.server_ip = ""
        self.port = 5000
        if platform.system() == "Linux":
            self.wifi = os.popen("iwgetid -r").read().rstrip()
            if self.wifi == "":
                self.wifi = None
        else:
            self.wifi = None
        self.already_connected = False
        self.first_login = True
        self.login_time = 0
        self.stop_thread = False
        self.online = None  # True=online, None=connecting, False=offline
        self.msg_json = []
        self.listbox_ids = []
        self.received_files = []
        self.default_filetypes = (("All files", "*.*"), ("Text files", "*.txt"))
        self.prog_ver = "1.3.0"
        self.msg_width = 84
        self.window = None
        self.menubar = None
        self.text_input = None
        self.login_win = None
        self.username_entry = None
        self.username_var = None
        self.port_entry = None
        self.port_var = None

    def s_to_time(self, s):
        return datetime.datetime.fromtimestamp(s).strftime("%a %b %d %H:%M:%S")

    def quit_func(self, window=True, err=False, _exit=True, send=True, logout=True):
        if not err:
            pass
        elif err is None:
            error_str = "Cannot establish connection."
            if platform.system() == "Linux":
                if self.wifi is None:
                    error_str += " Connect to a network and try again."
                else:
                    error_str += "\n1. Make sure there is an AllHands server running on " + self.ip + ":" + str(
                        self.port) + ".\n2. Are you sure " + self.wifi + " is the right network?"
            self.mk_offline_recv(error_str)
            choose_quit = easygui.buttonbox(title="What a bug!", msg=error_str, choices=["Change data", "Quit"])
            if choose_quit == "Change data":
                self.login()
                send = False
                logout = False
                window = False
                _exit = False
        else:
            messagebox.showerror(title="What a bug!", message=err)
        if send:
            self.stop_thread = True
            self.send(show=False, content="> ❌ Goodbye! I left the chat <", info=True)
        if logout:
            self.messages.delete(0, tk.END)
        if window:
            try:
                self.login_win.destroy()
            except AttributeError:
                pass
            self.window.destroy()
        if _exit:
            self.stop_thread = True
            quit()

    def check_username(self):
        self.username_var.set("Username")
        self.username_entry.config(highlightbackground="grey", highlightcolor="grey")
        username_approved = False
        username_cont = self.username_entry.get().strip()
        if username_cont == "":
            self.username_var.set("Username ⚠")
            self.username_entry.config(highlightbackground="orange", highlightcolor="orange")
        else:
            username_approved = True
            self.username = username_cont
        self.port_var.set("Port")
        self.port_entry.config(highlightbackground="grey", highlightcolor="grey")
        port_approved = False
        port_cont = self.port_entry.get().strip()
        port_cont_int = int(port_cont)
        if port_cont == "" or port_cont.isdigit() == False or port_cont_int < 1 or port_cont_int > 65535:
            self.port_var.set("Port ⚠")
            self.port_entry.config(highlightbackground="orange", highlightcolor="orange")
        else:
            port_approved = True
            self.port = port_cont
        if username_approved and port_approved:
            self.login_win.destroy()
            if self.already_connected:
                self.quit_func(window=False, _exit=False, send=False)
            user_msg = {"username": self.username}
            try:
                user_req = requests.post("http://" + self.ip + ":" + str(self.port) + "/access", json=user_msg)
                data = user_req.json()
                if user_req.status_code == 201:  # Anything is OK
                    self.server_ip = data["server_ip"]
                    self.menubar.entryconfig(5, label="Logged in as " + self.username + " (click to log out)")
                    self.send(show=True, content="< ✔ Hello to everybody! I joined the chat >", info=True)
                    if self.first_login:
                        self.receive_daemon()
                    self.login_time = time.time()
                    self.stop_thread = False
                    self.window.config(cursor="")
                else:  # An error occurred
                    self.quit_func(err=data["response"], send=False)
            except requests.exceptions.ConnectionError:
                self.quit_func(err=None, send=False, logout=False)

    def login(self):
        try:
            self.window.config(cursor="watch")
            self.login_win = tk.Toplevel()
            self.login_win.group(self.window)
            self.login_win.grab_set()
            self.login_win.title("Log in")
            self.login_win.tk.call('wm', 'iconphoto', self.login_win._w, tk.PhotoImage(file="../img/icon.png"))
            self.login_win.resizable(width=False, height=False)
            self.login_win.configure(bg="white")
            self.login_win.protocol("WM_DELETE_WINDOW", lambda: self.quit_func(send=False, logout=False))
            self.login_win.update()
            self.username_var = tk.StringVar()
            tk.Label(self.login_win, textvariable=self.username_var, bg="white", font=("Noto Sans", 10)).grid()
            self.username_var.set("Username")
            self.username_entry = tk.Entry(self.login_win, font=("Noto Sans", 10), selectbackground="orange",
                                           highlightbackground="grey", highlightcolor="grey", relief=tk.FLAT)
            self.username_entry.insert(0, self.username)
            self.username_entry.grid(sticky="we", padx=10)
            self.port_var = tk.StringVar()
            tk.Label(self.login_win, textvariable=self.port_var, bg="white", font=("Noto Sans", 10)).grid()
            self.port_var.set("Port")
            self.port_entry = tk.Spinbox(self.login_win, text="5000", from_=1, to=65535, font=("Noto Sans", 10),
                                         selectbackground="orange", highlightbackground="grey", highlightcolor="grey",
                                         relief=tk.FLAT)
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, self.port)
            self.port_entry.grid(sticky="we", padx=10)
            btn_login = tk.Button(master=self.login_win, text="OK", command=self.check_username, relief=tk.FLAT,
                                  font=("Noto Sans", 10), highlightbackground="grey", activebackground="orange",
                                  highlightthickness=1)
            btn_login.grid(pady=10, sticky="we", padx=10)
            self.login_win.bind("<Return>", lambda x: self.check_username())
            self.login_win.mainloop()
        except AttributeError:
            self.quit_func(send=False)

    def logout(self):
        self.first_login = False
        self.login()

    def show_msg(self, sender, time, content):
        if sender == self.username:
            text = [time]
        else:
            text = [f"{sender}   —   {time}"]
        for i in textwrap.wrap(content, self.msg_width - 20):
            text.append(i)
        n = 0
        for i in text:
            if sender == self.username:
                i = i.rjust(self.msg_width)
            self.messages.insert(tk.END, i)
            if n == 0:
                self.messages.itemconfig(tk.END, {"fg": "orange"})
            n += 1
        self.messages.yview(tk.END)

    def show_info(self, info):
        self.white_line()
        self.messages.insert(tk.END, "—" + info.center(self.msg_width - 2) + "—")
        self.messages.itemconfig(tk.END, {"fg": "white", "bg": "gray"})
        self.white_line()
        self.messages.yview(tk.END)

    def add_lines(self, lines, _id):
        for n in range(0, lines):
            self.listbox_ids.append(_id)

    def mk_offline_recv(self, details):
        if self.online:
            print("error: the server didn't respond correctly: " + str(details))
            self.online = False

    def recv_msg(self):
        inbox = requests.get("http://" + self.server_ip + ":" + str(self.port) + "/msg")
        if inbox.status_code == 200:
            if not self.online:
                self.online = True
            for i in inbox.json()[-20:]:
                recv_sender = i["sender"]
                recv_time = self.s_to_time(i["timestamp"])
                recv_content = i["content"]
                recv_id = i["id"]
                recv_type = i["type"]
                if not recv_id in self.listbox_ids:
                    self.msg_json.append(i)
                    if recv_type == "info":
                        lines = 3
                        if recv_content == "< ✔ Hello to everybody! I joined the chat >":
                            self.show_info(
                                recv_sender + " joined the chat on " + recv_time + ". Say hello to him!")
                        else:
                            self.show_info(recv_sender + " left the chat on " + recv_time)
                    else:
                        lines = 2
                        if recv_sender != self.username:
                            self.show_msg(recv_sender, recv_time, recv_content)
                    self.add_lines(lines, recv_id)
                    if self.already_connected and recv_sender != self.username:
                        plyer.notification.notify(title=recv_sender, message=recv_content,
                                                  app_icon="../img/icon.png")
        else:
            self.mk_offline_recv("it responded to GET /msg with a status of " + str(inbox.status_code))

    def recv_files(self):
        file_data_req = requests.get(f"http://{self.server_ip}:{str(self.port)}/file-data")
        n = 0
        for i in file_data_req.json():
            sender = i["sender"]
            time = self.s_to_time(i["timestamp"])
            filename = i["filename"]
            if sender != self.username and not filename in self.received_files:
                self.received_files.append(filename)
                file_msg = {"filename": filename}
                file_req = requests.post(f"http://{self.server_ip}:{str(self.port)}/download-file", json=file_msg)
                file = open(f"./media/{filename}", "wb")
                file.write(file_req.content)
                file.close()
                self.show_msg(sender, time, f"📄 {filename}")
                self.add_lines(2, None)
            n += 1

    def receive(self):
        while True:
            if not self.stop_thread:
                try:
                    hb_msg = {"username": self.username}
                    hb_req = requests.post("http://" + self.server_ip + ":" + str(self.port) + "/heartbit", json=hb_msg)
                    self.recv_msg()
                    self.recv_files()
                except requests.exceptions.ConnectionError:
                    self.quit_func(err=None)
                if not self.already_connected:
                    self.already_connected = True
                time.sleep(1)

    def receive_daemon(self):
        check_inbox = threading.Thread(target=self.receive)
        check_inbox.setDaemon(True)
        check_inbox.start()

    def mk_offline_send(self, details, send_msg):
        self.messages.insert(tk.END,
                             f"{send_msg['sender']}   —   {gloder_lib.get_date('%w %m %D') + ' ' + datetime.datetime.now().strftime('%H:%M:%S')}")
        self.messages.itemconfig(tk.END, {"fg": "red"})
        self.messages.insert(tk.END, send_msg["content"])
        print("error: the server didn't respond correctly: " + details)

    def send(self, show=True, content=None, info=False):
        timestamp = self.s_to_time(time.time())
        if content is None:
            content = self.text_input.get()
            self.text_input.delete(0, tk.END)
        if content.strip() != "":
            if info:
                send_msg = {"sender": self.username, "content": content, "type": "info"}
            else:
                send_msg = {"sender": self.username, "content": content, "type": "msg"}
                if show:
                    self.show_msg(self.username, timestamp, content)
            try:
                send_req = requests.post("http://" + self.server_ip + ":" + str(self.port) + "/msg", json=send_msg)
                if show and send_req.status_code != 201:
                    self.mk_offline_send(f"it responded with a status of {send_req.status_code}", send_msg)
            except requests.exceptions.ConnectionError as e:
                if show:
                    self.mk_offline_send(str(e), send_msg)

    def attach(self):
        filename = filedialog.askopenfilename(title="Attach a file",
                                              initialdir=self.home_dir,
                                              filetypes=self.default_filetypes)
        if filename != ():
            file = open(filename, "rb")
            # self.send(file={"name": filename, "content": content})
            try:
                attach_req = requests.post(f"http://{self.server_ip}:{str(self.port)}/upload-file",
                                           files={"file": file, "json": ('{"sender": "%s", "filename": "%s"}' % (self.username, filename.split("/")[-1].split("\\")[-1])).encode("latin-1")},
                                           data={'upload_file': filename.split("/")[-1].split("\\")[-1], 'DB': 'photcat', 'OUT': 'csv', 'SHORT':'short'})
                if attach_req.status_code != 201:
                    #self.mk_offline_send(f"it responded with a status of {attach_req.status_code}", attach_req)
                    pass
            except requests.exceptions.ConnectionError as e:
                #self.mk_offline_send(str(e), send_msg)
                pass
            file.close()


    def on_msg_sel(self):
        sel = self.messages.curselection()[0]
        """msg = None
        for i in self.msg_json:
            if i["id"] == self.listbox_ids[sel]:
                msg = i
        file = msg["file"]
        if msg:
            if file != {}:
                filename = file["name"]
                content = file["content"]
                file_ext = filename.split(".")[-1]
                if file_ext != filename:
                    save_filetypes = (self.default_filetypes, (f".{file_ext} files", f"*.{file_ext}"))
                else:
                    save_filetypes = self.default_filetypes
                save_file = filedialog.asksaveasfile("w",
                                                     title="Download file as...",
                                                     initialdir=self.home_dir,
                                                     initialfile=filename.split("/")[-1].split("\\")[-1],
                                                     filetypes=save_filetypes)
                if save_file:
                    save_file.write(content)
                    save_file.close()
        else:
            print("Warning: One or more messages are missing from Chatroom.msg_json or self.listbox_ids")"""


    def users(self):
        users_req = requests.get("http://" + self.server_ip + ":" + str(self.port) + "/users")
        if users_req.status_code == 200:
            data = users_req.json()
            n = 0
            data_str = ""
            for i in data:
                if n != 0:
                    data_str += "\n"
                time = self.s_to_time(data.get(i))
                if i == self.username:
                    data_str += "You (" + i + ") joined on " + time
                else:
                    data_str += i + " joined on " + time
                n += 1

            users_win = tk.Toplevel()
            users_win.group(self.window)
            users_win.grab_set()
            if len(data) == 1:
                users_win.title(str(len(data)) + " Chat Participant")
            else:
                users_win.title(str(len(data)) + " Chat Participants")
            users_win.tk.call('wm', 'iconphoto', users_win._w, tk.PhotoImage(file="../img/icon.png"))
            users_win.minsize(400, 300)
            users_win.resizable(width=False, height=False)
            users_win.configure(bg="white")
            users_win.update()
            users_label = tk.Label(users_win, text=data_str, bg="white", font=("Noto Sans", 10))
            users_label.pack()
        else:
            messagebox.showerror(title="What a bug!", message="We couldn't load participants' data.")

    def info(self):
        info_win = tk.Toplevel()
        info_win.group(self.window)
        info_win.grab_set()
        info_win.title("Information")
        info_win.tk.call('wm', 'iconphoto', info_win._w, tk.PhotoImage(file="../img/icon.png"))
        info_win.resizable(width=False, height=False)
        info_win.configure(bg="white")
        info_win.update()
        info = tk.Text(info_win, borderwidth=0, font=("Noto Mono", 10), selectbackground="orange",
                       inactiveselectbackground="orange", wrap=tk.WORD, height=4)
        if platform.system() == "Linux":
            info.config(height=5)
            info.insert(1.0, "Connected Network: " + str(self.wifi) + "\n")
        info.insert(2.0, f"""Your IP: {socket.gethostbyname(socket.gethostname())}
Server address: http://{self.server_ip}:{self.port}
Your OS: {platform.platform()}
Python: {sys.version.split()[0]}""")
        info.grid()

    def about(self):
        about_win = tk.Toplevel()
        about_win.group(self.window)
        about_win.grab_set()
        about_win.title("About AllHands")
        about_win.tk.call('wm', 'iconphoto', about_win._w, tk.PhotoImage(file="../img/about.png"))
        about_win.resizable(width=False, height=False)
        about_win.configure(background="white")
        about_win.update()
        img = tk.PhotoImage(file="../img/allhands.png")
        img_label = tk.Label(about_win, image=img, background="white")
        img_label.photo = img
        img_label.grid(row=0, column=0, padx=5)
        frm_about = tk.Frame(about_win, background="white")
        description = tk.Label(frm_about, text=f"""Chat the best you can with the new visual
improvements of AllHands {self.prog_ver}!
Made with <3 by the What-do-I-know Company""", background="white", font=("Noto Sans", 10))
        description.pack()
        links = [("GUI inspiration 🔗", "https://www.dev.to/zeyu2001/build-a-chatroom-app-with-python-44fa"), (
            "Tooltip inspiration 🔗",
            "https://stackoverflow.com/questions/20399243/display-message-when-hovering-over-something-with-mouse-cursor-in-python#answer-56749167"),
                 (
                     "About window icon source 🔗",
                     "https://anzeljg.github.io/rin2/book2/2405/docs/tkinter/cursors/47.png"),
                 ("Main window icon source 🔗", "https://www.icons8.com/icon/42782/chat")]
        for i in links:
            button.link(frm_about, i[0], i[1])
        dev_info = tk.Label(frm_about, text="""Linux test: Linux-5.11.0-27-generic-x86_64-with-glibc2.29
with Python 3.8.10
Windows test: Windows-10-10.0.22000-SP0 with Python 3.9.6""", fg="gray", background="white", font=("Noto Mono", 8))
        dev_info.pack()
        frm_about.grid(row=0, column=1)

    def white_line(self):
        self.messages.insert(tk.END, "")

    def create(self):
        self.window = tk.Tk(className="AllHands")
        self.window.title("AllHands")
        self.window.tk.call('wm', 'iconphoto', self.window._w, tk.PhotoImage(file="../img/icon.png"))
        self.window.minsize(700, 590)
        self.window.resizable(width=False, height=True)
        self.window.protocol("WM_DELETE_WINDOW", self.quit_func)
        self.window.update()

        self.menubar = tk.Menu(self.window, activebackground="orange")
        self.window.config(menu=self.menubar)
        self.menubar.add_command(label="Participants", command=self.users)
        self.menubar.add_command(label="Info", command=self.info)
        self.menubar.add_command(label="About", command=self.about)
        self.menubar.add_command(label="–", state=tk.DISABLED)
        self.menubar.add_command(label="Logging in…", command=self.logout)

        frm_messages = tk.Label(master=self.window)
        scrollbar = tk.Scrollbar(master=frm_messages)
        self.messages = tk.Listbox(
            master=frm_messages,
            yscrollcommand=scrollbar.set,
            font=("Noto Mono", 10),
            width=84
        )
        scrollbar.configure(command=self.messages.yview)
        self.messages.yview(tk.END)
        # self.messages.bindtags((self.messages, self.window, "all"))
        self.messages.bind("<<ListboxSelect>>", lambda x: self.on_msg_sel())
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
        self.messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        frm_messages.pack(fill=tk.BOTH, expand=True)

        random_number = random.randint(0, 3)
        random_phrases = ["Where r u?", "Who am I talking to?", "Let's meet!", "Would u like to know my password?"]
        # frm_entry = tk.Frame(master=self.window)
        self.text_input = tk.Entry(master=self.window, font=("Noto Sans", 10), selectbackground="orange",
                                   highlightbackground="grey", highlightcolor="grey", relief=tk.FLAT)
        self.text_input.pack(fill=tk.BOTH, expand=True, side="left", padx=15, pady=10)
        self.text_input.insert(0, random_phrases[random_number])
        self.text_input.bind("<Button-1>", lambda x: self.text_input.delete(0, tk.END))
        self.text_input.bind("<Return>", lambda x: self.send())

        btn_attach = tk.Button(
            master=self.window,
            text="Attach",
            command=self.attach,
            relief=tk.FLAT,
            font=("Noto Sans", 10),
            highlightbackground="grey",
            activebackground="orange",
            highlightthickness=1
        )

        btn_send = tk.Button(
            master=self.window,
            text="Send",
            command=self.send,
            relief=tk.FLAT,
            font=("Noto Sans", 10),
            highlightbackground="grey",
            activebackground="orange",
            highlightthickness=1
        )
        btn_attach.pack(fill=tk.Y, side="left", padx=0, pady=10)
        btn_send.pack(fill=tk.Y, side="left", padx=15, pady=10)
        # frm_entry.pack()

        self.window.rowconfigure(0, minsize=500, weight=1)
        self.window.rowconfigure(1, minsize=50, weight=0)
        self.window.columnconfigure(0, minsize=500, weight=1)
        self.window.columnconfigure(1, minsize=200, weight=0)

    def process(self):
        # Creates the main window
        self.create()
        # Prompts to log in
        self.login()
        # The locking function to don't freeze the GUI
        self.window.mainloop()

    def main(self):
        try:
            parser = argparse.ArgumentParser(description="AllHands Client", usage="./client.py | python3 client.py")
            parser.add_argument("-v", "--version", action="version",
                                version="AllHands Client " + self.prog_ver + " by the What-do-I-know Company")
            parser.add_argument("-i", "--ip", type=str, default="0.0.0.0",
                                help="IP: Interface the client listens at (by default the application listens to all the IPs)")
            args = parser.parse_args()
            self.ip = args.ip

            self.process()
        except KeyboardInterrupt:
            print("error: program stopped by the user")
            self.quit_func(window=False)
        except Exception as e:
            print("error: internal " + type(e).__name__ + " occurred: " + str(e))
            easygui.exceptionbox(title="AllHands Panic", msg="An internal error occurred. That's the "
                                                             "only thing we know.")
            self.quit_func(window=False)


if __name__ == "__main__":
    for i in range(0, 1):
        Chatroom().main()
