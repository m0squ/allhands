import tkinter as tk
from styles import tooltip
import webbrowser


class Button(tk.Button):
    def __init__(self, *args, **kwargs):
        super(Button, self).__init__(*args, **kwargs,
                                     relief=tk.FLAT,
                                     font=("Noto Sans", 10),
                                     highlightbackground="grey",
                                     activebackground="orange",
                                     highlightthickness=1
                                     )


class Link(tk.Button):
    def __init__(self, url, *args, **kwargs):
        super(Link, self).__init__(*args, **kwargs,
                                   relief=tk.FLAT,
                                   cursor="hand2",
                                   fg="orange",
                                   bg="white",
                                   activebackground="white",
                                   highlightthickness=0
                                   )
        tooltip.create_tool_tip(self, url)
        self.bind("<Button-1>", lambda e: webbrowser.open(url))
def link(window, text, url):
    label = tk.Button(window, text=text, fg="orange", bg="white", activebackground="white", highlightthickness=0,
                      relief=tk.FLAT, cursor="hand2")
