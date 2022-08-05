import tkinter as tk
from styles import tooltip
import webbrowser

def link(window, text, url):
    label = tk.Button(window, text=text, fg="orange", bg="white", activebackground="light grey", highlightthickness=0,
                      relief=tk.FLAT, cursor="hand2")
    tooltip.createToolTip(label, url)
    label.pack()
    label.bind("<Button-1>", lambda e: webbrowser.open(url))