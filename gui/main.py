import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Querybox
import random

class PokerCRTShare:
    def __init__(self, root):
        self.root = root
        self.root.title("CRT Secret Sharing")
        self.root.geometry("800x600")

        style = ttk.Style()
        style.configure("TFrame", background="#0a5f38")

        self.poker_frame = ttk.Frame(root, bootstyle="TFrame")
        self.poker_frame.pack(fill="both", expand=True)

        self.prompt_button = ttk.Button(
            self.poker_frame, 
            text="Generate SHARES", 
            bootstyle=(WARNING, "outline"),
            command=self.prompt_for_shares
        )
        self.prompt_button.pack(side=RIGHT, padx=5, pady=10)
    
    def prompt_for_shares(self):
        n = Querybox.get_integer(
            parent=self.root,
            title="Share distribution",
            prompt="Enter n:",
            initialvalue=5,
        )
        if n is None:
            return
        
        t = Querybox.get_integer(
            parent=self.root,
            title="Share distribution",
            prompt="Enter the threshold value:",
        )
        if t is None:
            return
        
        secret = Querybox.get_integer(
            parent=self.root,
            title="Share distribution",
            prompt="Enter the secret value:",
        )
        if secret is None:
            return
        
        p_lambda = Querybox.get_integer(
            parent=self.root,
            title="Share distribution",
            prompt="Enter lambda:",
            initialvalue=64,
        )
        if p_lambda is None:
            return
        
        self.n = 0
        self.t = 0
        self.secret = 0
        self.p_lambda = 0
        self.shares = []


if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = PokerCRTShare(root)
    root.mainloop()