import math
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Querybox
from crt_secret_sharing.crt_ss import share_distribution, share_reconstruction
from cards import ShareholderCard

class PokerCRTShare:
    def __init__(self, root):

        self.n = 0
        self.T = 0
        self.secret = 0
        self.p_lambda = 0
        self.S = 0
        self.shares = []
        self.P_0 = 0
        self.p_i = []

        self.cards = []
        self.active_cards = {}

        self.root = root
        self.root.title("CRT Secret Sharing")
        self.root.geometry("1000x800")

        style = ttk.Style()
        style.configure("TFrame", background="#0a5f38")

        self.poker_frame = ttk.Frame(root, bootstyle="TFrame")
        self.poker_frame.pack(fill="both", expand=True)

        self.left_panel = ttk.Frame(self.poker_frame, bootstyle="dark")
        self.left_panel.place(relx = 0, rely = 0, relwidth = 0.25, relheight = 1)

        self.panel_title = ttk.Label(
            self.left_panel,
            text="Shareholders",
            font=("Helvetica", 12, "bold"),
            anchor=ttk.CENTER,
            bootstyle="inverse-dark"
        )
        self.panel_title.pack(fill="x", pady=10, padx=5)

        self.container = ttk.Frame(self.left_panel, bootstyle="dark")
        self.container.pack(fill="both", expand=True, padx=5, pady=5)

        self.recreation_area = ttk.Frame(
            self.poker_frame, 
            bootstyle="secondary",
            width=400,
            height=300
        )
        self.recreation_area.place(relx=0.5, rely=0.6, anchor="center", relwidth=0.5, relheight=0.4)
        self.recreation_area.config(borderwidth=2, relief="groove")

        self.status_frame = ttk.Frame(self.poker_frame, bootstyle="dark")
        self.status_frame.place(relx=0.6, rely=0.1, anchor="center", relwidth=0.5, relheight=0.15)
        
        self.status_label = ttk.Label(
            self.status_frame,
            text="No shares generated yet",
            font=("Helvetica", 12),
            bootstyle="light"
        )
        self.status_label.pack(expand=True)

        self.prompt_button = ttk.Button(
            self.left_panel,
            text="Generate SHARES",
            bootstyle=(WARNING, "outline"),
            command=self.prompt_for_shares
        )
        self.prompt_button.pack(pady=10, padx=5)
    
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
        self.n = n
        self.T = t
        self.secret = secret
        self.p_lambda = p_lambda
        self.S, self.shares, self.p_0, self.p_i = share_distribution(self.p_lambda, 
                                              self.n, 
                                              self.T, 
                                              self.secret, 
                                              None, 
                                              None, 
                                              None, 
                                              False)
        self.generate_cards()
        

    def generate_cards(self):
        for widget in self.container.winfo_children():
            widget.destroy()
        
        self.cards = []
        
if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = PokerCRTShare(root)
    root.mainloop()