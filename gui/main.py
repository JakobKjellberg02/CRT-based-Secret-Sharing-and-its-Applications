import math
import ttkbootstrap as ttk
import tkinter as tk
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
from ttkbootstrap.dialogs import Querybox, Messagebox
from crt_secret_sharing.el_gamal_encryption import keygen, encrypt, partial_decrypt, reconstruct, decrypt
from crt_secret_sharing.weighted_crt_ss import weighted_setup

class ShareholderCard:
    def __init__(self, app, canvas, x, y, share_id, idx, share_value, weight):
        self.app = app
        self.canvas = canvas
        self.idx = idx
        self.share_id = share_id
        self.share_value = share_value
        self.weight = weight
        self.is_selected = False

        self.card_radius = 40
        self.card = canvas.create_oval(
            x - self.card_radius, y - self.card_radius,
            x + self.card_radius, y + self.card_radius,
            fill="white", outline="black", width=2, tags="card"
        )

        self.label = canvas.create_text(x, y, text=f"🂠 {share_id}", font=("Helvetica", 10, "bold"), tags="card")
        self.weight_label = canvas.create_text(x, y + 15, text=f"W: {weight}", font=("Helvetica", 8), tags="card")

        canvas.tag_bind(self.card, "<Button-1>", self.toggle_select)
        canvas.tag_bind(self.label, "<Button-1>", self.toggle_select)
        canvas.tag_bind(self.weight_label, "<Button-1>", self.toggle_select)

        # Binding for tooltip show/hide
        canvas.tag_bind(self.card, "<Enter>", self.on_enter)
        canvas.tag_bind(self.label, "<Enter>", self.on_enter)
        canvas.tag_bind(self.weight_label, "<Enter>", self.on_enter)
        canvas.tag_bind(self.card, "<Leave>", self.on_leave)
        canvas.tag_bind(self.label, "<Leave>", self.on_leave)
        canvas.tag_bind(self.weight_label, "<Leave>", self.on_leave)

    def build_tooltip_text(self):
        return (
            f"Share ID: {self.share_id}\n"
            f"Value: {self.share_value}\n"
            f"Weight: {self.weight}"
        )

    def toggle_select(self, event=None):
        self.is_selected = not self.is_selected
        color = "gold" if self.is_selected else "white"
        self.canvas.itemconfig(self.card, fill=color)
        self.app.update_selection(self)

    def on_enter(self, event):
        # Cancel any pending leave events
        if hasattr(self, "_leave_id") and self._leave_id:
            self.canvas.after_cancel(self._leave_id)
            self._leave_id = None
            
        # Schedule showing the tooltip after a very short delay
        # This helps prevent flickering when moving between items
        self._enter_id = self.canvas.after(50, lambda: self._show_tooltip(event))
    
    def _show_tooltip(self, event):
        x = event.x_root - self.app.root.winfo_rootx()
        y = event.y_root - self.app.root.winfo_rooty()
        self.app.show_tooltip(x + 15, y, self.build_tooltip_text(), self)
        self._enter_id = None

    def on_leave(self, event):
        # Cancel any pending enter events
        if hasattr(self, "_enter_id") and self._enter_id:
            self.canvas.after_cancel(self._enter_id)
            self._enter_id = None
            
        # Schedule hiding the tooltip after a short delay
        # This helps prevent flickering when moving between items
        self._leave_id = self.canvas.after(50, lambda: self._hide_tooltip(event))
    
    def _hide_tooltip(self, event):
        self.app.hide_tooltip(self)
        self._leave_id = None

    def get_reconstruction_data(self):
        return self.share_value

    def destroy(self):
        # Cancel any pending events
        if hasattr(self, "_enter_id") and self._enter_id:
            self.canvas.after_cancel(self._enter_id)
        if hasattr(self, "_leave_id") and self._leave_id:
            self.canvas.after_cancel(self._leave_id)
            
        self.canvas.delete(self.card)
        self.canvas.delete(self.label)


class PokerCRTApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Poker CRT Secret Sharing")
        self.root.geometry("1000x800")
        self.root.configure(bg="#000000")

        self.shares = []
        self.p_i = []
        self.weights = []
        self.T = 0
        self.t = 0
        self.p_0 = 0
        self.q = 0
        self.small_g = 0
        self.small_s = 0
        self.pk = 0
        self.c2 = 0
        self.seed = 0
        self.c1 = 0
        self.h_k = 0
        self.ciphertext = None

        self.cards = []
        self.selected_cards = {}
        self.encrypted_message = None
        self.current_weight = 0
        self.shareholder_count = 0

        # Tooltip management
        self.tooltip_anchor = tk.Label(self.root)
        self.tooltip = None
        self.active_tooltip_card = None
        self.tooltip_timer = None

        # --- Top Controls ---
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(fill=X)

        self.generate_button = ttk.Button(control_frame, text="Generate Shares", bootstyle=(WARNING, OUTLINE), command=self.prompt_for_shares)
        self.generate_button.pack(side=LEFT, padx=5)

        self.reconstruct_button = ttk.Button(control_frame, text="Reconstruct Secret", bootstyle=(SUCCESS, OUTLINE), command=self.attempt_reconstruction)
        self.reconstruct_button.pack(side=LEFT, padx=5)

        self.status_label = ttk.Label(control_frame, text="Welcome to the CRT Poker Table!", bootstyle="info", font=("Helvetica", 12))
        self.status_label.pack(side=LEFT, padx=10)

        # --- Poker Table Canvas ---
        self.canvas = tk.Canvas(self.root, width=800, height=600)
        self.canvas.configure(bg="#663300")
        self.canvas.pack(pady=50)

        # Oval "table"
        self.canvas.create_oval(100, 100, 700, 500, fill="#1a7e55", outline="#0f5e3d", width=8)

    def show_tooltip(self, x, y, text, card):
        # Cancel any pending tooltip timer
        if self.tooltip_timer:
            self.root.after_cancel(self.tooltip_timer)
            self.tooltip_timer = None
            
        # If tooltip is already showing from this card, don't recreate it
        if self.active_tooltip_card == card and self.tooltip:
            return
            
        # Hide any existing tooltip
        self._clear_tooltip()
        
        # Create and show the new tooltip
        self.tooltip_anchor.place(x=x, y=y)
        self.tooltip = ToolTip(self.tooltip_anchor, text=text, delay=0.1)
        self.active_tooltip_card = card
        self.tooltip.show_tip()

    def hide_tooltip(self, card=None):
        # Only hide if this is the card that created the tooltip or if card is None
        if card is None or card == self.active_tooltip_card:
            # Set a timer to clear the tooltip rather than clearing immediately
            # This helps prevent flicker when moving between parts of the same card
            if self.tooltip_timer:
                self.root.after_cancel(self.tooltip_timer)
            self.tooltip_timer = self.root.after(50, self._clear_tooltip)

    def _clear_tooltip(self):
        # Actually remove the tooltip
        if self.tooltip:
            self.tooltip.hide_tip()
            self.tooltip_anchor.place_forget()
            self.tooltip = None
            self.active_tooltip_card = None
            self.tooltip_timer = None

    def prompt_for_shares(self):
        p_lambda = Querybox.get_integer(
            parent=self.root,
            title="Share distribution",
            prompt="Enter λ (security bits):",
            initialvalue=64
        )
        if p_lambda is None: return

        n = Querybox.get_integer(
            parent=self.root,
            title="Efficient Weighted Threshold Encryption",
            prompt="Enter number of shareholders:",
            initialvalue=3,
            minvalue=2
        )
        if n is None: return

        weights = []
        for i in range(n):
            weight = Querybox.get_integer(
                parent=self.root,
                title="Efficient Weighted Threshold Encryption",
                prompt=f"Enter weight for shareholder {i+1}:",
                initialvalue=(i+1)*10,
                minvalue=1
            )
            if weight is None: return
            weights.append(weight)

        t = Querybox.get_integer(
            parent=self.root,
            title="Efficient Weighted Threshold Encryption",
            prompt=f"Enter privacy threshold:",
            initialvalue=int(0.3 * sum(weights))
        )
        if t is None: return

        T = Querybox.get_integer(
            parent=self.root,
            title="Efficient Weighted Threshold Encryption",
            prompt=f"Enter reconstruction threshold:",
            initialvalue=int(0.7 * sum(weights))
        )
        if T is None: return

        message = Querybox.get_integer(
            parent=self.root,
            title="Share distribution",
            prompt="Enter the message (Type int):",
            initialvalue=1234
        )
        if message is None: return

        self.weights = weights
        self.t = t
        self.T = T

        try:
            self.p_0, self.q, self.small_g, self.small_s, self.pk = keygen(p_lambda)
            _, self.shares, self.q, self.p_i, _ = weighted_setup(p_lambda, n, T, t, weights, self.small_s, self.q)
            self.ciphertext, _ = encrypt(message, self.pk, self.small_g, self.p_0, self.q)
            self.c2, self.seed, self.c1, self.h_k = self.ciphertext
            self.status_label.config(text=f"Generated {n} shareholders.")
            self.generate_cards(n)
        except Exception as e:
            Messagebox.show_error(str(e), "Error")

    def generate_cards(self, n):
        # Clear canvas
        for card in self.cards:
            card.destroy()
        self.cards.clear()
        self.selected_cards.clear()
        self.canvas.delete("text")  # Clean up

        # Place cards in a circle
        cx, cy = 400, 300
        radius = 200
        for i in range(n):
            angle = 2 * math.pi * i / n
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            card = ShareholderCard(self, self.canvas, x, y, str(i+1), i, self.shares[i], self.weights[i])
            self.cards.append(card)

    def update_selection(self, card):
        if card.is_selected:
            self.selected_cards[card] = True
        else:
            self.selected_cards.pop(card, None)

        selected_cards = list(self.selected_cards.keys())
        self.current_weight = sum(card.weight for card in selected_cards)
        self.shareholder_count = len(selected_cards)

        self.status_label.config(text=f"{self.shareholder_count} shareholders selected with total weight {self.current_weight}.")

    def attempt_reconstruction(self):
        try:
            shareholders = set(card.idx for card in self.selected_cards)
            partial_decryptions = {}
            for card in self.selected_cards:
                mu_i = partial_decrypt(
                    card.idx, card.share_value, self.c1, self.p_0, shareholders,
                    self.p_i, self.q
                )
                partial_decryptions[card.idx] = mu_i
            
            k_constructed = reconstruct(partial_decryptions, self.c1, self.h_k,self.p_0, shareholders, 
                                        self.p_i, self.q)
            
            decrypted_message = decrypt(self.c2, k_constructed, self.seed)
            Messagebox.show_info(f"Decrypted message: {decrypted_message}", "Success!")
            self.status_label.config(text=f"Success! Message decrypted: {decrypted_message}")
                                     
        except Exception as e:
            Messagebox.show_error(str(e), "Reconstruction failed")

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = PokerCRTApp(root)
    root.mainloop()