import ttkbootstrap as ttk
from ttkbootstrap.constants import *

class ShareholderCard:
    def __init__(self, main, share_id, width = 100, height = 150):
        self.share_id = share_id
        self.width = width
        self.height = height

        self.x = 0
        self.y = 0
        self.in_zone = False

        self.frame = ttk.Frame(main, width=width, height=height, bootstyle="light")
        self.frame.pack_propagate(False)

        self.label = ttk.Label(
            self.frame,
            text=f"Shareholder #{share_id}",
        )
    
        self.frame.bind("<Button-1>", self.drag_start)
        self.frame.bind("<B1-Motion>", self.drag_motion)
        self.frame.bind("<ButtonRelease-1>", self.drag_stop)
    
    def drag_start(self, event):
        self.x = event.x
        self.y = event.y
        self.frame.lift()
    
    def drag_motion(self, event):
        x = self.frame.winfo_x() - self.x + event.x
        y = self.frame.winfo_y() - self.y + event.y
        self.frame.place(x=x, y=y)
    
    def drag_stop(self, event):
        print("logic")

