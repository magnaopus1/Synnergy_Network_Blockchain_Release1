import tkinter as tk
from tkinter import ttk

# Global theme settings
def set_theme(root):
    style = ttk.Style(root)
    root.tk.call('source', 'azure.tcl')
    style.theme_use('azure')
    style.configure('TButton', padding=6, relief='flat', background='#4CAF50', foreground='white')
    style.map('TButton', background=[('active', '#45a049')])
    style.configure('TLabel', background='white', foreground='#333')
    style.configure('TEntry', fieldbackground='white', foreground='#333')
    style.configure('TFrame', background='white')
    style.configure('TLabelframe', background='white', borderwidth=2, relief='groove')
    style.configure('TLabelframe.Label', background='white', foreground='#333')
    style.configure('TNotebook', background='white')
    style.configure('TNotebook.Tab', background='white', foreground='#333')
    style.configure('TScrollbar', troughcolor='white', background='#E0E0E0', bordercolor='white', arrowcolor='gray')
    style.configure('TCombobox', fieldbackground='white', foreground='#333')

def apply_common_styles(widget):
    widget.config(padx=10, pady=10)

def create_main_notebook(root):
    notebook = ttk.Notebook(root)
    notebook.pack(expand=1, fill='both')
    return notebook

# Function to set up each tab with respective GUI content
def setup_tab(notebook, tab_name, gui_module):
    tab = ttk.Frame(notebook)
    notebook.add(tab, text=tab_name)
    gui_module.create_widgets(tab)

def main():
    root = tk.Tk()
    root.title("Synnergy Network Wallet")
    root.geometry("1024x768")

    set_theme(root)
    
    notebook = create_main_notebook(root)

    import wallet_analyticsGui
    import wallet_backupsGui
    import wallet_complianceGui
    import wallet_coreGui
    import wallet_cryptoGui
    import wallet_displayGui
    import wallet_integrationGui
    import wallet_notificationGui

    setup_tab(notebook, "Analytics", wallet_analyticsGui)
    setup_tab(notebook, "Backups", wallet_backupsGui)
    setup_tab(notebook, "Compliance", wallet_complianceGui)
    setup_tab(notebook, "Core", wallet_coreGui)
    setup_tab(notebook, "Crypto", wallet_cryptoGui)
    setup_tab(notebook, "Display", wallet_displayGui)
    setup_tab(notebook, "Integration", wallet_integrationGui)
    setup_tab(notebook, "Notification", wallet_notificationGui)

    root.mainloop()

if __name__ == "__main__":
    main()
