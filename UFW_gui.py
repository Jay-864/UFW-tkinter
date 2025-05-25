import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
from tkinter import ttk
import subprocess
from datetime import datetime

class UFWManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("UFW Firewall Manager")
        self.root.geometry("900x800")
        self.log_entries = []

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TButton', font=('Helvetica', 10), padding=6)
        self.style.configure('Title.TLabel', font=('Helvetica', 12, 'bold'), background='#f0f0f0')

        main_frame = ttk.Frame(root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill='x', pady=(0, 10))
        ttk.Label(title_frame, text="UFW Firewall Manager", style='Title.TLabel').pack()

        button_grid_frame = ttk.Frame(main_frame)
        button_grid_frame.pack(fill='x', pady=(0, 10))

        button_groups = [
            [
                ("Enable Firewall", self.enable_firewall),
                ("Disable Firewall", self.disable_firewall),
                ("Show Status", self.show_status)
            ],
            [
                ("List Rules", self.list_rules),
                ("Add Rule", self.show_add_rule_dialog),
                ("Delete Rule", self.delete_rule)
            ],
            [
                ("Reload Firewall", self.reload_firewall),
                ("Reset Firewall", self.reset_firewall),
                ("Default Policies", self.show_default_policies_dialog)
            ],
            [
                ("View Log", self.show_log),
                ("Exit", root.quit)
            ]
        ]

        for i, group in enumerate(button_groups):
            btn_frame = ttk.Frame(button_grid_frame)
            btn_frame.pack(side='left', expand=True, fill='both', padx=5)
            for (text, command) in group:
                btn = ttk.Button(btn_frame, text=text, command=command)
                btn.pack(fill='x', pady=2)

        output_frame = ttk.LabelFrame(main_frame, text="Firewall Output")
        output_frame.pack(fill='both', expand=True, pady=(5, 0))

        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            height=15,
            wrap='word',
            font=("Consolas", 10),
            padx=5,
            pady=5
        )
        self.output_text.pack(fill='both', expand=True)

        self.log_frame = ttk.LabelFrame(main_frame, text="Operation Log")
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
            height=8,
            wrap='word',
            font=("Consolas", 9),
            padx=5,
            pady=5,
            state='disabled'
        )
        self.log_text.pack(fill='both', expand=True)

        self.show_status()

    def log_action(self, action, details=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {action} {details}\n"
        self.log_entries.append(log_entry)
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def show_log(self):
        if self.log_frame.winfo_ismapped():
            self.log_frame.pack_forget()
        else:
            self.log_frame.pack(fill='both', expand=False, pady=(5, 0))

    def run_command(self, command):
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            self.log_action("COMMAND EXECUTED", command)
            return output
        except subprocess.CalledProcessError as e:
            self.log_action("COMMAND FAILED", f"{command} - {e.output}")
            return e.output

    def update_output(self, output):
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, output)
        self.output_text.see(tk.END)

    def enable_firewall(self):
        output = self.run_command("sudo ufw enable")
        self.update_output(output)

    def disable_firewall(self):
        output = self.run_command("sudo ufw disable")
        self.update_output(output)

    def show_status(self):
        output = self.run_command("sudo ufw status verbose")
        self.update_output(output)

    def list_rules(self):
        output = self.run_command("sudo ufw status numbered")
        self.update_output(output)

    def show_default_policies_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Set Default Policies")
        dialog.geometry("400x300")
        dialog.resizable(False, False)

        current_defaults = self.get_current_default_policies()

        incoming_frame = ttk.LabelFrame(dialog, text="Incoming Traffic")
        incoming_frame.pack(fill='x', padx=10, pady=5)

        incoming_policy = tk.StringVar(value=current_defaults.get('incoming', 'deny'))
        ttk.Radiobutton(incoming_frame, text="Deny (recommended)", variable=incoming_policy, value="deny").pack(anchor='w')
        ttk.Radiobutton(incoming_frame, text="Allow", variable=incoming_policy, value="allow").pack(anchor='w')

        outgoing_frame = ttk.LabelFrame(dialog, text="Outgoing Traffic")
        outgoing_frame.pack(fill='x', padx=10, pady=5)

        outgoing_policy = tk.StringVar(value=current_defaults.get('outgoing', 'allow'))
        ttk.Radiobutton(outgoing_frame, text="Allow (recommended)", variable=outgoing_policy, value="allow").pack(anchor='w')
        ttk.Radiobutton(outgoing_frame, text="Deny", variable=outgoing_policy, value="deny").pack(anchor='w')

        routing_frame = ttk.LabelFrame(dialog, text="Routing")
        routing_frame.pack(fill='x', padx=10, pady=5)

        routing_policy = tk.StringVar(value=current_defaults.get('routed', 'deny'))
        ttk.Radiobutton(routing_frame, text="Deny (recommended)", variable=routing_policy, value="deny").pack(anchor='w')
        ttk.Radiobutton(routing_frame, text="Allow", variable=routing_policy, value="allow").pack(anchor='w')

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill='x', pady=10)

        ttk.Button(
            btn_frame,
            text="Apply Policies",
            command=lambda: self.apply_default_policies(
                incoming_policy.get(),
                outgoing_policy.get(),
                routing_policy.get(),
                dialog
            )
        ).pack(side='left', padx=10)

        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side='right', padx=10)

    def get_current_default_policies(self):
        output = self.run_command("sudo ufw status verbose")
        policies = {}
        for line in output.split('\n'):
            if 'Default:' in line:
                parts = line.split()
                policies['incoming'] = parts[1].strip(')')
                policies['outgoing'] = parts[3].strip(')')
                policies['routed'] = parts[5].strip(')')
                break
        return policies

    def apply_default_policies(self, incoming, outgoing, routed, dialog):
        command = f"sudo ufw default {incoming} incoming && sudo ufw default {outgoing} outgoing && sudo ufw default {routed} routed"
        output = self.run_command(command)
        self.update_output(output)
        dialog.destroy()
        messagebox.showinfo("Success", "Default policies have been updated")

    def show_add_rule_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Firewall Rule")
        dialog.geometry("500x400")
        dialog.resizable(False, False)

        ttk.Label(dialog, text="Rule Type:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        rule_type = tk.StringVar(value="allow")
        ttk.Radiobutton(dialog, text="Allow", variable=rule_type, value="allow").grid(row=0, column=1, sticky='w')
        ttk.Radiobutton(dialog, text="Deny", variable=rule_type, value="deny").grid(row=0, column=2, sticky='w')

        ttk.Label(dialog, text="Direction:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        direction = tk.StringVar(value="in")
        ttk.Radiobutton(dialog, text="Incoming", variable=direction, value="in").grid(row=1, column=1, sticky='w')
        ttk.Radiobutton(dialog, text="Outgoing", variable=direction, value="out").grid(row=1, column=2, sticky='w')

        ttk.Label(dialog, text="Common Services:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        common_services = ttk.Combobox(dialog, values=[
            "SSH (22/tcp)", "HTTP (80/tcp)", "HTTPS (443/tcp)",
            "DNS (53/udp)", "SMTP (25/tcp)", "POP3 (110/tcp)",
            "IMAP (143/tcp)", "MySQL (3306/tcp)", "Custom..."
        ])
        common_services.grid(row=2, column=1, columnspan=2, sticky='ew', padx=5)
        common_services.bind("<<ComboboxSelected>>", lambda e: self.update_port_entry(common_services, port_entry))

        ttk.Label(dialog, text="Port/Protocol:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        port_entry = ttk.Entry(dialog)
        port_entry.grid(row=3, column=1, columnspan=2, sticky='ew', padx=5)

        ttk.Label(dialog, text="From IP (optional):").grid(row=4, column=0, padx=5, pady=5, sticky='w')
        ip_entry = ttk.Entry(dialog)
        ip_entry.grid(row=4, column=1, columnspan=2, sticky='ew', padx=5)

        help_text = """Rule Syntax Examples:
- allow in 22/tcp
- deny in from 192.168.1.100
- allow out 53/udp
- allow in 80/tcp to any port 443"""

        help_frame = ttk.LabelFrame(dialog, text="Syntax Help")
        help_frame.grid(row=5, column=0, columnspan=3, sticky='ew', padx=5, pady=5)
        ttk.Label(help_frame, text=help_text, justify='left').pack(padx=5, pady=5)

        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=6, column=0, columnspan=3, pady=10)

        ttk.Button(btn_frame, text="Add Rule", command=lambda: self.add_rule_from_dialog(
            rule_type.get(),
            direction.get(),
            common_services.get(),
            port_entry.get(),
            ip_entry.get(),
            dialog
        )).pack(side='left', padx=5)

        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side='left', padx=5)

    def update_port_entry(self, combo, entry):
        selection = combo.get()
        if selection != "Custom...":
            port = selection.split("(")[1].split(")")[0]
            entry.delete(0, tk.END)
            entry.insert(0, port)

    def add_rule_from_dialog(self, rule_type, direction, common_service, port, ip, dialog):
        rule_parts = [rule_type, direction]
        if ip:
            rule_parts.append(f"from {ip}")
        if port:
            rule_parts.append(port)
        elif common_service and common_service != "Custom...":
            port_proto = common_service.split("(")[1].split(")")[0]
            rule_parts.append(port_proto)
        rule = " ".join(rule_parts)
        if rule:
            output = self.run_command(f"sudo ufw {rule}")
            self.update_output(output)
            dialog.destroy()

    def add_rule(self):
        rule = simpledialog.askstring("Add Rule", "Enter rule (e.g., allow 22/tcp or deny from 192.168.0.1):")
        if rule:
            output = self.run_command(f"sudo ufw {rule}")
            self.update_output(output)

    def delete_rule(self):
        self.list_rules()
        rule_num = simpledialog.askstring("Delete Rule", "Enter rule number to delete:")
        if rule_num:
            command = f"echo 'y' | sudo ufw delete {rule_num}"
            output = self.run_command(command)
            self.update_output(output)

    def reload_firewall(self):
        output = self.run_command("sudo ufw reload")
        self.update_output(output)

    def reset_firewall(self):
        confirm = messagebox.askyesno("Reset Firewall", "Reset firewall to default and disable it?")
        if confirm:
            output = self.run_command("echo 'y' | sudo ufw reset")
            self.update_output(output)

if __name__ == "__main__":
    root = tk.Tk()
    app = UFWManagerGUI(root)
    root.mainloop()