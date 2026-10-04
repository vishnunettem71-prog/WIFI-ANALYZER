import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import re
import platform
import threading


class WiFiAnalyzer:

    def __init__(self, root):
        self.root = root
        self.root.title("Wi-Fi Network Analyzer")
        self.root.geometry("1000x650")
        self.root.configure(bg="#101820")

        self.create_ui()

    def create_ui(self):

        # ---------------- TITLE ----------------
        title = tk.Label(
            self.root,
            text="WI-FI NETWORK ANALYZER",
            font=("Arial", 25, "bold"),
            fg="#00e5ff",
            bg="#101820"
        )
        title.pack(pady=20)

        subtitle = tk.Label(
            self.root,
            text="Scan and analyze nearby Wi-Fi networks",
            font=("Arial", 12),
            fg="white",
            bg="#101820"
        )
        subtitle.pack()

        # ---------------- BUTTON ----------------
        self.scan_button = tk.Button(
            self.root,
            text="SCAN WI-FI NETWORKS",
            font=("Arial", 13, "bold"),
            bg="#00e5ff",
            fg="black",
            padx=20,
            pady=10,
            command=self.start_scan
        )
        self.scan_button.pack(pady=20)

        # ---------------- STATUS ----------------
        self.status_label = tk.Label(
            self.root,
            text="Ready to scan",
            font=("Arial", 12, "bold"),
            fg="#00ff88",
            bg="#101820"
        )
        self.status_label.pack(pady=5)

        # ---------------- TABLE ----------------
        table_frame = tk.Frame(
            self.root,
            bg="#18232c"
        )
        table_frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=15
        )

        columns = (
            "SSID",
            "Signal",
            "Channel",
            "Frequency",
            "Security"
        )

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        for column in columns:

            self.table.heading(
                column,
                text=column
            )

            self.table.column(
                column,
                width=170,
                anchor="center"
            )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.table.yview
        )

        self.table.configure(
            yscrollcommand=scrollbar.set
        )

        self.table.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.pack(
            side="right",
            fill="y"
        )

        # ---------------- INFORMATION ----------------
        self.info_label = tk.Label(
            self.root,
            text="Networks Found: 0",
            font=("Arial", 13, "bold"),
            fg="white",
            bg="#101820"
        )
        self.info_label.pack(pady=10)

    # ------------------------------------------------
    # START SCAN
    # ------------------------------------------------

    def start_scan(self):

        self.scan_button.config(
            state="disabled"
        )

        self.status_label.config(
            text="Scanning nearby Wi-Fi networks...",
            fg="#ffaa00"
        )

        thread = threading.Thread(
            target=self.scan_wifi
        )

        thread.daemon = True
        thread.start()

    # ------------------------------------------------
    # SCAN WIFI
    # ------------------------------------------------

    def scan_wifi(self):

        try:

            if platform.system() != "Windows":

                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "Unsupported OS",
                        "This version is designed for Windows."
                    )
                )

                return

            command = [
                "netsh",
                "wlan",
                "show",
                "networks",
                "mode=bssid"
            ]

            result = subprocess.check_output(
                command,
                encoding="utf-8",
                errors="ignore"
            )

            networks = self.parse_networks(
                result
            )

            self.root.after(
                0,
                lambda: self.display_networks(
                    networks
                )
            )

        except Exception as e:

            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Scan Error",
                    str(e)
                )
            )

        finally:

            self.root.after(
                0,
                lambda: self.scan_button.config(
                    state="normal"
                )
            )

    # ------------------------------------------------
    # PARSE NETWORK INFORMATION
    # ------------------------------------------------

    def parse_networks(self, output):

        networks = []

        current_ssid = ""

        current_authentication = "Unknown"
        current_encryption = "Unknown"

        current_signal = ""
        current_channel = ""
        current_frequency = ""

        for line in output.splitlines():

            line = line.strip()

            # SSID
            if line.startswith("SSID") and "BSSID" not in line:

                match = re.search(
                    r"SSID\s+\d+\s*:\s*(.*)",
                    line
                )

                if match:

                    current_ssid = match.group(1).strip()

            # Authentication
            elif line.startswith(
                "Authentication"
            ):

                current_authentication = (
                    line.split(":", 1)[1].strip()
                )

            # Encryption
            elif line.startswith(
                "Encryption"
            ):

                current_encryption = (
                    line.split(":", 1)[1].strip()
                )

            # Signal
            elif line.startswith("Signal"):

                current_signal = (
                    line.split(":", 1)[1].strip()
                )

            # Channel
            elif line.startswith("Channel"):

                current_channel = (
                    line.split(":", 1)[1].strip()
                )

                frequency = self.channel_frequency(
                    current_channel
                )

                security = (
                    current_authentication
                    + " / "
                    + current_encryption
                )

                networks.append(
                    {
                        "ssid": current_ssid,
                        "signal": current_signal,
                        "channel": current_channel,
                        "frequency": frequency,
                        "security": security
                    }
                )

        return networks

    # ------------------------------------------------
    # CHANNEL TO FREQUENCY
    # ------------------------------------------------

    def channel_frequency(self, channel):

        try:

            ch = int(channel)

            # 2.4 GHz
            if 1 <= ch <= 13:

                return "2.4 GHz"

            # 5 GHz
            elif 36 <= ch <= 177:

                return "5 GHz"

            # 6 GHz
            elif 1 <= ch <= 233:

                return "2.4/5/6 GHz"

        except:

            pass

        return "Unknown"

    # ------------------------------------------------
    # DISPLAY NETWORKS
    # ------------------------------------------------

    def display_networks(self, networks):

        for item in self.table.get_children():

            self.table.delete(item)

        for network in networks:

            self.table.insert(
                "",
                "end",
                values=(
                    network["ssid"],
                    network["signal"],
                    network["channel"],
                    network["frequency"],
                    network["security"]
                )
            )

        self.info_label.config(
            text=f"Networks Found: {len(networks)}"
        )

        self.status_label.config(
            text="Scan completed",
            fg="#00ff88"
        )


# ----------------------------------------------------
# MAIN PROGRAM
# ----------------------------------------------------

if __name__ == "__main__":

    root = tk.Tk()

    app = WiFiAnalyzer(root)

    root.mainloop()