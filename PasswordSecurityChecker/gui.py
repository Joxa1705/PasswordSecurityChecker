import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import secrets
import string
import math
import hashlib
import json
import os
import requests


# =========================================================
# PROJECT INFORMATION
# =========================================================

APP_VERSION = "3.4"


# =========================================================
# GLOBAL VARIABLES
# =========================================================

password_history = set()
security_history = []

dark_mode = True

analytics_window = None
analytics_tree = None
analytics_labels = {}

ANALYTICS_FILE = os.path.join(
    os.path.expanduser("~"),
    ".password_security_checker_v31_history.json"
)

AUDIT_FILE = os.path.join(
    os.path.expanduser("~"),
    ".password_security_checker_v34_audit.json"
)

audit_history = []


# =========================================================
# COLORS
# =========================================================

BG_DARK = "#111827"
CARD_DARK = "#1f2937"
TEXT_DARK = "#f9fafb"
ENTRY_DARK = "#374151"

BG_LIGHT = "#f3f4f6"
CARD_LIGHT = "#ffffff"
TEXT_LIGHT = "#111827"
ENTRY_LIGHT = "#ffffff"


# =========================================================
# SECURITY CORE
# =========================================================

from security_core import (
    generate_password,
    is_common_password,
    detect_weak_pattern,
    calculate_entropy,
    check_password_breach,
    get_risk_level,
    calculate_security_health,
    analyze_password,
)


# =========================================================
# PERSISTENT ANALYTICS
# =========================================================

def save_analytics_history():

    try:
        with open(
            ANALYTICS_FILE,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                security_history[-200:],
                file,
                indent=2
            )
    except Exception:
        pass


def load_analytics_history():

    if not os.path.exists(ANALYTICS_FILE):
        return

    try:
        with open(
            ANALYTICS_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        if isinstance(data, list):
            security_history.clear()

            for item in data[-200:]:
                if isinstance(item, dict):
                    security_history.append(item)

    except Exception:
        security_history.clear()


# =========================================================
# AUDIT LOGGING V3.4
# =========================================================

def save_audit_history():

    try:
        with open(AUDIT_FILE, "w", encoding="utf-8") as file:
            json.dump(audit_history[-500:], file, indent=2, ensure_ascii=False)
    except Exception:
        pass


def load_audit_history():

    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            audit_history.clear()
            audit_history.extend(
                item for item in data[-500:] if isinstance(item, dict)
            )
    except Exception:
        audit_history.clear()


def write_audit_log(action, status="SUCCESS", details=""):
    """Record an audit event without storing passwords or password hashes."""

    safe_details = str(details).replace("\n", " ").strip()[:300]

    audit_history.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": str(action)[:100],
        "status": str(status)[:30],
        "details": safe_details,
    })

    del audit_history[:-500]
    save_audit_history()


load_audit_history()


# =========================================================
# RECORD SECURITY CHECK
# =========================================================

def record_security_check(
    check_type,
    result
):

    security_history.append({

        "time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "type": check_type,

        "score": result["score"],

        "strength": result["strength"],

        "risk": result["risk"],

        "breach_found": result["breach_found"],

        "breach_count": result["breach_count"],

        "common": result["common"],

        "weak_pattern": result.get("weak_pattern", False),

        "health": result.get("health", 0),

        "entropy": result["entropy"]
    })

    save_analytics_history()
    refresh_analytics()
    write_audit_log(
        f"{check_type}",
        "SUCCESS",
        f"Score={result.get('score', 0)}/5; Risk={result.get('risk', 'Unknown')}"
    )


# =========================================================
# LIVE CHECKLIST
# =========================================================

def update_live_checklist(event=None):

    password = password_entry.get()

    checks = [

        (
            "Length ≥ 8",
            len(password) >= 8
        ),

        (
            "Uppercase",
            any(c.isupper() for c in password)
        ),

        (
            "Lowercase",
            any(c.islower() for c in password)
        ),

        (
            "Number",
            any(c.isdigit() for c in password)
        ),

        (
            "Special character",
            any(
                c in string.punctuation
                for c in password
            )
        )
    ]

    score = sum(
        1
        for _, passed in checks
        if passed
    )

    score_label.config(
        text=f"Security Score: {score}/5"
    )

    if "health_label" in globals():
        health_label.config(
            text=f"Security Health: {score * 20}/100"
        )

    progress["value"] = score * 20

    for i, (text, passed) in enumerate(checks):

        if passed:

            checklist_labels[i].config(
                text=f"✓ {text}"
            )

        else:

            checklist_labels[i].config(
                text=f"✗ {text}"
            )


# =========================================================
# CHECK PASSWORD
# =========================================================

def check_password_gui():

    password = password_entry.get()

    if not password:

        messagebox.showwarning(
            "Warning",
            "Please enter a test password."
        )

        return

    result = analyze_password(password)

    output.configure(state="normal")

    output.delete(
        "1.0",
        tk.END
    )

    output.insert(
        tk.END,
        "PASSWORD SECURITY REPORT\n"
    )

    output.insert(
        tk.END,
        "=" * 45 + "\n\n"
    )

    output.insert(
        tk.END,
        f"Password Strength : "
        f"{result['strength']}\n"
    )

    output.insert(
        tk.END,
        f"Security Score    : "
        f"{result['score']}/5\n"
    )

    output.insert(
        tk.END,
        f"Entropy           : "
        f"{result['entropy']} bits\n"
    )

    output.insert(
        tk.END,
        f"Risk Level        : "
        f"{result['risk']}\n"
    )

    output.insert(
        tk.END,
        f"Security Health   : "
        f"{result['health']}/100\n\n"
    )

    if result["common"]:

        output.insert(
            tk.END,
            "Common Password   : YES ⚠️\n"
        )

    else:

        output.insert(
            tk.END,
            "Common Password   : NO ✓\n"
        )

    if result["breach_found"] is True:

        output.insert(
            tk.END,
            "Breach Status     : FOUND ⚠️\n"
        )

        output.insert(
            tk.END,
            f"Times Seen        : "
            f"{result['breach_count']}\n"
        )

    elif result["breach_found"] is False:

        output.insert(
            tk.END,
            "Breach Status     : NOT FOUND ✓\n"
        )

    else:

        output.insert(
            tk.END,
            "Breach Status     : CHECK FAILED\n"
        )

    output.insert(
        tk.END,
        (
            "Weak Pattern      : "
            + ("DETECTED ⚠️" if result.get("weak_pattern") else "NOT DETECTED ✓")
            + "\n"
        )
    )

    pattern_details = result.get("pattern_details", [])
    if pattern_details:
        output.insert(tk.END, "Pattern Details    :\n")
        for pattern in pattern_details:
            output.insert(tk.END, f"  • {pattern}\n")
    else:
        output.insert(tk.END, "Pattern Details    : None detected ✓\n")

    output.insert(
        tk.END,
        "\nRECOMMENDATIONS\n"
    )

    output.insert(
        tk.END,
        "-" * 45 + "\n"
    )

    if result["score"] < 5:

        output.insert(
            tk.END,
            "• Use at least 8 characters.\n"
        )

        output.insert(
            tk.END,
            "• Add uppercase letters.\n"
        )

        output.insert(
            tk.END,
            "• Add lowercase letters.\n"
        )

        output.insert(
            tk.END,
            "• Add numbers.\n"
        )

        output.insert(
            tk.END,
            "• Add special characters.\n"
        )

    if result["common"]:

        output.insert(
            tk.END,
            "• Avoid common passwords.\n"
        )

    if result.get("weak_pattern"):
        output.insert(
            tk.END,
            "• Avoid simple sequences, keyboard patterns, "
            "and repeated characters.\n"
        )

    if result["breach_found"] is True:

        output.insert(
            tk.END,
            "• Do not use a password found "
            "in breaches.\n"
        )

    if (
        result["score"] == 5
        and not result["common"]
        and result["breach_found"] is not True
    ):

        output.insert(
            tk.END,
            "✓ Password meets the basic "
            "security checks.\n"
        )

    # Only hash is stored.
    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()

    password_history.add(
        password_hash
    )

    output.configure(
        state="disabled"
    )

    record_security_check(
        "Password Check",
        result
    )


# =========================================================
# ACCOUNT SECURITY
# =========================================================

def account_security_gui():

    username = username_entry.get()
    password = password_entry.get()
    confirm_password = confirm_entry.get()

    if not username:

        messagebox.showwarning(
            "Warning",
            "Please enter a username."
        )

        return

    if not password:

        messagebox.showwarning(
            "Warning",
            "Please enter a test password."
        )

        return

    output.configure(state="normal")

    output.delete(
        "1.0",
        tk.END
    )

    output.insert(
        tk.END,
        "ACCOUNT SECURITY REPORT\n"
    )

    output.insert(
        tk.END,
        "=" * 45 + "\n\n"
    )

    if len(username) >= 4:

        output.insert(
            tk.END,
            "✓ Username length is acceptable.\n"
        )

    else:

        output.insert(
            tk.END,
            "✗ Username should be at least "
            "4 characters.\n"
        )

    if password == confirm_password:

        output.insert(
            tk.END,
            "✓ Password confirmation matches.\n"
        )

    else:

        output.insert(
            tk.END,
            "✗ Password confirmation does "
            "not match.\n"
        )

    if username.lower() == password.lower():

        output.insert(
            tk.END,
            "✗ Username and password are "
            "too similar.\n"
        )

    else:

        output.insert(
            tk.END,
            "✓ Username and password are "
            "different.\n"
        )

    if username.lower() in password.lower():

        output.insert(
            tk.END,
            "⚠️ Username appears inside "
            "the password.\n"
        )

    else:

        output.insert(
            tk.END,
            "✓ Username does not appear "
            "inside password.\n"
        )

    result = analyze_password(
        password,
        username
    )

    output.insert(
        tk.END,
        "\nPASSWORD ANALYSIS\n"
    )

    output.insert(
        tk.END,
        "-" * 45 + "\n"
    )

    output.insert(
        tk.END,
        f"Strength : "
        f"{result['strength']}\n"
    )

    output.insert(
        tk.END,
        f"Score    : "
        f"{result['score']}/5\n"
    )

    output.insert(
        tk.END,
        f"Risk     : "
        f"{result['risk']}\n"
    )

    output.insert(
        tk.END,
        f"Health   : "
        f"{result['health']}/100\n"
    )

    output.insert(
        tk.END,
        f"Weak Pattern : "
        f"{'Detected' if result.get('weak_pattern') else 'Not detected'}\n"
    )

    pattern_details = result.get("pattern_details", [])
    if pattern_details:
        output.insert(tk.END, "Pattern Details :\n")
        for pattern in pattern_details:
            output.insert(tk.END, f"  • {pattern}\n")
    else:
        output.insert(tk.END, "Pattern Details : None detected\n")

    if result["breach_found"] is True:

        output.insert(
            tk.END,
            f"Breaches : "
            f"{result['breach_count']}\n"
        )

    elif result["breach_found"] is False:

        output.insert(
            tk.END,
            "Breaches : Not found\n"
        )

    else:

        output.insert(
            tk.END,
            "Breaches : Check failed\n"
        )

    output.configure(
        state="disabled"
    )

    record_security_check(
        "Account Check",
        result
    )


# =========================================================
# GENERATE PASSWORD GUI
# =========================================================

def generate_password_gui():

    password = generate_password()

    password_entry.delete(
        0,
        tk.END
    )

    password_entry.insert(
        0,
        password
    )

    confirm_entry.delete(
        0,
        tk.END
    )

    confirm_entry.insert(
        0,
        password
    )

    update_live_checklist()


# =========================================================
# SHOW / HIDE PASSWORD
# =========================================================

def toggle_single_password(entry, button):
    """Show/hide one password field without affecting the other field."""
    if entry.cget("show") == "":
        entry.config(show="*")
        button.config(text="Show")
    else:
        entry.config(show="")
        button.config(text="Hide")


def toggle_password():

    # Keep backward compatibility: toggle both fields together.
    if password_entry.cget("show") == "":

        password_entry.config(show="*")
        confirm_entry.config(show="*")

        password_show_button.config(text="Show")
        confirm_show_button.config(text="Show")

    else:

        password_entry.config(show="")
        confirm_entry.config(show="")

        password_show_button.config(text="Hide")
        confirm_show_button.config(text="Hide")


# =========================================================
# CLEAR GUI
# =========================================================

def clear_gui():

    username_entry.delete(
        0,
        tk.END
    )

    password_entry.delete(
        0,
        tk.END
    )

    confirm_entry.delete(
        0,
        tk.END
    )

    output.configure(state="normal")

    output.delete(
        "1.0",
        tk.END
    )

    output.insert(
        tk.END,
        "PASSWORD SECURITY REPORT\n"
        + "=" * 45
        + "\n\n"
        "Enter a password above and click \"Check Password\" "
        "to generate the security report."
    )

    output.configure(state="disabled")

    update_live_checklist()


# =========================================================
# EXPORT REPORT
# =========================================================

def export_report():

    content = output.get(
        "1.0",
        tk.END
    ).strip()

    if not content:

        messagebox.showwarning(
            "Warning",
            "There is no report to export."
        )

        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[
            ("Text Files", "*.txt")
        ]
    )

    if not file_path:
        return

    try:

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(content)

        messagebox.showinfo(
            "Success",
            "Report exported successfully."
        )

    except Exception as e:

        messagebox.showerror(
            "Error",
            f"Could not export report:\n{e}"
        )


# =========================================================
# ANALYTICS STATISTICS
# =========================================================

def calculate_analytics():

    total = len(
        security_history
    )

    low = sum(
        1
        for item in security_history
        if item["risk"] == "LOW"
    )

    medium = sum(
        1
        for item in security_history
        if item["risk"] == "MEDIUM"
    )

    high = sum(
        1
        for item in security_history
        if item["risk"] == "HIGH"
    )

    breached = sum(
        1
        for item in security_history
        if item["breach_found"] is True
    )

    common = sum(
        1
        for item in security_history
        if item["common"]
    )

    if total > 0:

        average_score = round(
            sum(
                item["score"]
                for item in security_history
            ) / total,
            2
        )

    else:

        average_score = 0

    return {
        "total": total,
        "low": low,
        "medium": medium,
        "high": high,
        "breached": breached,
        "common": common,
        "average_score": average_score
    }


# =========================================================
# REFRESH ANALYTICS
# =========================================================

def refresh_analytics():

    if analytics_window is None:
        return

    try:

        if not analytics_window.winfo_exists():
            return

    except tk.TclError:

        return

    stats = calculate_analytics()

    for key, value in stats.items():

        if key in analytics_labels:

            analytics_labels[key].config(
                text=str(value)
            )

    if analytics_tree is None:
        return

    for item in analytics_tree.get_children():

        analytics_tree.delete(
            item
        )

    latest_checks = security_history[-20:]

    for item in reversed(
        latest_checks
    ):

        if item["breach_found"] is True:

            breach = "YES"

        elif item["breach_found"] is False:

            breach = "NO"

        else:

            breach = "N/A"

        analytics_tree.insert(
            "",
            tk.END,
            values=(
                item["time"],
                item["type"],
                f"{item['score']}/5",
                item["strength"],
                item["risk"],
                breach
            )
        )


# =========================================================
# OPEN ANALYTICS
# =========================================================

def open_analytics():

    global analytics_window
    global analytics_tree
    global analytics_labels

    if (
        analytics_window is not None
        and analytics_window.winfo_exists()
    ):

        analytics_window.lift()

        refresh_analytics()

        return

    analytics_window = tk.Toplevel(
        root
    )

    analytics_window.title(
        "Security Analytics V2.9"
    )

    analytics_window.geometry(
        "850x600"
    )

    analytics_window.minsize(
        750,
        500
    )

    analytics_labels = {}

    bg = (
        BG_DARK
        if dark_mode
        else BG_LIGHT
    )

    card = (
        CARD_DARK
        if dark_mode
        else CARD_LIGHT
    )

    text = (
        TEXT_DARK
        if dark_mode
        else TEXT_LIGHT
    )

    analytics_window.configure(
        bg=bg
    )

    title = tk.Label(
        analytics_window,
        text="📊 Security Analytics",
        font=("Segoe UI", 20, "bold"),
        bg=bg,
        fg=text
    )

    title.pack(
        pady=(15, 10)
    )

    stats_frame = tk.Frame(
        analytics_window,
        bg=bg
    )

    stats_frame.pack(
        fill="x",
        padx=15
    )

    stats = [
        ("Total", "total"),
        ("Low", "low"),
        ("Medium", "medium"),
        ("High", "high"),
        ("Avg Score", "average_score"),
        ("Breached", "breached"),
        ("Common", "common")
    ]

    for i, (label_text, key) in enumerate(stats):

        stats_frame.grid_columnconfigure(
            i,
            weight=1
        )

        card_frame = tk.Frame(
            stats_frame,
            bg=card
        )

        card_frame.grid(
            row=0,
            column=i,
            padx=3,
            sticky="nsew"
        )

        label = tk.Label(
            card_frame,
            text=label_text,
            font=("Segoe UI", 9),
            bg=card,
            fg=text
        )

        label.pack(
            pady=(8, 1)
        )

        value = tk.Label(
            card_frame,
            text="0",
            font=("Segoe UI", 14, "bold"),
            bg=card,
            fg=text
        )

        value.pack(
            pady=(0, 8)
        )

        analytics_labels[key] = value

    history_title = tk.Label(
        analytics_window,
        text="Recent Security Checks",
        font=("Segoe UI", 13, "bold"),
        bg=bg,
        fg=text
    )

    history_title.pack(
        anchor="w",
        padx=15,
        pady=(15, 5)
    )

    tree_frame = tk.Frame(
        analytics_window,
        bg=bg
    )

    tree_frame.pack(
        fill="both",
        expand=True,
        padx=15
    )

    columns = (
        "time",
        "type",
        "score",
        "strength",
        "risk",
        "breach"
    )

    analytics_tree = ttk.Treeview(
        tree_frame,
        columns=columns,
        show="headings"
    )

    analytics_tree.heading(
        "time",
        text="Time"
    )

    analytics_tree.heading(
        "type",
        text="Type"
    )

    analytics_tree.heading(
        "score",
        text="Score"
    )

    analytics_tree.heading(
        "strength",
        text="Strength"
    )

    analytics_tree.heading(
        "risk",
        text="Risk"
    )

    analytics_tree.heading(
        "breach",
        text="Breach"
    )

    analytics_tree.column(
        "time",
        width=150
    )

    analytics_tree.column(
        "type",
        width=110
    )

    analytics_tree.column(
        "score",
        width=70
    )

    analytics_tree.column(
        "strength",
        width=100
    )

    analytics_tree.column(
        "risk",
        width=80
    )

    analytics_tree.column(
        "breach",
        width=70
    )

    scrollbar = ttk.Scrollbar(
        tree_frame,
        orient="vertical",
        command=analytics_tree.yview
    )

    analytics_tree.configure(
        yscrollcommand=scrollbar.set
    )

    analytics_tree.pack(
        side="left",
        fill="both",
        expand=True
    )

    scrollbar.pack(
        side="right",
        fill="y"
    )

    button_frame = tk.Frame(
        analytics_window,
        bg=bg
    )

    button_frame.pack(
        pady=10
    )

    export_button = tk.Button(
        button_frame,
        text="📄 Export Analytics",
        command=export_analytics,
        font=("Segoe UI", 10, "bold"),
        bg="#2563eb",
        fg="white",
        relief="flat",
        padx=12,
        pady=6,
        cursor="hand2"
    )

    export_button.pack(
        side="left",
        padx=4
    )

    clear_button = tk.Button(
        button_frame,
        text="🗑 Clear History",
        command=clear_analytics_history,
        font=("Segoe UI", 11, "bold"),
        bg="#dc2626",
        fg="white",
        relief="flat",
        padx=12,
        pady=6,
        cursor="hand2"
    )

    clear_button.pack(
        side="left",
        padx=4
    )

    refresh_analytics()


# =========================================================
# EXPORT ANALYTICS
# =========================================================

def export_analytics():

    stats = calculate_analytics()

    if stats["total"] == 0:

        messagebox.showwarning(
            "Warning",
            "There is no analytics data yet."
        )

        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[
            ("Text Files", "*.txt")
        ]
    )

    if not file_path:
        return

    try:

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                "PASSWORD SECURITY CHECKER V3.1\n"
            )

            file.write(
                "SECURITY ANALYTICS REPORT\n"
            )

            file.write(
                "=" * 60 + "\n\n"
            )

            file.write(
                f"Total Checks: {stats['total']}\n"
            )

            file.write(
                f"Low Risk: {stats['low']}\n"
            )

            file.write(
                f"Medium Risk: {stats['medium']}\n"
            )

            file.write(
                f"High Risk: {stats['high']}\n"
            )

            file.write(
                f"Average Score: "
                f"{stats['average_score']}/5\n"
            )

            file.write(
                f"Breached: {stats['breached']}\n"
            )

            file.write(
                f"Common Passwords: "
                f"{stats['common']}\n\n"
            )

            file.write(
                "CHECK HISTORY\n"
            )

            file.write(
                "-" * 60 + "\n"
            )

            for item in security_history:

                if item["breach_found"] is True:

                    breach = "YES"

                elif item["breach_found"] is False:

                    breach = "NO"

                else:

                    breach = "N/A"

                file.write(
                    f"{item['time']} | "
                    f"{item['type']} | "
                    f"Score: {item['score']}/5 | "
                    f"{item['strength']} | "
                    f"Risk: {item['risk']} | "
                    f"Breach: {breach}\n"
                )

        messagebox.showinfo(
            "Success",
            "Analytics exported successfully."
        )

    except Exception as e:

        messagebox.showerror(
            "Error",
            f"Could not export analytics:\n{e}"
        )


# =========================================================
# CLEAR ANALYTICS HISTORY
# =========================================================

def clear_analytics_history():

    if not security_history:

        messagebox.showinfo(
            "Info",
            "Analytics history is already empty."
        )

        return

    answer = messagebox.askyesno(
        "Clear History",
        "Are you sure you want to clear "
        "all analytics history?"
    )

    if not answer:
        return

    security_history.clear()
    save_analytics_history()

    try:
        if os.path.exists(ANALYTICS_FILE):
            os.remove(ANALYTICS_FILE)
    except Exception:
        pass

    refresh_analytics()

    messagebox.showinfo(
        "Success",
        "Analytics history cleared."
    )


# =========================================================
# EDUCATION MODULE V3.2
# =========================================================

def open_education():

    education_window = tk.Toplevel(root)
    education_window.title("Password Security Education V3.2")
    education_window.geometry("900x700")
    education_window.minsize(700, 520)
    education_window.configure(
        bg=BG_DARK if dark_mode else BG_LIGHT
    )

    bg = BG_DARK if dark_mode else BG_LIGHT
    card = CARD_DARK if dark_mode else CARD_LIGHT
    text = TEXT_DARK if dark_mode else TEXT_LIGHT
    entry = ENTRY_DARK if dark_mode else ENTRY_LIGHT

    header = tk.Frame(education_window, bg=bg)
    header.pack(fill="x", padx=20, pady=(18, 8))

    tk.Label(
        header,
        text="🎓 Password Security Education",
        font=("Segoe UI", 20, "bold"),
        bg=bg,
        fg=text
    ).pack(anchor="w")

    tk.Label(
        header,
        text="Learn why passwords become weak and how to protect accounts.",
        font=("Segoe UI", 11),
        bg=bg,
        fg=text
    ).pack(anchor="w", pady=(4, 0))

    content_frame = tk.Frame(education_window, bg=bg)
    content_frame.pack(fill="both", expand=True, padx=20, pady=(5, 15))

    scrollbar = tk.Scrollbar(content_frame)
    scrollbar.pack(side="right", fill="y")

    education_text = tk.Text(
        content_frame,
        font=("Segoe UI", 11),
        bg=entry,
        fg=text,
        insertbackground=text,
        relief="flat",
        wrap="word",
        padx=18,
        pady=15,
        spacing1=2,
        spacing3=7,
        yscrollcommand=scrollbar.set
    )
    education_text.pack(side="left", fill="both", expand=True)
    scrollbar.config(command=education_text.yview)

    topics = [
        (
            "1. What makes a password strong?",
            "A strong password is long, difficult to guess, and not based on personal information. "
            "Using a unique password for every important account also limits damage if one password is exposed."
        ),
        (
            "2. Password length",
            "Longer passwords generally provide more possible combinations. A memorable passphrase can be "
            "a practical way to create a longer password without making it impossible to remember."
        ),
        (
            "3. Entropy",
            "Entropy is an estimate of how difficult a password may be to guess. Higher entropy usually means "
            "a larger search space. The checker shows entropy as one part of the overall security analysis."
        ),
        (
            "4. Common passwords",
            "Passwords such as common words, popular password choices, or simple variations are easier for "
            "attackers to guess. The checker flags passwords found in its common-password checks."
        ),
        (
            "5. Pattern analysis",
            "Simple sequences, repeated characters, keyboard patterns, years, and predictable substitutions "
            "can make a password weaker. Pattern Analysis identifies these warning signs."
        ),
        (
            "6. Breach checking",
            "The checker can use a privacy-preserving breach lookup based on a SHA-1 prefix. Only a partial "
            "hash is sent for the lookup; the full password is not sent to the breach service."
        ),
        (
            "7. Password managers and unique passwords",
            "A password manager can help create and store strong, unique passwords. This reduces the need to "
            "reuse the same password across many services."
        ),
        (
            "8. Multi-factor authentication (MFA)",
            "MFA adds another verification step in addition to a password. When available, enabling MFA can "
            "provide an additional layer of account protection."
        ),
        (
            "9. Important rule",
            "Never share your password with other people. For real accounts, use unique credentials and follow "
            "the security recommendations of the service you are using."
        )
    ]

    for title, body in topics:
        education_text.insert(tk.END, title + "\n", "topic")
        education_text.insert(tk.END, body + "\n\n", "body")

    education_text.tag_configure(
        "topic",
        font=("Segoe UI", 12, "bold"),
        foreground=text
    )
    education_text.tag_configure(
        "body",
        font=("Segoe UI", 11),
        foreground=text
    )

    education_text.configure(state="disabled")

    close_button = tk.Button(
        education_window,
        text="Close",
        command=education_window.destroy,
        font=("Segoe UI", 11, "bold"),
        bg="#2563eb",
        fg="white",
        relief="flat",
        padx=28,
        pady=8,
        cursor="hand2"
    )
    close_button.pack(pady=(0, 18))



# =========================================================
# SECURITY POLICIES MODULE V3.3
# =========================================================

def open_security_policies():

    policy_window = tk.Toplevel(root)
    policy_window.title("Security Policies V3.3")
    policy_window.geometry("920x720")
    policy_window.minsize(720, 560)

    bg = BG_DARK if dark_mode else BG_LIGHT
    card = CARD_DARK if dark_mode else CARD_LIGHT
    text = TEXT_DARK if dark_mode else TEXT_LIGHT
    entry = ENTRY_DARK if dark_mode else ENTRY_LIGHT

    policy_window.configure(bg=bg)

    header = tk.Frame(policy_window, bg=bg)
    header.pack(fill="x", padx=20, pady=(18, 8))

    tk.Label(
        header,
        text="🛡 Security Policies",
        font=("Segoe UI", 20, "bold"),
        bg=bg,
        fg=text
    ).pack(anchor="w")

    tk.Label(
        header,
        text="Check a password against practical security policies before using it.",
        font=("Segoe UI", 11),
        bg=bg,
        fg=text
    ).pack(anchor="w", pady=(4, 0))

    form = tk.Frame(policy_window, bg=card)
    form.pack(fill="x", padx=20, pady=(8, 10))

    tk.Label(
        form,
        text="Username (optional)",
        font=("Segoe UI", 10, "bold"),
        bg=card,
        fg=text
    ).grid(row=0, column=0, padx=12, pady=(12, 4), sticky="w")

    username_entry = tk.Entry(
        form,
        font=("Segoe UI", 11),
        bg=entry,
        fg=text,
        insertbackground=text,
        relief="flat"
    )
    username_entry.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="ew")

    tk.Label(
        form,
        text="Password",
        font=("Segoe UI", 10, "bold"),
        bg=card,
        fg=text
    ).grid(row=0, column=1, padx=12, pady=(12, 4), sticky="w")

    password_entry = tk.Entry(
        form,
        show="•",
        font=("Segoe UI", 11),
        bg=entry,
        fg=text,
        insertbackground=text,
        relief="flat"
    )
    password_entry.grid(row=1, column=1, padx=12, pady=(0, 12), sticky="ew")

    form.grid_columnconfigure(0, weight=1)
    form.grid_columnconfigure(1, weight=2)

    result_frame = tk.Frame(policy_window, bg=card)
    result_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

    result_scroll = tk.Scrollbar(result_frame)
    result_scroll.pack(side="right", fill="y")

    result_text = tk.Text(
        result_frame,
        font=("Cascadia Mono", 10),
        bg=entry,
        fg=text,
        insertbackground=text,
        relief="flat",
        wrap="word",
        padx=14,
        pady=12,
        yscrollcommand=result_scroll.set
    )
    result_text.pack(side="left", fill="both", expand=True)
    result_scroll.config(command=result_text.yview)

    def show_policies():
        password = password_entry.get()
        username = username_entry.get().strip()

        if not password:
            messagebox.showwarning(
                "Missing Password",
                "Enter a password to check the security policies."
            )
            return

        try:
            result = analyze_password(password, username)
        except Exception as exc:
            messagebox.showerror(
                "Policy Check Error",
                f"Could not analyze the password.\n\n{exc}"
            )
            return

        checks = [
            ("Minimum length (8+ characters)", len(password) >= 8),
            ("Uppercase letter", any(c.isupper() for c in password)),
            ("Lowercase letter", any(c.islower() for c in password)),
            ("Number", any(c.isdigit() for c in password)),
            ("Special character", any(not c.isalnum() for c in password)),
            ("Not a common password", not result.get("common", False)),
            ("No weak patterns", not result.get("weak_pattern", False)),
            ("No known breach exposure", not result.get("breach_found", False)),
        ]

        if username:
            checks.append(("Not similar to username", not any(
                "username" in item.lower()
                for item in result.get("pattern_details", [])
            )))

        passed = sum(ok for _, ok in checks)
        total = len(checks)

        if passed == total:
            status = "POLICY STATUS: PASS"
        elif passed >= total * 0.75:
            status = "POLICY STATUS: REVIEW"
        else:
            status = "POLICY STATUS: FAIL"

        lines = [
            "SECURITY POLICY REPORT",
            "=" * 45,
            "",
            status,
            f"Policies passed: {passed}/{total}",
            f"Security score: {result.get('score', 0)}/5",
            f"Risk level: {result.get('risk', 'Unknown')}",
            "",
            "POLICY CHECKS",
            "-" * 45,
        ]

        for name, ok in checks:
            lines.append(f"{'PASS' if ok else 'FAIL':<5} | {name}")

        lines.extend([
            "",
            "RECOMMENDATION",
            "-" * 45,
        ])

        failed = [name for name, ok in checks if not ok]
        if failed:
            lines.extend(f"• Fix: {name}" for name in failed)
        else:
            lines.append("• All configured policies passed.")

        result_text.configure(state="normal")
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, "\n".join(lines))
        result_text.configure(state="disabled")

        write_audit_log(
            "Security Policies",
            "SUCCESS",
            f"Policies passed={passed}/{total}; Status={status.replace('POLICY STATUS: ', '')}"
        )

    check_btn = tk.Button(
        policy_window,
        text="🛡 Check Security Policies",
        command=show_policies,
        font=("Segoe UI", 11, "bold"),
        bg="#7c3aed",
        fg="white",
        relief="flat",
        padx=20,
        pady=8,
        cursor="hand2"
    )
    check_btn.pack(pady=(0, 8))

    close_btn = tk.Button(
        policy_window,
        text="Close",
        command=policy_window.destroy,
        font=("Segoe UI", 10, "bold"),
        bg="#6b7280",
        fg="white",
        relief="flat",
        padx=24,
        pady=6,
        cursor="hand2"
    )
    close_btn.pack(pady=(0, 16))

# =========================================================
# AUDIT LOG VIEWER V3.4
# =========================================================

def open_audit_log():

    audit_window = tk.Toplevel(root)
    audit_window.title("Audit Log V3.4")
    audit_window.geometry("900x620")
    audit_window.minsize(700, 480)

    bg = BG_DARK if dark_mode else BG_LIGHT
    card = CARD_DARK if dark_mode else CARD_LIGHT
    text = TEXT_DARK if dark_mode else TEXT_LIGHT
    entry = ENTRY_DARK if dark_mode else ENTRY_LIGHT
    audit_window.configure(bg=bg)

    tk.Label(
        audit_window,
        text="🧾 Security Audit Log",
        font=("Segoe UI", 20, "bold"),
        bg=bg,
        fg=text
    ).pack(anchor="w", padx=20, pady=(18, 2))

    tk.Label(
        audit_window,
        text="Security events are recorded without storing passwords.",
        font=("Segoe UI", 10),
        bg=bg,
        fg=text
    ).pack(anchor="w", padx=20, pady=(0, 10))

    frame = tk.Frame(audit_window, bg=card)
    frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

    scrollbar = tk.Scrollbar(frame)
    scrollbar.pack(side="right", fill="y")

    log_text = tk.Text(
        frame,
        font=("Cascadia Mono", 10),
        bg=entry,
        fg=text,
        insertbackground=text,
        relief="flat",
        wrap="word",
        padx=14,
        pady=12,
        yscrollcommand=scrollbar.set
    )
    log_text.pack(fill="both", expand=True)
    scrollbar.config(command=log_text.yview)

    if not audit_history:
        log_text.insert(tk.END, "No audit events recorded yet.")
    else:
        for item in reversed(audit_history):
            log_text.insert(
                tk.END,
                f"[{item.get('time', 'Unknown')}] "
                f"{item.get('status', 'UNKNOWN')} | "
                f"{item.get('action', 'Unknown action')}\n"
                f"  {item.get('details', '')}\n\n"
            )

    log_text.configure(state="disabled")

    buttons = tk.Frame(audit_window, bg=bg)
    buttons.pack(fill="x", padx=20, pady=(0, 16))

    def export_audit():
        path = filedialog.asksaveasfilename(
            title="Export Audit Log",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                json.dump(audit_history, file, indent=2, ensure_ascii=False)
            messagebox.showinfo("Export Complete", "Audit log exported successfully.")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    def clear_audit():
        if not audit_history:
            return
        confirm = messagebox.askyesno(
            "Clear Audit Log",
            "Delete all stored audit events?"
        )
        if not confirm:
            return
        audit_history.clear()
        save_audit_history()
        log_text.configure(state="normal")
        log_text.delete("1.0", tk.END)
        log_text.insert(tk.END, "No audit events recorded yet.")
        log_text.configure(state="disabled")

    tk.Button(
        buttons, text="📤 Export", command=export_audit,
        font=("Segoe UI", 10, "bold"), bg="#2563eb", fg="white",
        relief="flat", padx=18, pady=7, cursor="hand2"
    ).pack(side="left", padx=(0, 6))

    tk.Button(
        buttons, text="🗑 Clear", command=clear_audit,
        font=("Segoe UI", 10, "bold"), bg="#dc2626", fg="white",
        relief="flat", padx=18, pady=7, cursor="hand2"
    ).pack(side="left", padx=6)

    tk.Button(
        buttons, text="Close", command=audit_window.destroy,
        font=("Segoe UI", 10, "bold"), bg="#6b7280", fg="white",
        relief="flat", padx=22, pady=7, cursor="hand2"
    ).pack(side="right")


# =========================================================
# THEME
# =========================================================

def toggle_theme():

    global dark_mode

    dark_mode = not dark_mode

    apply_theme()


def apply_theme():

    bg = (
        BG_DARK
        if dark_mode
        else BG_LIGHT
    )

    card = (
        CARD_DARK
        if dark_mode
        else CARD_LIGHT
    )

    text = (
        TEXT_DARK
        if dark_mode
        else TEXT_LIGHT
    )

    entry_bg = (
        ENTRY_DARK
        if dark_mode
        else ENTRY_LIGHT
    )

    root.configure(
        bg=bg
    )

    for widget in all_labels:

        try:

            widget.configure(
                bg=bg,
                fg=text
            )

        except:
            pass

    for widget in all_frames:

        try:

            widget.configure(
                bg=bg
            )

        except:
            pass

    for widget in card_frames:

        try:

            widget.configure(
                bg=card,
                highlightthickness=1,
                highlightbackground=(
                    "#111827" if not dark_mode else "#1f2937"
                ),
                highlightcolor=(
                    "#111827" if not dark_mode else "#1f2937"
                )
            )

        except:
            pass

    for widget in [
        username_entry,
        password_entry,
        confirm_entry
    ]:

        widget.configure(
            bg=entry_bg,
            fg=text,
            insertbackground=text,
            relief="solid",
            bd=1,
            highlightthickness=1,
            highlightbackground=(
                "#111827" if not dark_mode else "#4b5563"
            ),
            highlightcolor=(
                "#111827" if not dark_mode else "#4b5563"
            )
        )

    output.configure(
        bg=entry_bg,
        fg=text,
        insertbackground=text
    )

    # Inline Show/Hide buttons stay readable in both themes.
    show_button_bg = "#4b5563" if dark_mode else "#6b7280"

    for widget in [
        password_show_button,
        confirm_show_button
    ]:
        try:
            widget.configure(
                bg=show_button_bg,
                fg="white",
                relief="solid",
                bd=1
            )
        except:
            pass

    for widget in [
        password_row,
        confirm_row
    ]:
        try:
            widget.configure(
                bg=card,
                highlightthickness=1,
                highlightbackground=(
                    "#111827" if not dark_mode else "#1f2937"
                )
            )
        except:
            pass

    for widget in [
        checklist_title,
        score_label,
        username_label,
        password_label,
        confirm_label,
        output_title,
        health_label
    ]:

        try:

            widget.configure(
                bg=card,
                fg=text
            )

        except:
            pass

    for widget in checklist_labels:

        try:

            widget.configure(
                bg=card,
                fg=text
            )

        except:
            pass

    if dark_mode:

        theme_button.config(
            text="☀️ Light Mode",
            bg="#f59e0b",
            fg="white"
        )

    else:

        theme_button.config(
            text="🌙 Dark Mode",
            bg="#374151",
            fg="white"
        )

    update_live_checklist()


# =========================================================
# MAIN WINDOW
# =========================================================

root = tk.Tk()

# Let Tk scale widgets appropriately on high-DPI displays.
# High-DPI / 4K-friendly Tk scaling.
# Tkinter renders text as real fonts, so increasing the scale keeps it crisp
# instead of making it look like a low-resolution image.
try:
    dpi = root.winfo_fpixels("1i")
    # Tk's normal 96 DPI baseline should be used here.
    # Using 72 DPI makes the whole dashboard unnecessarily large
    # on Windows high-DPI displays and leaves too little room for
    # the Security Report.
    target_scale = max(1.0, dpi / 96.0)
    root.tk.call("tk", "scaling", target_scale)
except Exception:
    pass

root.title(
    "Password Security Checker V3.4"
)

# =========================================================
# RESPONSIVE WINDOW
# =========================================================
# The window uses the user's available screen size instead
# of a fixed 780x720 size.
screen_w = root.winfo_screenwidth()
screen_h = root.winfo_screenheight()

# Use most of the available screen so the Security Report remains visible.
window_w = max(760, int(screen_w * 0.90))
window_h = max(680, int(screen_h * 0.90))

# Do not make the window larger than the screen.
window_w = min(window_w, screen_w - 30)
window_h = min(window_h, screen_h - 70)

pos_x = max(0, (screen_w - window_w) // 2)
pos_y = max(0, (screen_h - window_h) // 2)

root.geometry(f"{window_w}x{window_h}+{pos_x}+{pos_y}")

# The user can freely resize the window.
root.resizable(True, True)

# Minimum size prevents the UI from becoming unusably small.
root.minsize(680, 620)

root.configure(
    bg=BG_DARK
)


# =========================================================
# STYLE
# =========================================================

style = ttk.Style()

try:
    style.theme_use("clam")
except:
    pass

style.configure(
    "TProgressbar",
    thickness=10
)

style.configure(
    "Treeview",
    rowheight=25,
    font=("Segoe UI", 12)
)

style.configure(
    "Treeview.Heading",
    font=("Segoe UI", 11, "bold")
)


# =========================================================
# WIDGET TRACKING
# =========================================================

all_labels = []
all_frames = []
card_frames = []


# =========================================================
# HEADER
# =========================================================

header_frame = tk.Frame(
    root,
    bg=BG_DARK
)

header_frame.pack(
    fill="x",
    padx=20,
    pady=(8, 3)
)

all_frames.append(
    header_frame
)

title_label = tk.Label(
    header_frame,
    text="🔐 Password Security Checker",
    font=("Segoe UI", 20, "bold"),
    bg=BG_DARK,
    fg=TEXT_DARK
)

title_label.pack()

all_labels.append(
    title_label
)

subtitle_label = tk.Label(
    header_frame,
    text="V3.2 • Professional Security Dashboard",
    font=("Segoe UI", 12),
    bg=BG_DARK,
    fg=TEXT_DARK
)

subtitle_label.pack(
    pady=(1, 0)
)

all_labels.append(
    subtitle_label
)


# =========================================================
# THEME BUTTON
# =========================================================

theme_button = tk.Button(
    root,
    text="☀️ Light Mode",
    command=toggle_theme,
    font=("Segoe UI", 11, "bold"),
    bg="#f59e0b",
    fg="white",
    relief="flat",
    padx=12,
    pady=2,
    cursor="hand2"
)

theme_button.pack(
    pady=(2, 5)
)


# =========================================================
# USERNAME CARD
# =========================================================

username_card = tk.Frame(
    root,
    bg=CARD_DARK
)

username_card.pack(
    fill="x",
    padx=20,
    pady=2
)

card_frames.append(
    username_card
)

username_label = tk.Label(
    username_card,
    text="Username",
    font=("Segoe UI", 11, "bold"),
    bg=CARD_DARK,
    fg=TEXT_DARK
)

username_label.pack(
    anchor="w",
    padx=10,
    pady=(3, 1)
)

all_labels.append(
    username_label
)

username_entry = tk.Entry(
    username_card,
    font=("Segoe UI", 12),
    bg=ENTRY_DARK,
    fg=TEXT_DARK,
    insertbackground=TEXT_DARK,
    relief="flat"
)

username_entry.pack(
    fill="x",
    padx=10,
    pady=(0, 6),
    ipady=2
)


# =========================================================
# PASSWORD CARD
# =========================================================

password_card = tk.Frame(
    root,
    bg=CARD_DARK
)

password_card.pack(
    fill="x",
    padx=20,
    pady=2
)

card_frames.append(
    password_card
)

password_label = tk.Label(
    password_card,
    text="Password",
    font=("Segoe UI", 11, "bold"),
    bg=CARD_DARK,
    fg=TEXT_DARK
)

password_label.pack(
    anchor="w",
    padx=10,
    pady=(3, 1)
)

all_labels.append(
    password_label
)

password_row = tk.Frame(
    password_card,
    bg=CARD_DARK
)

password_row.pack(
    fill="x",
    padx=10,
    pady=(0, 5)
)

password_row.grid_columnconfigure(0, weight=1)

password_entry = tk.Entry(
    password_row,
    font=("Segoe UI", 12),
    show="*",
    bg=ENTRY_DARK,
    fg=TEXT_DARK,
    insertbackground=TEXT_DARK,
    relief="flat"
)

password_entry.grid(
    row=0,
    column=0,
    sticky="ew",
    ipady=2
)

password_show_button = tk.Button(
    password_row,
    text="Show",
    command=lambda: toggle_single_password(password_entry, password_show_button),
    font=("Segoe UI", 11, "bold"),
    bg="#4b5563",
    fg="white",
    relief="flat",
    padx=12,
    pady=2,
    cursor="hand2"
)

password_show_button.grid(
    row=0,
    column=1,
    padx=(6, 0),
    sticky="ns"
)

password_entry.bind(
    "<KeyRelease>",
    update_live_checklist
)


# =========================================================
# CONFIRM PASSWORD
# =========================================================

confirm_label = tk.Label(
    password_card,
    text="Confirm Password",
    font=("Segoe UI", 11, "bold"),
    bg=CARD_DARK,
    fg=TEXT_DARK
)

confirm_label.pack(
    anchor="w",
    padx=10,
    pady=(2, 2)
)

all_labels.append(
    confirm_label
)

confirm_row = tk.Frame(
    password_card,
    bg=CARD_DARK
)

confirm_row.pack(
    fill="x",
    padx=10,
    pady=(0, 6)
)

confirm_row.grid_columnconfigure(0, weight=1)

confirm_entry = tk.Entry(
    confirm_row,
    font=("Segoe UI", 12),
    show="*",
    bg=ENTRY_DARK,
    fg=TEXT_DARK,
    insertbackground=TEXT_DARK,
    relief="flat"
)

confirm_entry.grid(
    row=0,
    column=0,
    sticky="ew",
    ipady=2
)

confirm_show_button = tk.Button(
    confirm_row,
    text="Show",
    command=lambda: toggle_single_password(confirm_entry, confirm_show_button),
    font=("Segoe UI", 11, "bold"),
    bg="#4b5563",
    fg="white",
    relief="flat",
    padx=12,
    pady=2,
    cursor="hand2"
)

confirm_show_button.grid(
    row=0,
    column=1,
    padx=(6, 0),
    sticky="ns"
)



# =========================================================
# CHECKLIST CARD
# =========================================================

checklist_card = tk.Frame(
    root,
    bg=CARD_DARK
)

checklist_card.pack(
    fill="x",
    padx=20,
    pady=(2, 1)
)

card_frames.append(
    checklist_card
)

checklist_title = tk.Label(
    checklist_card,
    text="Live Password Checklist",
    font=("Segoe UI", 13, "bold"),
    bg=CARD_DARK,
    fg=TEXT_DARK
)

checklist_title.pack(
    anchor="w",
    padx=10,
    pady=(2, 0)
)

all_labels.append(
    checklist_title
)

checklist_labels = []

check_names = [
    "Length ≥ 8",
    "Uppercase",
    "Lowercase",
    "Number",
    "Special character"
]

for name in check_names:

    label = tk.Label(
        checklist_card,
        text=f"✗ {name}",
        font=("Segoe UI", 8),
        bg=CARD_DARK,
        fg=TEXT_DARK,
        anchor="w"
    )

    label.pack(
        fill="x",
        padx=10,
        pady=0
    )

    checklist_labels.append(
        label
    )

    all_labels.append(
        label
    )


# =========================================================
# SCORE
# =========================================================

score_label = tk.Label(
    checklist_card,
    text="Security Score: 0/5",
    font=("Segoe UI", 11, "bold"),
    bg=CARD_DARK,
    fg=TEXT_DARK
)

score_label.pack(
    pady=(1, 0)
)

all_labels.append(
    score_label
)

health_label = tk.Label(
    checklist_card,
    text="Security Health: 0/100",
    font=("Segoe UI", 11, "bold"),
    bg=CARD_DARK,
    fg=TEXT_DARK
)

health_label.pack(
    pady=(0, 0)
)

all_labels.append(
    health_label
)

progress = ttk.Progressbar(
    checklist_card,
    orient="horizontal",
    length=400,
    mode="determinate",
    maximum=100
)

progress.pack(
    padx=10,
    pady=(1, 4),
    fill="x"
)


# =========================================================
# BUTTON ROW
# =========================================================

button_card = tk.Frame(
    root,
    bg=BG_DARK
)

button_card.pack(
    fill="x",
    padx=20,
    pady=(1, 1)
)

all_frames.append(
    button_card
)


# Responsive button columns: all four buttons expand equally.
for _column in range(5):
    button_card.grid_columnconfigure(_column, weight=1, uniform="main_buttons")

def create_button(
    parent,
    text,
    command,
    bg_color
):

    return tk.Button(
        parent,
        text=text,
        command=command,
        font=("Segoe UI", 11, "bold"),
        bg=bg_color,
        fg="white",
        relief="flat",
        padx=6,
        pady=3,
        cursor="hand2"
    )


check_button = create_button(
    button_card,
    "🔍 Check Password",
    check_password_gui,
    "#2563eb"
)

check_button.grid(
    row=0,
    column=0,
    padx=2,
    pady=2,
    sticky="ew"
)

account_button = create_button(
    button_card,
    "👤 Account Security",
    account_security_gui,
    "#7c3aed"
)

account_button.grid(
    row=0,
    column=1,
    padx=2,
    pady=2,
    sticky="ew"
)

generate_button = create_button(
    button_card,
    "⚡ Generate",
    generate_password_gui,
    "#059669"
)

generate_button.grid(
    row=0,
    column=2,
    padx=2,
    pady=2,
    sticky="ew"
)

analytics_button = create_button(
    button_card,
    "📊 Analytics",
    open_analytics,
    "#0891b2"
)

analytics_button.grid(
    row=0,
    column=3,
    padx=2,
    pady=2,
    sticky="ew"
)

education_button = create_button(
    button_card,
    "🎓 Education",
    open_education,
    "#db2777"
)

education_button.grid(
    row=0,
    column=4,
    padx=2,
    pady=2,
    sticky="ew"
)


# =========================================================
# SECOND BUTTON ROW
# =========================================================

button_card_2 = tk.Frame(
    root,
    bg=BG_DARK
)

button_card_2.pack(
    fill="x",
    padx=20,
    pady=(0, 2)
)

all_frames.append(
    button_card_2
)

clear_button = create_button(
    button_card_2,
    "🧹 Clear",
    clear_gui,
    "#6b7280"
)

clear_button.pack(
    side="left",
    padx=2,
    fill="x",
    expand=True
)

policy_button = create_button(
    button_card_2,
    "🛡 Security Policies",
    open_security_policies,
    "#7c3aed"
)

policy_button.pack(
    side="left",
    padx=2,
    fill="x",
    expand=True
)

audit_button = create_button(
    button_card_2,
    "🧾 Audit Log",
    open_audit_log,
    "#9333ea"
)

audit_button.pack(
    side="left",
    padx=2,
    fill="x",
    expand=True
)

export_button = create_button(
    button_card_2,
    "📄 Export Report",
    export_report,
    "#ea580c"
)

export_button.pack(
    side="left",
    padx=2,
    fill="x",
    expand=True
)


# =========================================================
# SECURITY REPORT CARD
# =========================================================

output_card = tk.Frame(
    root,
    bg=CARD_DARK
)

# Security Report is the main expandable area.
# It automatically takes all remaining vertical space after
# the checklist and buttons, so it cannot get pushed below
# the visible screen.
output_card.pack(
    fill="both",
    expand=True,
    padx=20,
    pady=(1, 8)
)

card_frames.append(
    output_card
)

output_title = tk.Label(
    output_card,
    text="Security Report",
    font=("Segoe UI", 13, "bold"),
    bg=CARD_DARK,
    fg=TEXT_DARK
)

output_title.pack(
    anchor="w",
    padx=10,
    pady=(2, 2)
)

all_labels.append(
    output_title
)


# =========================================================
# REPORT WITH SCROLLBAR
# =========================================================

output_frame = tk.Frame(
    output_card,
    bg=ENTRY_DARK
)

output_frame.pack(
    fill="both",
    expand=True,
    padx=10,
    pady=(0, 5)
)

output = tk.Text(
    output_frame,
    height=14,
    font=("Cascadia Mono", 10),
    bg=ENTRY_DARK,
    fg=TEXT_DARK,
    insertbackground=TEXT_DARK,
    relief="flat",
    wrap="word"
)

output.pack(
    side="left",
    fill="both",
    expand=True
)

output_scrollbar = tk.Scrollbar(
    output_frame,
    command=output.yview
)

output_scrollbar.pack(
    side="right",
    fill="y"
)

output.config(
    yscrollcommand=output_scrollbar.set
)

# Initial report content: the panel is visible immediately.
output.insert(
    tk.END,
    "PASSWORD SECURITY REPORT\n"
    + "=" * 45 + "\n\n"
    "Enter a password above and click \"Check Password\" "
    "to generate the full security report.\n\n"
    "The report will show strength, score, entropy, risk level, "
    "common-password status, and breach status."
)
output.configure(state="disabled")


# =========================================================
# INITIALIZE
# =========================================================

load_analytics_history()

apply_theme()

update_live_checklist()


# =========================================================
# START
# =========================================================

root.mainloop()