import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, Raw

window = tk.Tk()
window.title("Packet Sniffer")
window.geometry("800x600")
sniffing_active = False
output_file_path = 'packet_summaries.txt'

def packet_sniffer(packet):
    summary = packet.summary()
    with open(output_file_path, 'a') as f:
        f.write(summary + '\n')
    packet_log.insert(tk.END, summary + '\n')
    packet_log.yview(tk.END)
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet:
            data = packet[TCP].payload.load
            packet_log.insert(tk.END, f"Data between {ip_src} and {ip_dst}:\n{data.decode('utf-8', errors='ignore')}\n")
        elif UDP in packet:
            data = packet[UDP].payload.load
            packet_log.insert(tk.END, f"Data between {ip_src} and {ip_dst}:\n{data.decode('utf-8', errors='ignore')}\n")
        elif ICMP in packet:
            data = packet[ICMP].payload.load
            packet_log.insert(tk.END, f"Data between {ip_src} and {ip_dst}:\n{data.decode('utf-8', errors='ignore')}\n")

def start_sniffing():
    global sniffing_active
    selected_filters = [filter_listbox.get(i) for i in filter_listbox.curselection()]
    if selected_filters:
        if "All" in selected_filters:
            threading.Thread(target=sniff_packets, args=('Wi-Fi',)).start()
        else:
            filter_expr = " or ".join(selected_filters)
            threading.Thread(target=sniff_packets, args=('Wi-Fi', filter_expr)).start()
    else:
        messagebox.showerror("Error", "Please select at least one filter expression.")

# Function to sniff packets
def sniff_packets(interface, filter_expr=None):
    global sniffing_active
    sniffing_active = True
    sniff(iface=interface, prn=packet_sniffer, filter=filter_expr, stop_filter=lambda x: not sniffing_active, count=0)
    messagebox.showinfo("Packet Sniffing", "Packet sniffing stopped.")

# Function to stop sniffing
def stop_sniffing():
    global sniffing_active
    sniffing_active = False

def toggle_filter_listbox():
    if filter_listbox.winfo_viewable():
        filter_listbox.grid_forget()
        select_filter_button.config(text="Select Filter")
    else:
        filter_listbox.grid(row=2, column=1, padx=10, pady=5)
        select_filter_button.config(text="Hide Filter")

filter_options = ["All", "tcp", "udp", "icmp"]

top_frame = ttk.Frame(window, padding="10")
top_frame.grid(row=0, column=0, columnspan=2, sticky="ew")

select_filter_button = ttk.Button(top_frame, text="Select Filter", command=toggle_filter_listbox)
select_filter_button.grid(row=0, column=0, padx=10, pady=5)

start_button = ttk.Button(top_frame, text="Start Sniffing", command=start_sniffing)
start_button.grid(row=0, column=1, padx=10, pady=5)

stop_button = ttk.Button(top_frame, text="Stop Sniffing", command=stop_sniffing)
stop_button.grid(row=0, column=2, padx=10, pady=5)

middle_frame = ttk.Frame(window, padding="10")
middle_frame.grid(row=1, column=0, columnspan=2, sticky="ew")

filter_listbox = tk.Listbox(middle_frame, selectmode="multiple", height=len(filter_options))
for option in filter_options:
    filter_listbox.insert(tk.END, option)
filter_listbox.grid(row=2, column=1, padx=10, pady=5)

bottom_frame = ttk.Frame(window, padding="10")
bottom_frame.grid(row=2, column=0, columnspan=2, sticky="nsew")

packet_log_label = ttk.Label(bottom_frame, text="Packet Log")
packet_log_label.grid(row=0, column=0, padx=10, pady=5)

packet_log = scrolledtext.ScrolledText(bottom_frame, wrap=tk.WORD, height=20)
packet_log.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")

interface_label = ttk.Label(top_frame, text="Interface:")
interface_label.grid(row=1, column=0, padx=10, pady=5)

interface_var = tk.StringVar(value="Wi-Fi")  # Default interface
interface_dropdown = ttk.Combobox(top_frame, textvariable=interface_var, values=list(sniff(prn=lambda x: x.show())) )
interface_dropdown.grid(row=1, column=1, padx=10, pady=5)

filter_options.extend(["IP", "Port", "Protocol"])
filter_listbox.delete(0, tk.END)
for option in filter_options:
    filter_listbox.insert(tk.END, option)

custom_filter_label = ttk.Label(middle_frame, text="Custom Filter:")
custom_filter_label.grid(row=3, column=0, padx=10, pady=5)

custom_filter_entry = ttk.Entry(middle_frame)
custom_filter_entry.grid(row=3, column=1, padx=10, pady=5)

save_button = ttk.Button(top_frame, text="Save Data", command=lambda: save_packet_data(output_file_path))
save_button.grid(row=2, column=2, padx=10, pady=5)

def save_packet_data(file_path):
    with open(file_path, 'a') as f:
        f.write(packet_log.get("1.0", tk.END))
    messagebox.showinfo("Packet Data Saved", f"Packet data saved to {file_path}")

window.grid_rowconfigure(2, weight=1)
window.grid_columnconfigure(1, weight=1)

window.mainloop()
