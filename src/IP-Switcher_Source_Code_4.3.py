import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog, scrolledtext
import subprocess
import re
import csv
import webbrowser
from threading import Thread
import time
import json
import os
import sys

CREATE_NO_WINDOW = 0x08000000

def get_projects_folder():
    # Get the user application data directory
    if sys.platform.startswith('win'):
        # Windows path
        appdata_path = os.getenv('APPDATA')  # This gets the path to the AppData/Roaming directory
    else:
        # For other operating systems, you might want to adjust the path accordingly
        appdata_path = os.path.expanduser('~')  # Home directory for non-Windows
        messagebox.showerror("Error", "This app is only compatible with Windows")
        return

    # Define the projects folder name
    projects_folder_name = "IP Switcher Projects"

    # Construct the full path to the projects folder
    global appdata_path_app 
    appdata_path_app = os.path.join(appdata_path, "IP Switcher")
    global projects_folder_path
    projects_folder_path = os.path.join(appdata_path, "IP Switcher", projects_folder_name)

    # Ensure the directory exists
    if not os.path.exists(projects_folder_path):
        os.makedirs(projects_folder_path)  # Create the folder if it does not exist
    return

def get_interfaces():
    """ Retrieve network interface names with their current IP addresses and subnet masks using 'ipconfig' command. """
    cmd = "ipconfig"
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
    interfaces = []
    if result.returncode == 0:
        lines = result.stdout.split('\n')
        interface_dict = {}
        for line in lines:
            if line.startswith("Ethernet") or line.startswith("Wireless"):
                if interface_dict and 'ip' in interface_dict:  # Append only if IP is present
                    interfaces.append(interface_dict)
                interface_name = line.split('adapter')[1].split(':')[0].strip()
                interface_dict = {'name': interface_name}  # Start new dictionary with interface name
            elif "IPv4 Address" in line and 'name' in interface_dict:
                ip_address = line.split(':')[1].strip()
                interface_dict['ip'] = ip_address
            elif "Subnet Mask" in line and 'name' in interface_dict:
                subnet_mask = line.split(':')[1].strip()
                interface_dict['subnet'] = subnet_mask
            elif "Default Gateway" in line and 'name' in interface_dict:
                gateway = line.split(':')[1].strip()
                interface_dict['gateway'] = gateway
        if interface_dict and 'ip' in interface_dict:  # Append the last collected interface info if IP is present
            interfaces.append(interface_dict)
    else:
        messagebox.showerror("Error", "Failed to retrieve network interfaces")
    return interfaces

def refresh_interfaces(interface_dropdown, interface_var, interfaces_cache):
    """ Refresh the list of network interfaces """
    interfaces = get_interfaces()
    interfaces_cache[:] = interfaces  # Refresh the cache
    interface_dropdown['values'] = [interface['name'] for interface in interfaces]
    if interfaces:
        interface_var.set(interfaces[0]['name'])  # Automatically trigger update_display via trace
    else:
        interface_var.set('')

def load_config_from_csv(file_path, ip_entry, subnet_entry, gateway_entry):
    """ Load IP configuration from a CSV file """
    try:
        # Check delimiter in CSV
        with open(file_path, newline='') as csvfile:
            first_line = csvfile.readline()
            if first_line.count('\t') > first_line.count(','):
                delimiter = '\t'  # Use tab as the delimiter
            else:
                delimiter = ','   # Use comma as the delimiter

        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=delimiter)  # Specify the tab delimiter
            for i, row in enumerate(reader):
                if i < len(ip_entry):  # Ensure we do not go out of index bounds
                    # Unpack the row with defaults for missing values
                    ip = row[0] if len(row) > 0 else ''
                    subnet = row[1] if len(row) > 1 else ''
                    gateway = row[2] if len(row) > 2 else ''

                    ip_entry[i].delete(0, tk.END)
                    ip_entry[i].insert(0, ip)
                    if subnet:
                        subnet_entry[i].delete(0, tk.END)
                        subnet_entry[i].insert(0, subnet)
                    if gateway:
                        gateway_entry[i].delete(0, tk.END)
                        gateway_entry[i].insert(0, gateway)
    except ValueError as e:
        # Show error popup if a ValueError occurs
        messagebox.showerror("CSV Error", f"Error in uploaded file: {e}")    

def upload_config(interface_var, ip_entry, subnet_entry, gateway_entry):
    """ Handle CSV file upload """
    file_path = filedialog.askopenfilename(
        title="Open Config File",
        filetypes=[("CSV files", "*.csv"), ("TSV files", "*.tsv"), ("Text files", "*.txt")],
        initialdir=projects_folder_path)  # Add file types for clarity
    if file_path:
        load_config_from_csv(file_path, ip_entry, subnet_entry, gateway_entry)

def is_valid_ip(ip):
    """ Validate IP address format """
    pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return pattern.match(ip)

def change_ip(interface_var, ip_entry, subnet_entry, gateway_entry, ip_tree, ping_interval_entry, i, ip_current, subnet_current, gateway_current, interfaces_cache):
    interface_name = interface_var.get()
    ip = ip_entry[i].get()
    subnet = subnet_entry[i].get()
    gateway = gateway_entry[i].get()

    if not (is_valid_ip(ip) and is_valid_ip(subnet)):
        messagebox.showerror("Error", "Invalid IP or Subnet Mask format.")
        return
    if gateway and not is_valid_ip(gateway):
        messagebox.showerror("Error", "Invalid Gateway format.")
        return

    is_online, response_time = ping_ip(ip)
    if is_online:
        continue_choice = messagebox.askyesno(
            "IP Already in Use",
            f"The IP address {ip} is already in use on the network (response time: {response_time}). "
            f"Do you want to continue and set this IP address anyway?"
        )
        if not continue_choice:
            # If the user chooses not to continue, exit the function
            return

        #messagebox.showerror("Error", f"The IP address {ip} is already in use on the network (response time: {response_time}). Please choose a different IP.")
        #return

    # If IP is not in use, proceed with setting the new IP
    command = f"netsh interface ipv4 set address name=\"{interface_name}\" static {ip} {subnet} {gateway}"
    try:
        subprocess.run(command, check=True, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        #messagebox.showinfo("Success", "IP Address changed successfully!")

        # Refresh or update IP and gateway information
        new_ip = ip
        new_subnet = subnet
        new_gateway = gateway
        for interface in interfaces_cache:
            if interface['name'] == interface_name:
                interface['ip'] = new_ip
                interface['subnet'] = new_subnet
                interface['gateway'] = new_gateway
                break
        update_display(interface_var, ip_current, subnet_current, gateway_current, interfaces_cache)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to change IP: {str(e)}")

    export_project(ip_entry, subnet_entry, gateway_entry,ip_tree, ping_interval_entry, AUTOSAVE=True)



def update_display(interface_var, ip_current, subnet_current, gateway_current, interfaces_cache):
    selected_interface_name = interface_var.get()
    for interface in interfaces_cache:
        if interface['name'] == selected_interface_name:
            ip_current.config(state='normal')
            subnet_current.config(state='normal')
            gateway_current.config(state='normal')
            ip_current.delete(0, tk.END)
            ip_current.insert(0, interface['ip'])
            subnet_current.delete(0, tk.END)
            subnet_current.insert(0, interface['subnet'])
            gateway_current.delete(0, tk.END)
            gateway_current.insert(0, interface['gateway'])
            ip_current.config(state='readonly')
            subnet_current.config(state='readonly')
            gateway_current.config(state='readonly')
            break


# -------- PINGER --------
def ping_ip(ip):
    """ Ping an IP address and return a tuple of (online status, response time) """
    response_time = "N/A"
    result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], stdout=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if "time=" in line:
                response_time = line.split("time=")[1].split("ms")[0] + " ms"
                break
            elif "time<" in line:
                response_time = line.split("time<")[1].split("ms")[0] + " ms"
                break
        return (True, response_time)
    return (False, response_time)

def import_ip_file(ip_tree):
    """ Import IPs and hostnames from a file and populate the Treeview """

    file_path = filedialog.askopenfilename(
        title="Open IP List File",
        filetypes=[("CSV or TXT files", "*.txt;*.csv"), ("CSV files", "*.csv"), ("TSV files", "*.tsv"), ("Text files", "*.txt")]
        )
    if file_path:
        # Clear existing data in the treeview
        for item in ip_tree.get_children():
            ip_tree.delete(item)

        with open(file_path, "r") as file:
            for line in file:
                parts = line.strip().split()
                if len(parts) >= 1:
                    ip, hostname = parts[0], " ".join(parts[1:])
                    if is_valid_ip(ip):
                        if hostname: 
                            ip_tree.insert("", "end", values=(ip, hostname, "Not Checked", "N/A"))
                        else: 
                            ip_tree.insert("", "end", values=(ip, "", "Not Checked", "N/A"))
                    else:
                        messagebox.showerror("Error", "File contains invalid IP Address format.")
                        break

def open_ip_in_browser(ip):
    """ Open an IP address in the default web browser """
    if ip:  # Check if the IP address is not empty
        webbrowser.open(f'http://{ip}')  # Prepends 'http://' to the IP to form a proper URL

def add_new_ip(window, ip_tree):
    """ Function to add a new IP address and subnet mask to the Treeview. """
    ip = simpledialog.askstring("Input", "Enter new IP Address:", parent=window)
    if ip and is_valid_ip(ip):
        hostname = simpledialog.askstring("Input", "Enter Hostname:", parent=window)
        if hostname:
            ip_tree.insert("", "end", values=(ip, hostname, "Not Checked", "N/A"))
        else:
            ip_tree.insert("", "end", values=(ip, "", "Not Checked", "N/A"))
    else:
        messagebox.showerror("Error", "Invalid IP Address format.")

def export_ips_to_csv(ip_tree):
    """ Export IPs and hostnames from the Treeview to a CSV file. """
    # Ask the user for a file name and location to save the CSV
    file_path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        title="Save as",
        initialdir=projects_folder_path
    )
    
    if file_path:
        with open(file_path, mode='w', newline='') as file:
            # Set delimiter to tab instead of comma
            writer = csv.writer(file, delimiter='\t')
            # Iterate over all items in the Treeview
            for item in ip_tree.get_children():
                # Get values (Assuming IP is in the first column and Hostname in the second)
                row = ip_tree.item(item, 'values')
                # Extract only the IP address and hostname
                ip_address = row[0]
                hostname = row[1]
                # Write the extracted values to the CSV
                writer.writerow([ip_address, hostname])
        messagebox.showinfo("Success", "Data exported successfully to {}".format(file_path))
    else:
        messagebox.showwarning("Warning", "Export cancelled, no file was saved.")

def continuous_ping(ip_tree, ping_interval, running):
    """ Continuously ping all IPs in the treeview at the specified interval """
    while running[0]:
        for item in ip_tree.get_children():
            ip = ip_tree.item(item, "values")[0]
            is_online, response_time = ping_ip(ip)
            status = "Online" if is_online else "Offline"
            ip_tree.item(item, values=(ip, ip_tree.item(item, "values")[1], status, response_time))
        for i in range(ping_interval):
            time.sleep(1)
            if not running[0]:
                break


# -------- EXPORT PROJECT -----------
def export_project(ip_entry, subnet_entry, gateway_entry, ip_tree, ping_interval_entry, AUTOSAVE):
    """Export IP configurations and Ping Interval to a JSON file, excluding dynamic status data."""
    project_data = {
        'ip_configs': [(ip.get(), subnet.get(), gateway.get()) for ip, subnet, gateway in zip(ip_entry.values(), subnet_entry.values(), gateway_entry.values())],
        'tree_data': [
            (item[0], item[1]) for item in (ip_tree.item(child, 'values') for child in ip_tree.get_children())
        ],
        'ping_interval': ping_interval_entry.get()  # Export the ping interval
    }
    if not AUTOSAVE:
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Project",
            initialdir=projects_folder_path
        )
    else:
        file_path = os.path.join(projects_folder_path,"autosave.json")

    if file_path:
        with open(file_path, 'w') as jsonfile:
            json.dump(project_data, jsonfile, indent=4)
        if not AUTOSAVE: messagebox.showinfo("Success", "Project exported successfully to {}".format(file_path))

def import_project(ip_entry, subnet_entry, gateway_entry, ip_tree, ping_interval_entry, AUTOSAVE):
    """Import IP configurations and Ping Interval from a JSON file, excluding dynamic status data."""
    if not AUTOSAVE:
        file_path = filedialog.askopenfilename(
            title="Open Project File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=projects_folder_path
        )
    else:
        file_path = os.path.join(projects_folder_path,"autosave.json")
        if not os.path.exists(file_path): return

    if file_path:
        with open(file_path, 'r') as jsonfile:
            project_data = json.load(jsonfile)
        
        # Load IP configurations
        for i, (ip, subnet, gateway) in enumerate(project_data['ip_configs']):
            ip_entry[i].delete(0, tk.END)
            ip_entry[i].insert(0, ip)
            subnet_entry[i].delete(0, tk.END)
            subnet_entry[i].insert(0, subnet)
            gateway_entry[i].delete(0, tk.END)
            gateway_entry[i].insert(0, gateway)
        
        # Load Treeview data
        for item in ip_tree.get_children():
            ip_tree.delete(item)
        for ip, hostname in project_data['tree_data']:
            ip_tree.insert("", "end", values=(ip, hostname, "Not Checked", "N/A"))

        # Set Ping Interval
        ping_interval_entry.delete(0, tk.END)
        ping_interval_entry.insert(0, project_data['ping_interval'])

        if not AUTOSAVE: messagebox.showinfo("Success", "Project imported successfully from {}".format(file_path))

def open_help_page():
    help_window = tk.Toplevel()
    help_window.title("IP Switcher GUI Help Page")
    help_window.geometry("700x800")
    
    # Scrollable text widget to display help content
    help_text = scrolledtext.ScrolledText(help_window, wrap=tk.WORD, width=93, height=43, font=("Arial", 10))
    help_text.grid(row=0, column=0, padx=10, pady=10)
    
    # Insert help content into the scrolled text widget
    help_content = """
    VERSION: 4.3

    IP Switcher GUI Help Page
    
    This GUI-based tool allows users to manage, configure, and monitor IP addresses on a selected network interface. 
    Key functionalities include setting IP configurations, pinging to check network status, importing/exporting configurations, and more.
    
    ---------------------------------------------------------------------
    Interface Overview
    ---------------------------------------------------------------------
    
    Main Components:
    
    • Interface Selection:
        - Select the network interface from a dropdown to update its IP configurations.
    
    • Current Network Details:
        - Displays the current IP, Subnet Mask, and Gateway of the selected interface.
    
    • IP Configuration Fields:
        - Configure multiple IP addresses, Subnet Masks, and Gateways.
    
    • Action Buttons:
        - Execute various actions, including setting IP configurations, pinging IP addresses, 
          importing/exporting configurations, and more.
    
    • Treeview Table:
        - Shows IP addresses, hostnames, status, and response time for easy monitoring.
    
    ---------------------------------------------------------------------
    Using the Tool
    ---------------------------------------------------------------------
    
    1. Select a Network Interface:
        - Choose an interface from the Select Interface dropdown.
        - Refresh: Refreshes the list of available interfaces.
       
    2. Viewing Current Network Details:
        - Displays the current IP address, subnet mask, and gateway for the selected interface.
       
    3. Configuring IP Addresses:
        - Enter IP, Subnet Mask, and Gateway for each IP slot provided.
        - Set IP: Applies the entered IP configuration to the interface.
       
    4. Importing and Exporting Configurations:
        - Import IP List: Allows users to import a list of IP addresses from a file.
        - Export IP List: Exports the current list of IP addresses and hostnames to a CSV file.
        - Import/Export Project: Save or load complete IP configurations (including IP, subnet, gateway, and ping interval).
       
    5. Checking IP Status:
        - MonoPing Selected: Pings the selected IP to check its network status.
        - MonoPing All: Pings all listed IPs to check their statuses.
        - Start Multiping: Enables continuous pinging of listed IPs at specified intervals.
        
            • Set the interval (in seconds) in Ping Interval before starting.
            • Press the button again to stop continuous pinging.
           
    6. IP Monitoring Table (Treeview):
        - Displays IP addresses, hostnames, online/offline status, and response times.
        - Double-click a cell to edit IP address or hostname values.
        - Delete Selected IP: Deletes the selected IP from the table.
        - Open Selected in Browser: Opens the selected IP in a web browser.
    """
    
    help_text.insert(tk.END, help_content)
    help_text.configure(state='disabled')  # Make text read-only
    
    # Button to close the help window
    close_button = tk.Button(help_window, text="Close", command=help_window.destroy)
    close_button.grid(row=1, column=0, pady=10)


# ------- GUI --------

def create_ip_updater():
    window = tk.Tk()
    window.title("IP Switcher 4.3")
    window['padx'] = 4  # Add padding to the left and right
    window['pady'] = 4  # Add padding to the top and bottom

    # Set the window icon
    window.iconbitmap('icon2.ico')  # Specify the path to your icon file

    row = 0

    menu_bar = tk.Menu(window)
    window.config(menu=menu_bar)

    def close_application():
        export_project(ip_entry, subnet_entry, gateway_entry, ip_tree, ping_interval_entry, True)
        window.destroy()

    interface_var = tk.StringVar(window)
    interfaces_cache = []  # Cache interfaces to avoid re-fetching

    # Interface dropdown
    tk.Label(window, text="Select Interface:").grid(row=row, column=0, sticky='e')
    interface_dropdown = ttk.Combobox(window, textvariable=interface_var, state="readonly")
    interface_dropdown.grid(row=row, column=1, columnspan=3, sticky="ew")

    # Refresh button
    refresh_button = tk.Button(window, text="Refresh", command=lambda: refresh_interfaces(interface_dropdown, interface_var, interfaces_cache))
    refresh_button.grid(row=row, column=4)

    # ------- NEXT ROW ----------
    row += 1

    # Headers
    tk.Label(window, text="IP Address:").grid(row=row, column=1)
    tk.Label(window, text="Subnet Mask:").grid(row=row, column=3)
    tk.Label(window, text="Gateway:").grid(row=row, column=4)

    # ------- NEXT ROW ----------
    row += 1

    # Current IP and Subnet display
    tk.Label(window, text="Current IP Address:").grid(row=row, column=0, sticky='e')
    ip_current = tk.Entry(window, state='readonly')
    ip_current.grid(row=row, column=1)
    subnet_current = tk.Entry(window, state='readonly')
    subnet_current.grid(row=row, column=3)
    gateway_current = tk.Entry(window, state='readonly')
    gateway_current.grid(row=row, column=4)

     # ------- NEXT ROW ----------
    row += 1

    # Trace changes in the interface_var
    interface_var.trace_add("write", lambda *args: update_display(interface_var, ip_current, subnet_current, gateway_current, interfaces_cache))

    # Initial population of interfaces
    refresh_interfaces(interface_dropdown, interface_var, interfaces_cache)

    rows = 5
    ip_entry = {}
    subnet_entry = {}
    gateway_entry = {}
    set_ip_button = {}
    for i in range(rows):
        tk.Label(window, text=f"IP Number {i+1}: ").grid(row=row, column=0, sticky='e')
        ip_entry[i] = tk.Entry(window)
        ip_entry[i].grid(row=row, column=1)
        #tk.Label(window, text=" ").grid(row=row, column=2)
        subnet_entry[i] = tk.Entry(window)
        subnet_entry[i].grid(row=row, column=3)
        subnet_entry[i].insert(0, "255.255.255.0")
        gateway_entry[i] = tk.Entry(window)
        gateway_entry[i].grid(row=row, column=4)
        # Set IP Button
        set_ip_button[i] = tk.Button(window, text="Set IP", width=7,
                                command=lambda j=i: change_ip(interface_var, ip_entry, subnet_entry, gateway_entry, ip_tree, ping_interval_entry, j, ip_current, subnet_current, gateway_current, interfaces_cache))
        set_ip_button[i].grid(row=row, column=5, padx=3)
        row += 1

    # ------- NEXT ROW ----------
    #row += 1
    # CSV Config Upload Button
    #upload_button = tk.Button(window, text="Upload CSV Config", command=lambda: upload_config(interface_var, ip_entry, subnet_entry, gateway_entry))
    #upload_button.grid(row=row, column=0, columnspan=5, sticky="ew")

    # ------- NEXT ROW ----------
    row += 1

    def edit_tree_item(event):
    # Get the focused item and column
        item = ip_tree.focus()
        column = ip_tree.identify_column(event.x)

        # Only allow editing for IP and Hostname columns
        if column == "#1" or column == "#2":

            # Get the bounding box of the cell
            try:
                x, y, width, height = ip_tree.bbox(item, column)
            except:
                add_new_ip(window, ip_tree)
                return

            # Place the entry widget in the cell and set its current text to the cell's value
            entry = tk.Entry(ip_tree)
            entry.place(x=x, y=y, width=width, height=height, anchor='nw')

            def save_edit(event):
                new_value = entry.get()
                # Validation for IP address format if it's the IP column
                if column == "#1" and not is_valid_ip(new_value):
                    messagebox.showerror("Error", "Invalid IP Address format.")
                    entry.destroy()
                    return
                ip_tree.set(item, column=column, value=new_value)  # Update the Treeview item
                entry.destroy()  # Remove the entry widget

            entry.insert(0, ip_tree.item(item, 'values')[int(column[1:]) - 1])  # Pre-fill entry with current value
            entry.select_range(0, tk.END)  # Select the text
            entry.focus()  # Set focus on the entry widget
            entry.bind('<Return>', save_edit)  # Save the edit on Enter key
            entry.bind('<FocusOut>', lambda e: entry.destroy())  # Destroy entry if focus is lost

    # Treeview for displaying IPs, hostnames, status, and response time
    ip_tree = ttk.Treeview(window, columns=("IP", "Hostname", "Status", "Response Time"), show="headings", height=10)
    ip_tree.grid(row=row, column=0, columnspan=5, sticky="nsew")
    ip_tree.heading("IP", text="IP Address")
    ip_tree.heading("Hostname", text="Hostname")
    ip_tree.heading("Status", text="Status")
    ip_tree.heading("Response Time", text="Response Time")
    ip_tree.column("IP", width=100)
    ip_tree.column("Hostname", width=100)
    ip_tree.column("Status", width=80)
    ip_tree.column("Response Time", width=120)
    ip_tree.bind('<Double-1>', edit_tree_item)

    # Function to update the status and response time for all IPs
    def ping_all_ips():
        """ Ping all IPs in the Treeview and update their status and response time """
        for item in ip_tree.get_children():
            ip = ip_tree.item(item, "values")[0]
            is_online, response_time = ping_ip(ip)
            status = "Online" if is_online else "Offline"
            ip_tree.item(item, values=(ip, ip_tree.item(item, "values")[1], status, response_time))

    # Function to update the status
    def update_status():
        try:
            item = ip_tree.selection()[0]  # Get selected item
        except:
            messagebox.showerror("Error", "Select a line to ping")
            return
        ip = ip_tree.item(item, "values")[0]
        is_online, response_time = ping_ip(ip)
        status = "Online" if is_online else "Offline"
        ip_tree.item(item, values=(ip, ip_tree.item(item, "values")[1], status, response_time))

    # Function to open the IP in a browser
    def open_ip_in_browser():
        try: 
            selected_item = ip_tree.selection()[0]  # Get selected item
        except:
            messagebox.showerror("Error", "Select a line to open")
            return
        ip = ip_tree.item(selected_item, "values")[0]
        if ip:
            webbrowser.open(f'http://{ip}')
    
    def delete_selected_ip():
        try: 
            selected_item = ip_tree.selection()[0]  # Get selected item
        except:
            messagebox.showerror("Error", "Select a line to delete")
            return
        ip_tree.delete(selected_item)

    # ------- NEXT ROW ----------
    row += 1

    # Button for continuous ping
    ping_control_button = tk.Button(window, text="Start Multiping")
    ping_control_button.grid(row=row, column=0, sticky="ew")
    
    # Buttons for actions
    ping_button = tk.Button(window, text="MonoPing Selected", command=update_status)
    ping_button.grid(row=row, column=1, sticky="ew")

    # Button to ping all IPs
    ping_all_button = tk.Button(window, text="MonoPing All", command=ping_all_ips)
    ping_all_button.grid(row=row, column=3, sticky="ew")
    
    # Import button
    import_button = tk.Button(window, text="Import IP List", command=lambda: import_ip_file(ip_tree))
    import_button.grid(row=row, column=4, sticky="ew")


    # ------- NEXT ROW ----------
    row += 1

    # Button to add a new IP
    add_ip_button = tk.Button(window, text="Add New IP", command=lambda: add_new_ip(window, ip_tree))
    add_ip_button.grid(row=row, column=0, sticky="ew")

    # Button to delete a selected IP
    delete_button = tk.Button(window, text="Delete Selected IP", command=lambda: delete_selected_ip())
    delete_button.grid(row=row, column=1, sticky="ew")

    open_button = tk.Button(window, text="Open Selected in Browser", command=open_ip_in_browser)
    open_button.grid(row=row, column=3, sticky="ew")

    # Button to export IP and Hostname to CSV
    export_csv_button = tk.Button(window, text="Export IP List", command=lambda: export_ips_to_csv(ip_tree))
    export_csv_button.grid(row=row, column=4, sticky="ew")

    # ------- NEXT ROW ----------
    row += 1


    tk.Label(window, text="Ping Interval (s):").grid(row=row, column=0, sticky='e')
    ping_interval_entry = tk.Entry(window)
    ping_interval_entry.insert(0, "10")  # Default interval
    ping_interval_entry.grid(row=row, column=1)

    # Setting up control for continuous ping
    is_running = [False]  # Using list to maintain reference
    ping_thread = [None]  # Using list to keep thread reference

    def toggle_pinging():
        """Toggle the continuous pinging process."""
        if is_running[0]:
            is_running[0] = False
            ping_control_button.config(text="Start Pinging")
            if ping_thread[0] and ping_thread[0].is_alive():
                ping_thread[0].join()
        else:
            try:
                # Ensure at least 1 second interval and no more than 99 seconds
                ping_interval = int(ping_interval_entry.get())
                if ping_interval < 1 or ping_interval > 99:
                    raise ValueError("Ping interval must be between 1 and 99 seconds.")
            except ValueError as e:
                messagebox.showerror("Error", str(e))
                return
            
            is_running[0] = True
            ping_interval = max(1, int(ping_interval_entry.get()))  # Ensure at least 1 second interval
            ping_thread[0] = Thread(target=continuous_ping, args=(ip_tree, ping_interval, is_running))
            ping_thread[0].start()
            ping_control_button.config(text="Stop Pinging")

    ping_control_button.config(command=toggle_pinging)

    # FILE MENU
    file_menu = tk.Menu(menu_bar, tearoff=0)
    file_menu.add_command(label="Import Project", command=lambda: import_project(ip_entry, subnet_entry, gateway_entry, ip_tree, ping_interval_entry, False))
    file_menu.add_command(label="Export Project", command=lambda: export_project(ip_entry, subnet_entry, gateway_entry, ip_tree, ping_interval_entry, False))
    #file_menu.add_command(label="Open result directory", command=open_temp_folder)
    file_menu.add_separator()
    file_menu.add_command(label="Help", command=open_help_page)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=close_application)
    menu_bar.add_cascade(label="File", menu=file_menu)

    import_project(ip_entry, subnet_entry, gateway_entry, ip_tree, ping_interval_entry, True)

    window.mainloop()

if __name__ == "__main__":
    get_projects_folder()
    create_ip_updater()
