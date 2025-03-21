# Network Process Mapper

A desktop application that captures and visualizes network connections and associates them with the corresponding processes on your system.

![ff184b0293e9cf8d9fe0bca622ea4588](https://github.com/user-attachments/assets/e3698b07-fdc1-4e6f-8e37-4888c12b70a5)


## Features

- Real-time network traffic monitoring
- Process-to-connection mapping
- Filtering by process, IP address, or custom search
- Sortable log entries
- Clean, responsive UI

## Prerequisites

- Python 3.7+
- Administrator privileges (required for network packet capture)

## Installation

### 1. Clone or download the repository

```bash
git clone https://github.com/yourusername/network-process-mapper.git
cd network-process-mapper
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Running the application

Run the application with administrator privileges (needed for packet capture):

#### Windows

Right-click on the command prompt or PowerShell and select "Run as administrator", then:

```bash
python app.py
```

#### macOS/Linux

```bash
sudo python3 app.py
```

### Using the application

1. Click "Start Capture" to begin capturing network traffic
2. The application will display connections in the table below
3. Use the search and filter options to find specific connections
4. Click column headers to sort the data
5. Click "Refresh Logs" to update the display with the latest data
6. Click "Stop Capture" when finished

## Security Notes

This application:
- Requires administrator/root privileges to function correctly
- Only captures TCP traffic on your local system
- Does not send any data over the network
- Stores all captured data in memory only (data is lost when the application is closed)
