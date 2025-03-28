# Network Process Mapper

A command line application that captures network connections and associates them with the corresponding processes on your system.

![9a46b321ed7f2a279be0e80d31b0de9c](https://github.com/user-attachments/assets/1fa33a75-31f9-4bad-869f-a607dc21dfce)


## Prerequisites

- Python 3.7+
- Administrator privileges (required for network packet capture)

## Installation

### 1. Clone or download the repository

```bash
git clone https://github.com/ethanwaggoner/ProcessNetworkMapper.git
cd ProcessNetworkMapper
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

## Running the Program

Run the tool using the command line. Below are some example usages:

Run indefinitely with table display:

```bash
python network_process_mapper.py
```

Run for 30 seconds and display the table:

```bash
python network_process_mapper.py --time 30
```

Run indefinitely and output results to JSON on exit:

```bash
python network_process_mapper.py --json
```

Run for 30 seconds without real-time table output and save JSON:

```bash
python network_process_mapper.py --time 30 --json --no-table
```

Display help:
```bash
python network_process_mapper.py --help
```

## Security Notes

This application:
- Requires administrator/root privileges to function correctly
- Only captures TCP traffic on your local system
- Does not send any data over the network
- Stores all captured data in memory only (data is lost when the application is closed) unless specified to output to JSON.
