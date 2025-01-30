# core/report.py
import json
import csv
import os

def save_report(file_path, data):
    """Save the report data to a file in JSON or CSV format."""
    directory = os.path.dirname(file_path) or '.'
    
    # Ensure the reports directory exists
    os.makedirs(directory, exist_ok=True)
    
    if file_path.endswith('.json'):
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Report saved to {file_path}")
    elif file_path.endswith('.csv'):
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            for key, value in data.items():
                writer.writerow([key, value])
        print(f"Report saved to {file_path}")
    else:
        print("Unsupported file format. Please use .json or .csv")
