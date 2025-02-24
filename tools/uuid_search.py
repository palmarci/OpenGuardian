import os
import re
import argparse
import csv

# Global dictionary to store matches
matches = {}

def search_in_directory(directory, pattern, extensions):
    """Recursively search for a pattern in files with specified extensions within a directory."""
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                search_in_file(file_path, pattern)
                print(file_path)

def search_in_file(file_path, pattern):
    """Search for a pattern in a file and store matches."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            for current_match in pattern.findall(line):
                current_match = current_match.lower()
                if current_match not in matches:
                    matches[current_match] = [file_path]
                else:
                    matches[current_match].append(file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Search for UUID strings in specified file types within a directory.')
    parser.add_argument('directory', help='Directory to search in')
    parser.add_argument('--extensions', nargs='+', default=['.smali', '.json'], help='File extensions to search in (default: .smali .json)')
    parser.add_argument('--output', default='output.csv', help='CSV file to write the results (default: output.csv)')

    args = parser.parse_args()

    # Regex pattern to match UUIDs
    uuid_pattern = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')

    # Search for UUIDs in the specified directory
    search_in_directory(args.directory, uuid_pattern, args.extensions)

    # Write results to CSV
    with open(args.output, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['UUID', 'Filepath'])
        for uuid, filepaths in matches.items():
            files = ";".join(filepaths)
            csv_writer.writerow([uuid, files])

    print(f"Results written to {args.output}")

    # Write cleaned results to a new CSV
    cleaned_output = 'cleaned_' + args.output
    with open(cleaned_output, 'w', newline='') as cleaned_csvfile:
        cleaned_csv_writer = csv.writer(cleaned_csvfile)
        cleaned_csv_writer.writerow(['UUID', 'Filepath'])
        seen_uuids = set()
        for uuid, filepaths in matches.items():
            if uuid not in seen_uuids:
                cleaned_csv_writer.writerow([uuid, filepaths[0]])
                seen_uuids.add(uuid)

    print(f"Cleaned results written to {cleaned_output}")
