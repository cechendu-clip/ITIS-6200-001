import hashlib      #library for hashing functions
import os           #library for interacting with the operating system
import json         #library for working with JSON data

# ---- Constants ---- 
TABLE_FILE = "hash_table.json"

# ---- Hashing Function ----
def hash_file(file_path):
    """ Compute SHA-256 hash of a file"""
    hasher = hashlib.sha256() 
    try:  
        with open(file_path, 'rb') as f:  
            while True:
                chunk = f.read(4096)  
                if not chunk:  
                    break
                hasher.update(chunk)
        return hasher.hexdigest() 
    except (IOError, OSError, PermissionError) as e:
        print(f"Warning: Could not read file {file_path}: {e}")
        return None
    
# ---- Directory Traversal ---- 
def traverse_directory(dir_path):
    """ Repeatedly collect all file path in a directory """
    file_paths = [] 

    for root, _, files in os.walk(dir_path):  
        for name in files:
            full_path = os.path.abspath(os.path.join(root, name))  
            file_paths.append(full_path) 
    return file_paths 

# ---- Hash Table Operations ---- 
def build_hash_table(file_paths):
    """ Map each file path to its SHA-256 hash table """
    table = {}
    for path in file_paths:
        file_hash = hash_file(path)
        if file_hash is not None:
            table[path] = file_hash
    return table

def save_hash_table(table, output_file):
    """ Save the hash table to a json file """
    try:
       with open(output_file, 'w') as f:
            json.dump(table, f, indent=2)
    except (IOError, OSError) as e:
        print(f"Error: Could not save hash table: {e}")

def load_hash_table(input_file):
    """ Load the hash table from a json file """
    try:
        with open(input_file, 'r') as f:
            return json.load(f)
    except (IOError, OSError) as e:
        print(f"Error: Could not load hash table: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Hash table file is corrupted {e}")
        return None

def filter_table_file(file_paths, table_file):
    """ Filter a hash table file """
    table_file_abs = os.path.abspath(table_file)
    return [p for p in file_paths if p != table_file_abs]

# ---- Verification Logic ---- 
def verify_hashes(dir_path, table_file):
    """ Verify the hash table files """
    old_table = load_hash_table(table_file)
    if old_table is None:
        return

    current_files = traverse_directory(dir_path)
    current_files = filter_table_file(current_files, table_file)

    # Build current hash table
    current_table = build_hash_table(current_files)

    # Compare 
    old_paths = set(old_table.keys())
    current_paths = set(current_table.keys())

    # Set operations to classify files 
    deleted_files = old_paths - current_paths   # files that were removed 
    new_files = current_paths - old_paths       # files that were added 
    common_files = old_paths & current_paths    # files that exist in both tables

    valid_count = 0
    invalid_count = 0

    # Print results 
    for path in sorted(common_files):
        if old_table[path] == current_table[path]:
            valid_count += 1
            print("VALID:", path)
        else:
            invalid_count += 1
            print("INVALID:", path)
            print(" saved:", old_table[path])
            print(" current:", current_table[path])

    for path in sorted(new_files):
        print("NEW:", path)

    for path in sorted(deleted_files):
        print("DELETED:", path)   

    print(f"\nSummary: {valid_count} valid, {invalid_count} invalid, "
          f"{len(new_files)} new, {len(deleted_files)} deleted")

# ---- Main Program Loop ----
def main():
    """ Main entry point """
    while True: 
        print("\nHashing Program")
        print("1) Generate Hash table")
        print("2) Verify Hashes")
        print ("q) Quit the program")
        choice = input("Choose an option: ").strip().lower()

        if choice == "q":
            print("Goodbye.")
            break 

        if choice not in ("1", "2"):
            print("Invalid choice. Please choose 1, 2, or q.")
            continue 

        dir_path = input("Enter directory path: ").strip()
        if not dir_path:
            dir_path = "."

        files = traverse_directory(dir_path)
        files = filter_table_file(files, TABLE_FILE)

        if choice == "1":
            if not files: 
                print("No files found in the directory.") 
                continue 
            table = build_hash_table(files)
            save_hash_table(table, TABLE_FILE)
            print("Hash table generated and saved to", TABLE_FILE)

        elif choice == "2":
            if not os.path.exists(TABLE_FILE):
               print("No hash table found. Run option 1 first.")
               continue
            verify_hashes(dir_path, TABLE_FILE)
        
if __name__ == "__main__":
    main() 
