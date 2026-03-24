# BLP Visualizer: Initialize environment and run all 18 test cases

from blp import BLPSystem

def make_system():
    blp = BLPSystem()
    print("[System] Initializing Default State ...")
    blp.add_subject("Alice", start="U", max_level="S")
    blp.add_subject("Bob",   start="C", max_level="C")
    blp.add_subject("Eve",   start="U", max_level="U")

    blp.add_object("pub.txt",      "U")
    blp.add_object("emails.txt",   "C")
    blp.add_object("username.txt", "S")
    blp.add_object("password.txt", "TS")
    return blp

# ── 18 Test Cases ──

CASES = { 
    1:  ("Alice reads emails.txt", lambda b: b.read("Alice", "emails.txt")),
    2:  ("Alice reads password.txt", lambda b: b.read("Alice", "password.txt")),
    3:  ("Eve reads pub.txt", lambda b: b.read("Eve", "pub.txt")),
    4:  ("Eve reads emails.txt", lambda b: b.read("Eve", "emails.txt")),
    5:  ("Bob reads password.txt", lambda b: b.read("Bob", "password.txt")),
    6:  ("Alice reads emails.txt then writes to pub.txt",
         lambda b: [b.read("Alice", "emails.txt"), b.write("Alice", "pub.txt")]),
    7:  ("Alice reads emails.txt then writes to password.txt",
         lambda b: [b.read("Alice", "emails.txt"), b.write("Alice", "password.txt")]),
    8:  ("Alice: read emails → write emails → read username → write emails",
         lambda b: [b.read("Alice","emails.txt"), b.write("Alice","emails.txt"),
                    b.read("Alice","username.txt"), b.write("Alice","emails.txt")]),
    9:  ("Alice: read username → write emails → read password → write password",
         lambda b: [b.read("Alice","username.txt"), b.write("Alice","emails.txt"),
                    b.read("Alice","password.txt"), b.write("Alice","password.txt")]),
    10: ("Alice: read pub → write emails; Bob reads emails",
         lambda b: [b.read("Alice","pub.txt"), b.write("Alice","emails.txt"), b.read("Bob","emails.txt")]),
    11: ("Alice: read pub → write username; Bob reads username",
         lambda b: [b.read("Alice","pub.txt"), b.write("Alice","username.txt"), b.read("Bob","username.txt")]),
    12: ("Alice: read pub → write password; Bob reads password",
         lambda b: [b.read("Alice","pub.txt"), b.write("Alice","password.txt"), b.read("Bob","password.txt")]),
    13: ("Alice: read pub → write emails; Eve reads emails",
         lambda b: [b.read("Alice","pub.txt"), b.write("Alice","emails.txt"), b.read("Eve","emails.txt")]),
    14: ("Alice: read emails → write pub; Eve reads pub",
         lambda b: [b.read("Alice","emails.txt"), b.write("Alice","pub.txt"), b.read("Eve","pub.txt")]),
    15: ("Alice sets level to S then reads username.txt",
         lambda b: [b.set_level("Alice","S"), b.read("Alice","username.txt")]),
    16: ("Alice: read emails → set U → write pub; Eve reads pub",
         lambda b: [b.read("Alice","emails.txt"), b.set_level("Alice","U"),
                    b.write("Alice","pub.txt"), b.read("Eve","pub.txt")]),
    17: ("Alice: read username → set C → write emails; Eve reads emails",
         lambda b: [b.read("Alice","username.txt"), b.set_level("Alice","C"),
                    b.write("Alice","emails.txt"), b.read("Eve","emails.txt")]),
    18: ("Eve reads pub.txt then reads emails.txt",
         lambda b: [b.read("Eve","pub.txt"), b.read("Eve","emails.txt")]),
}

def run_case(num): 
    desc, actions = CASES[num]
    print(f"\n{'=' * 16} CASE #{num} {'=' * 16}")
    blp = make_system()
    actions(blp)
    print() 
    blp.print_state() 

def print_menu():
    print("\nOptions:")
    print("  [1-18] Run a specific test case (1 to 18)")
    print("  [A]    Run all test cases sequentially")
    print("  [Q]    Quit")

def main():
    print("\nBell-LaPadula (BLP) Simulator CLI - Test Cases 1 to 18")
    print("=" * 36) 

    while True:
        print_menu()
        choice = input("\nEnter choice: ").strip().upper()

        if choice == 'Q':
            print("Exiting. Goodbye!")
            break

        elif choice == 'A':
           for i in range(1, 19):
               run_case(i)

        elif choice.isdigit() and 1 <= int(choice) <= 18:
           run_case(int(choice))
        else:
            print("[ERROR] Invalid choice. Enter 1-18, A, or Q.")

if __name__ == "__main__":
    main()

