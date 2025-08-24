# Import required libraries
import time  # To add delays between operations, if necessary
from QRCodeScanner import QRScanner  # Import the QRScanner class from QRCodeScanner.py to scan QR codes
from QRCodeGenerator import QRCodeGenerator  # Import the QRCodeGenerator class from QRCodeGenerator.py to generate QR codes
from QRCodeEncrypt import SecureQRCodeGenerator #Import the QRCodeEncrypt class from QRCodeEncrypt.py
from colorama import Fore, Style  # For adding colors to the console output (used for text styling)

# Function to display a banner when the script starts
def print_banner():
    """
    Displays an ASCII art banner for beQRful.
    """
    # Define the banner with color styling using colorama
    banner = f"""
{Fore.MAGENTA}
    ______      _______________________      ______
    ___  /________  __ \__  __ \__  __/___  ____  /
    __  __ \  _ \  / / /_  /_/ /_  /_ _  / / /_  / 
    _  /_/ /  __/ /_/ /_  _, _/_  __/ / /_/ /_  /  
    /_.___/\___/\___\_\/_/ |_| /_/    \__,_/ /_/                                   
                                            {Style.RESET_ALL}
    """
    print(banner)  # Print the banner to the console

# Function to display the header for QR code scanning results
def print_header():
    """
    Prints a header for the QR code scanning result table.
    """
    # Prints a header for the QR code scanning results
    print("+-----------------------------QR CODE SCANNER------------------------------+")
    print("|    Scanning for QR codes ... Press Ctrl+C to Stop                        |")
    print("+--------------------------------------------------------------------------+")
    print("| Timestamp             | Decoded QR Code               | Response         |")  # Column headers
    print("+--------------------------------------------------------------------------+")

# Function to display the footer when the scanning ends
def print_footer():
    """
    Prints the footer after QR code scanning is stopped.
    """
    # Prints a footer after QR code scanning is complete
    print("+---------------------------------------------------------------------------+")
    print("|                Saved data to QR_info.csv                                  |")  # Displays message about saving data
    print("+---------------------------------------------------------------------------+")

# Main function to handle user input and control the program flow
def main():
    """
    Main function for running the QR code scanner or generator based on user choice.
    """
    print_banner()  # Display the ASCII art banner when the script starts
    
    while True:  # Loop to allow the user to re-enter choices
        # Prompt the user for input to either scan, generate QR codes, or quit
        choice = input("Choose an option:\n1. Scan QR codes\n2. Generate QR code\n3. Encrypt QR code\n(q to quit)\nEnter choice: ").strip().lower()

        # If the user chooses to scan QR codes
        if choice == "1":
            qr_scanner = QRScanner()  # Initialize the QRScanner class to scan QR codes
            print_header()  # Print the header for the QR code scanning results table

            try:
                while True:
                    user_input = input("\nPress Enter to scan a QR code or type 'q' to quit: ").strip().lower()
                    if user_input == 'q':
                        print_footer()
                        break  # Exit scanning loop
                    qr_scanner.capture_and_save()  # Scan once on each Enter press
            except Exception as e:
                print(f"An error occurred: {e}")
                print_footer()

        # If the user chooses to generate a QR code
        elif choice == "2":
            user_input = input("\nEnter the text or URL for the QR code: ")  # Ask the user for the text or URL to encode in the QR code
            file_name = input("Enter the filename to save the QR code (with .png extension): ").strip()  # Ask the user for the file name

            # If the user doesn't provide a filename, set a default value
            if not file_name:
                file_name = "qrcode.png"
            elif not file_name.endswith(".png"):  # Ensure the filename ends with '.png'
                file_name += ".png"  # Add the '.png' extension if not already present

            qr_generator = QRCodeGenerator(user_input, file_name)  # Initialize the QRCodeGenerator class with user input and filename
            qr_generator.generate_qr_code()  # Call the method to generate the QR code

        # If the user chooses the third option (to encrypt QR code)
        elif choice == "3":
            qr_generator = SecureQRCodeGenerator()  # Initialize the SecureQRCodeGenerator class to generate and encrypt QR code
            user_data = input("\nEnter the data to encode in the QR code (URL, text, or file path): ")  # Ask for user input
            qr_generator.create_secure_qr(user_data)  # Generate the secure QR code with encryption

        # If the user chooses to quit
        elif choice == "q":
            print("Exiting program. Goodbye!")  # Exit message
            break  # Exit the loop

        else:
            print("Invalid choice. Please select 1, 2, 3, or q to quit.")  # If the user enters an invalid option, show an error message

# This block ensures that the main function runs only when this script is executed directly
if __name__ == "__main__":
    main()  # Start the main function when the script is executed