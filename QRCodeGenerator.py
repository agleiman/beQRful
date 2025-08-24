import qrcode  # Imports the qrcode module for generating QR codes
from PIL import Image  # Imports the Image class from Pillow for handling images

class QRCodeGenerator:  # Defines a class for generating QR codes
    def __init__(self, data, filename="qrcode.png"):  # Constructor to initialize with data and optional filename
        self.data = data  # Stores the data to encode in the QR code
        self.filename = filename  # Sets the filename to save the QR code image

    def generate_qr_code(self):  # Method to generate and display the QR code
        # Create QR code instance
        qr = qrcode.QRCode(  # Initializes a new QRCode object with specific configuration
            version=1,  # Sets the version of the QR code (controls size, 1 is smallest)
            error_correction=qrcode.constants.ERROR_CORRECT_L,  # Sets error correction level (L = 7% correction)
            box_size=10,  # Sets the number of pixels for each box of the QR code
            border=4,  # Sets the width of the border (minimum is 4)
        )
        
        qr.add_data(self.data)  # Adds the data to be encoded in the QR code
        qr.make(fit=True)  # Generates the QR code matrix, fitting size automatically

        # Create and save the QR code image
        img = qr.make_image(fill="black", back_color="white")  # Creates a PIL image from the QR matrix with color settings
        img.save(self.filename)  # Saves the QR code image to the specified file
        
        # Print a success message
        print(f"QR code saved as {self.filename}")  # Notifies the user that the QR code was saved

        # Attempt to display the saved QR code image
        try:
            img = Image.open(self.filename)  # Opens the saved image using Pillow
            img.show()  # This will open the image using the default image viewer
        except Exception as e:  # Catch and display any exceptions that occur during opening
            print(f"Error opening image: {e}")  # Print the error if the image can't be opened
