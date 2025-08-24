import csv  # Importing the csv module to handle CSV file operations
from datetime import datetime  # Importing datetime to generate timestamps

class CSVWriter:
    """
    Class to write extracted data into a CSV file.
    """
    def __init__(self, csv_filename: str):
        """
        Initialize the CSVWriter with a CSV file name. 
        :param csv_filename: The name of the CSV file where data will be stored.
        """
        self.csv_filename: str = csv_filename  # Storing the filename
        self._initialize_csv()  # Ensuring the CSV file is properly initialized

    def _initialize_csv(self):
        """
        Creates a new CSV file with headers if it doesn't already exist.
        """
        try:
            # Open the file in 'x' mode, which creates a new file but raises an error if it already exists
            with open(self.csv_filename, mode='x', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)  # Creating a CSV writer object
                writer.writerow(["Timestamp", "Extracted Data"])  # Writing the header row
            print(f"Created new file: {self.csv_filename}")  # Logging file creation
        except FileExistsError:
            # If the file already exists, we do nothing and continue execution
            pass

    def write_to_csv(self, data: str):
        """
        Writes data to the CSV file with a timestamp.
        :param data: The extracted data to be written into the CSV file.
        """
        timestamp: str = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))  # Getting the current timestamp

        # Open the file in append mode to add data without overwriting previous entries
        with open(self.csv_filename, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)  # Creating a CSV writer object
            writer.writerow([timestamp, data])  # Writing the timestamp and data into the CSV file

        # Uncomment the below line if you want a log message every time data is saved
        # print(f"Saved to {self.csv_filename}: {data}")  
