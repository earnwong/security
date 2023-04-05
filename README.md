# Hostname Extraction
- The Hostname Extraction tool is a data transformation and filtering tool that uses Pandas to extract and filter raw data into a usable and readable format.
- Its main purpose is to extract alternative and valid hostnames through filtering the output of plugins.
- It can handle large datasets, having been tested on datasets with over 50,000 rows.
- The extracted and filtered data is loaded into a MySQL database.
- The tool includes built-in data validation and error checking to ensure the accuracy and reliability of the extracted data.

How to use: 
This command will automatically scan for CSV files in the parsefile folder. 
python3 cleandata.py

This command will scan for specific CSV files in the current directory.
python3 cleandata.py "example_dataset.csv" 



