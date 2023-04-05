import errno
from datetime import date
import pandas as pd
import re
import numpy as np
import glob
import os
import sys
import pymysql
from sqlalchemy import create_engine


class ValidDomain:
    def __init__(self, domain):
        self.domain = domain
        self.valid = False

    def is_valid(self):
        """
        - checks for valid domain name using regex
        :return: boolean
        """
        pattern = r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)"
        match = re.match(pattern, self.domain)
        self.valid = match is not None
        if '.local' in self.domain:
            return False
        else:
            return self.valid


class Clean:
    def __init__(self, data):
        """
        - takes pandas dataframe and changes it to the desired format, ready for extracting information
        :param data: pandas dataframe
        """
        self.df = pd.DataFrame(data, columns=['Host', 'Name', 'Plugin Output'])
        self.df['Name'] = self.df['Name'].str.lower()
        self.df['Plugin Output'] = self.df['Plugin Output'].str.lower()

    def get_df(self):
        """
        :return: cleaned dataframe
        """
        return self.df


class Search:
    def __init__(self, df):
        self.df = df
        self.name_dict = {}
        self.aggregated_df = pd.DataFrame()

    def netbios(self):
        """
        - Extract hostnames through netbios search
        :return: dictionary key(hostname) : value(extracted name)
        """
        # sorts for netbios computer names
        netbios_df = self.df[(self.df['Name'].str.contains("netbios")) & (self.df['Plugin Output'].str.contains("computer name"))].copy()

        # regex to find computer names
        regex = r"[A-Za-z0-9]+-[A-Za-z0-9]+=(computername)|[A-Za-z0-9]+=(computername)|[A-Za-z0-9]+-=(computername)"

        # extract computer names using the regex
        def extract_computer_name(x):
            no_space_x = x.replace(" ", "")
            match = re.search(regex, no_space_x)
            if match:
                return match.group().replace("=computername", '')
            else:
                return f"No match found in: {x}"  # return the problematic string

        computer_names = netbios_df['Plugin Output'].apply(extract_computer_name)

        # create a list of tuples from the extracted computer names and the host names
        self.name_dict.update(dict(zip(netbios_df['Host'], computer_names)))

        # add a new column called "Extracted Hostnames" and add all of the computer names into the correct row
        self.aggregated_df = netbios_df[['Host', 'Name']]  # only need host and name column
        self.aggregated_df['Extracted Hostname'] = ''
        for key in self.name_dict:
            self.aggregated_df.loc[self.aggregated_df.Host == key, 'Extracted Hostname'] = self.name_dict[key]

        return self.name_dict

    def dns(self):
        """
        - Extract hostnames through additional DNS hostname search
        :return: dictionary key(hostname) : value(extracted name)
        """
        temporary_dict = {}  # make new dictionary for dns

        # find dns hostname rows
        dns_df = self.df[self.df['Name'] == "additional dns hostnames"][['Host', 'Name', 'Plugin Output']]

        # remove spaces from plugin output, remove first line, replace all the dashes (-)with spaces and split into list
        dns_df['Plugin Output'] = dns_df['Plugin Output'].str.replace(" ", "").str.replace(
            "thefollowinghostnamespointtotheremotehost:", "").str.replace("\n-", " ").str.split().apply(
            lambda x: x[0] if x else None)  # if hostname already exists then disregard, if doesn't, then add to dict

        temporary_dict.update(dns_df.set_index('Host').to_dict()['Plugin Output'])  # update the temp dict
        self.name_dict.update(dns_df.set_index('Host').to_dict()['Plugin Output'])  # update the name dict

        dns_df = dns_df[['Host', 'Name']]
        for key in temporary_dict:
            dns_df.loc[dns_df.Host == key, 'Extracted Hostname'] = temporary_dict[key]

        self.aggregated_df = pd.concat([self.aggregated_df, dns_df])

        return self.name_dict

    def ssl(self):
        """
        - Extract hostnames through SSL self-signed certificate search
        :return: dictionary key(hostname) : value(extracted name)
        """
        temporary_dict = {}  # make a new dictionary only for ssl

        df2 = self.df[(self.df['Name'].str.contains("ssl self-signed certificate"))].copy()

        # clean data for only necessary rows, if we have already extracted a name from the original IP address then
        # disregard the data
        for key in self.name_dict:
            df2.loc[df2.Host == key, 'Plugin Output'] = np.nan
        ssl_df = df2[df2['Plugin Output'].notna()].copy()

        # remove spaces from plugin output data and split data into list
        ssl_df['Plugin Output'] = ssl_df['Plugin Output'].str.replace(" ", "").str.split("[/:]")

        def process_row(row):
            """
            - Extracts the hostname then checks if it is a valid domain name by using ValidDomain class
            :param row: list - plugin output data
            :return: the processed row
            """
            s = (row['Plugin Output'])[2::]
            for elem in s:
                if "cn=" in elem:
                    name = elem.replace("\n", "").replace("cn=", "")
                    valid_domain = ValidDomain(name)
                    if valid_domain.is_valid() and row["Host"] not in self.name_dict.keys():
                        temporary_dict[row["Host"]] = name
                        self.name_dict[row["Host"]] = name
            return

        ssl_df.apply(process_row, axis=1)

        ssl_df = ssl_df[['Host', 'Name']]
        for key in temporary_dict:
            ssl_df.loc[ssl_df.Host == key, 'Extracted Hostname'] = temporary_dict[key]

        self.aggregated_df = pd.concat([self.aggregated_df, ssl_df])

        return self.name_dict

    def aggregate_results(self):
        self.netbios()
        self.dns()
        self.ssl()

        self.aggregated_df = self.aggregated_df[self.aggregated_df['Extracted Hostname'].notna()]

        return self.aggregated_df


def extract(filename):
    """
    Reads a filename into a pandas dataframe and extracts the hostname

    :param filename: name of the file
    :return: extracted dataframe
    """

    data = pd.read_csv(filename)
    clean = Clean(data)
    cleaned_df = clean.get_df()  # desired dataframe to extract names from
    search_data = Search(cleaned_df)
    result_df = search_data.aggregate_results()

    return result_df


# def isreadable(filename):
#     try:
#         with open(filename) as f:
#             s = f.read()
#             print('read', filename)
#     except IOError as x:
#         if x.errno == errno.ENOENT:
#             print(filename, '- does not exist')
#         elif x.errno == errno.EACCES:
#             print(filename, '- cannot be read')
#         else:
#             print(filename, '- some other error')

def main():
    engine = create_engine('mysql+pymysql://username:password@localhost/extractedcomputernames')

    if len(sys.argv) == 1:  # if there is no input, then scan folder
        print("Scanning for CSV files")
        filenames = glob.glob('../parsefiles/*.csv', recursive=True)

        new_dataframes = {}  # new dictionary
        for filename in filenames:  # loop into list of filenames extracted from folder
            new_dataframes[filename] = extract(filename)

        for name, df in new_dataframes.items():
            new_filename = "[Extracted] " + os.path.basename(name)
            # add two new columns here, current date and another column for with the path basename
            df['Date of Extraction'] = date.today()
            df['Filename'] = os.path.basename(name)
            df.to_csv('../output/' + new_filename)
            df.to_sql(name='All Extracted Names', con=engine, if_exists='append', index=False)
            os.remove(name)

    else:

        new_dataframes = {}
        for filename in sys.argv[1::]:
            print(sys.argv[1::])
            if os.path.exists(filename):
                new_dataframes[filename] = extract(filename)
            else:
                print("[ERROR] File not found: " + filename)

        os.makedirs('Output', exist_ok=True)
        for name, df in new_dataframes.items():
            new_filename = "[Extracted] " + os.path.basename(name)
            df['Date of Extraction'] = date.today()
            df['Filename'] = os.path.basename(name)
            df.to_csv('./Output/' + new_filename)
            df.to_sql(name='All Extracted Names', con=engine, if_exists='append', index=False)


if __name__ == "__main__":
    main()

