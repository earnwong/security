import pandas as pd
import re
import numpy as np
import glob
import os
import sys


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

    def netbios(self):
        """
        - Extract hostnames through netbios search
        :return: dictionary key(hostname) : value(extracted name)
        """
        # sorts for netbios computer names
        netbios_df = self.df[(self.df['Name'].str.contains("netbios")) & (self.df['Plugin Output'].str.contains("computer name"))]

        # regex to find computer names
        regex = r"[A-Za-z0-9]+-[A-Za-z0-9]+=(computername)|[A-Za-z0-9]+=(computername)"

        # extract computer names using the regex
        computer_names = netbios_df['Plugin Output'].apply(lambda x: re.search(regex, x.replace(" ", "")).group().replace("=computername", ''))

        # create a list of tuples from the extracted computer names and the host names
        self.name_dict.update(dict(zip(netbios_df['Host'], computer_names)))

        return self.name_dict

    def dns(self):
        """
        - Extract hostnames through additional DNS hostname search
        :return: dictionary key(hostname) : value(extracted name)
        """
        # find dns hostname rows
        dns_df = self.df[self.df['Name'] == "additional dns hostnames"][['Host', 'Plugin Output']]

        # remove spaces from plugin output, remove first line, replace all the dashes (-)with spaces and split into list
        dns_df['Plugin Output'] = dns_df['Plugin Output'].str.replace(" ", "").str.replace(
            "thefollowinghostnamespointtotheremotehost:", "").str.replace("\n-", " ").str.split().apply(
            lambda x: x[0] if x else None)  # if hostname already exists then disregard, if doesn't, then add to dict
        self.name_dict.update(dns_df.set_index('Host').to_dict()['Plugin Output'])

        return self.name_dict

    def ssl(self):
        """
        - Extract hostnames through SSL self-signed certificate search
        :return: dictionary key(hostname) : value(extracted name)
        """
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
                        self.name_dict[row["Host"]] = name
            return

        ssl_df.apply(process_row, axis=1)

        return self.name_dict


def extract(filename):
    '''

    :param filename: name of the file
    :return: extracted dataframe
    '''

    data = pd.read_csv(filename)
    clean = Clean(data)
    cleaned_df = clean.get_df()  # desired dataframe to extract names from
    search_data = Search(cleaned_df)
    search_data.netbios()  # use netbios method
    search_data.dns()  # use dns method
    dict_list = search_data.ssl()  # use ssl method

    # make a new column and correlate the host name to the computer names
    cleaned_df['Extracted Hostname'] = ''
    for key in dict_list:
        cleaned_df.loc[cleaned_df.Host == key, 'Extracted Hostname'] = dict_list[key]

    return cleaned_df


def main():

    if len(sys.argv) == 1:  # if there is no input, then scan folder
        print("Scanning for CSV files")
        filenames = glob.glob('../parsefiles/*.csv', recursive=True)

        new_dataframes = {}  # new dictionary
        for filename in filenames:  # loop into list of filenames extracted from folder
            new_dataframes[filename] = extract(filename)

        for name, df in new_dataframes.items():
            new_filename = "[Extracted] " + os.path.basename(name)
            df.to_csv('../output/' + new_filename)

    else:

        new_dataframes = {}
        for filename in sys.argv[1::]:
            if os.path.exists(filename):
                new_dataframes[filename] = extract(filename)
            else:
                print("[ERROR] File not found: " + filename)

        os.makedirs('Parsed Files', exist_ok=True)
        for name, df in new_dataframes.items():
            new_filename = "[Extracted] " + os.path.basename(name)
            df.to_csv('./Parsed Files/' + new_filename)


    # cleaned_df.to_csv('/Users/earnsmacbookair/Desktop/tester/Data Output.csv')

    # code for when we only want to see how many names have been extracted
    # cleaned_df['Extracted Hostname'].replace('', np.nan, inplace=True)
    # df = cleaned_df[cleaned_df['Extracted Hostname'].notna()]
    # os.makedirs('/Users/earnsmacbookair/Desktop/tester', exist_ok=True)
    # df.to_csv('/Users/earnsmacbookair/Desktop/tester/Only Name.csv')
    # print(df)

if __name__ == "__main__":
    main()