import pandas as pd
import os
import re
import numpy as np


class ValidDomain:
    def __init__(self, domain):
        self.domain = domain
        self.valid = False

    def is_valid(self):
        pattern = r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)"
        match = re.match(pattern, self.domain)
        self.valid = match is not None
        if '.local' in self.domain:
            return False
        else:
            return self.valid


class Clean:
    def __init__(self, data):
        self.df = pd.DataFrame(data, columns=['Host', 'Name', 'Plugin Output'])
        self.df['Name'] = self.df['Name'].str.lower()
        self.df['Plugin Output'] = self.df['Plugin Output'].str.lower()

    def get_df(self):
        return self.df


class Search:
    def __init__(self, df):
        self.df = df
        self.dict_list = {}

    def netbios(self):
        """
        - search for computer names through netbios search
        """
        # sorts for netbios computer names
        netbios_df = self.df[(self.df['Name'].str.contains("netbios")) & (self.df['Plugin Output'].str.contains("computer name"))]

        # regex to find computer names
        regex = r"[A-Za-z0-9]+-[A-Za-z0-9]+=(computername)|[A-Za-z0-9]+=(computername)"

        # extract computer names using the regex
        computer_names = netbios_df['Plugin Output'].apply(lambda x: re.search(regex, x.replace(" ", "")).group().replace("=computername", ''))

        # create a list of tuples from the extracted computer names and the host names
        self.dict_list.update(dict(zip(netbios_df['Host'], computer_names)))

        return self.dict_list

    def dns(self):
        """
        - dns hostname search
        """
        # find dns hostname rows
        dns_df = self.df[self.df['Name'] == "additional dns hostnames"][['Host', 'Plugin Output']]

        # remove spaces from plugin output, remove first line, replace all the dashes (-)with spaces and split into list
        dns_df['Plugin Output'] = dns_df['Plugin Output'].str.replace(" ", "").str.replace(
            "thefollowinghostnamespointtotheremotehost:", "").str.replace("\n-", " ").str.split().apply(
            lambda x: x[0] if x else None)  # if hostname already exists then disregard, if doesn't, then add to dict
        self.dict_list.update(dns_df.set_index('Host').to_dict()['Plugin Output'])

        return self.dict_list

    def ssl(self):
        """

        :return: dictionary
        """
        df2 = self.df[(self.df['Name'].str.contains("ssl self-signed certificate"))].copy()

        # clean data for only necessary rows
        for key in self.dict_list:
            df2.loc[df2.Host == key, 'Plugin Output'] = np.nan

        ssl_df = df2[df2['Plugin Output'].notna()].copy()

        ssl_df['Plugin Output'] = ssl_df['Plugin Output'].str.replace(" ", "").str.split("[/:]")

        def process_row(row):
            """

            :param row:
            :return:
            """
            s = (row['Plugin Output'])[2::]
            for elem in s:
                if "cn=" in elem:
                    name = elem.replace("\n", "").replace("cn=", "")
                    valid_domain = ValidDomain(name)
                    if valid_domain.is_valid() and row["Host"] not in self.dict_list.keys():
                        self.dict_list[row["Host"]] = name
            return

        ssl_df.apply(process_row, axis=1)

        return self.dict_list


def main():
    # read data
    # data = pd.read_csv(r'/Users/earnsmacbookair/Desktop/General Workstations 20230207.csv')
    data = pd.read_csv(r'/Users/earnsmacbookair/Desktop/academicservers.csv')
    clean = Clean(data)
    cleaned_df = clean.get_df()

    search_data = Search(cleaned_df)
    dict_list = search_data.netbios()
    dict_list = search_data.dns()
    dict_list = search_data.ssl()

    # make a new column and correlate the host name to the computer names
    cleaned_df['Extracted Hostname'] = ''
    for key in dict_list:
        cleaned_df.loc[cleaned_df.Host == key, 'Extracted Hostname'] = dict_list[key]

    cleaned_df['Extracted Hostname'].replace('', np.nan, inplace=True)
    df = cleaned_df[cleaned_df['Extracted Hostname'].notna()]
    print(df)

    os.makedirs('/Users/earnsmacbookair/Desktop/tester', exist_ok=True)
    df.to_csv('/Users/earnsmacbookair/Desktop/tester/Output3.csv')


if __name__ == "__main__":
    main()