# taking random sample from files and combining benign/bot files into one
import pandas as pd

def combine_sample():
    bot_file = pd.read_csv('./Datasets/Filtered_Data/bot_filtered.csv', header=0, encoding="utf-8")
    benign_file = pd.read_csv('./Datasets/Filtered_Data/benign_filtered.csv', header=0, encoding="utf-8")
    #random sample target 5:1 ratio(benign/bot) = ~800000
    benign_sample = benign_file.sample(n=800000, random_state=50)
    files_combined = pd.concat([benign_sample, bot_file], ignore_index=True)
    mixed = files_combined.sample(frac=1, random_state=42).reset_index(drop=True) 
    mixed.to_parquet('./Datasets/base_data.parquet', index=False)

def combine_csv():
    for i in range(1, 31):
        path =  './Datasets/Filtered_Data/'
        file = f'benign_filtered.part{i}.csv'
        benign_files = pd.read_csv(path+file, header=0, encoding="utf-8")
        files_combined = pd.concat(benign_files, ignore_index=True)
        mixed = files_combined.sample(frac=1, random_state=42).reset_index(drop=True) 
        mixed.to_csv('./Datasets/Filtered_Data/benign_filtered.csv', index=False)

combine_csv()
