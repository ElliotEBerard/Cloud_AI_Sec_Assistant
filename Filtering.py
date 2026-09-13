import pandas as pd

def duplicate_removal():
    names = ['benign', 'BF_FTP', 'BF_SSH', 'BF_web', 'BF_XSS', 'bot' , 'DoS_Golden_Eye', 'dos_hulk', 'dos_slowhttp', 'DoS_Slowloris', 'hoic', 'infiltration', 'loic_http', 'SQL_Injection', 'SQL_Injection_1', 'BF_web_1', 'BF_XSS_1', 'benign_1', 'benign_2', 'benign_3', 'benign_4', 'benign_5', 'benign_6', 'benign_7', 'benign_8', 'benign_9', 'benign_10', 'benign_11', 'benign_12', 'benign_13', 'benign_14', 'dos_hulk_2', 'dos_slowhttp_2', 'hoic_2']
    path = './Datasets/Test_Data/'
    ext = '.csv'
    for name in names:
        # removing duplicate rows
        input_file = pd.read_csv(path+name+ext, header=0, encoding="utf-8")
        before = len(input_file)
        dedup_file = input_file.drop_duplicates()
        after = len(dedup_file)
        new_path = './Datasets/Filtered_Data/'
        dedup_file.to_csv(new_path+name+ext, index=False)
        print(f'{name} file completed, {before} -> {after} rows')

def combine_files():
    names = ['benign', 'BF_FTP', 'BF_SSH', 'BF_web', 'BF_XSS', 'bot' , 'DoS_Golden_Eye', 'dos_hulk', 'dos_slowhttp', 'DoS_Slowloris', 'hoic', 'infiltration', 'loic_http', 'SQL_Injection', 'SQL_Injection_1', 'BF_web_1', 'BF_XSS_1', 'benign_1', 'benign_2', 'benign_3', 'benign_4', 'benign_5', 'benign_6', 'benign_7', 'benign_8', 'benign_9', 'benign_10', 'benign_11', 'benign_12', 'benign_13', 'benign_14', 'dos_hulk_2', 'dos_slowhttp_2', 'hoic_2']
    path = './Datasets/Filtered_Data/'
    ext = '.csv'
    files = {}
    for name in names:
        files[name] = pd.read_csv(path+name+ext, header=0, encoding="utf-8")
    files_combined = pd.concat(files, ignore_index=True)
    mixed = files_combined.sample(frac=1, random_state=42).reset_index(drop=True) 
    mixed.to_csv('./Datasets/base_data.csv', index=False)

'''def label_extractor():
    path = './Datasets/Raw_Data/'
    ext = '.csv'
    # specifies what columns will be kept
    columns = []
    
    input_file = pd.read_csv(path+{name}+ext, header=0, encoding="utf-8")
    new_path = './Datasets/Processed_Data/'
    pd.DataFrame(input_file, columns=columns).to_csv(new_path+{name}+ext, index=False)'''


#duplicate_removal()
combine_files()
#label_extractor()