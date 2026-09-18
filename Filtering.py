import pandas as pd

def clean_data():
    names = ['benign', 'BF_FTP', 'BF_SSH', 'BF_web', 'BF_XSS', 'bot' , 'DoS_Golden_Eye', 'dos_hulk', 'dos_slowhttp', 'DoS_Slowloris', 'hoic', 'infiltration', 'loic_http', 'SQL_Injection', 'SQL_Injection_1', 'BF_web_1', 'BF_XSS_1', 'benign_1', 'benign_2', 'benign_3', 'benign_4', 'benign_5', 'benign_6', 'benign_7', 'benign_8', 'benign_9', 'benign_10', 'benign_11', 'benign_12', 'benign_13', 'benign_14', 'dos_hulk_2', 'dos_slowhttp_2', 'hoic_2']
    path = './Datasets/Raw_Data/'
    ext = '.csv'
    new_path = './Datasets/Clean_Data/'
    bad_cols = ['delta_start', 'handshake_duration']
    for name in names:
        input_file = pd.read_csv(path+name+ext, header=0, encoding="utf-8", low_memory=False, chunksize=50000)
        first_chunk = True
        for chunk in input_file:
            for col in bad_cols:
                if col in chunk.columns:
                    chunk[col] = pd.to_numeric(chunk[col], errors='coerce')
            mode = 'w' if first_chunk else 'a'
            header = first_chunk
            chunk.to_csv(new_path+name+ext, mode=mode, header=header, index=False)
            first_chunk = False
        print(f'{name} file completed')


def combine_files():
    names = ['BF_FTP', 'BF_SSH', 'BF_web', 'BF_XSS', 'bot' , 'DoS_Golden_Eye', 'dos_hulk', 'dos_slowhttp', 'DoS_Slowloris', 'hoic', 'infiltration', 'loic_http', 'SQL_Injection', 'SQL_Injection_1', 'BF_web_1', 'BF_XSS_1', 'benign_1', 'benign_2', 'benign_3', 'benign_4', 'benign_5', 'benign_6', 'benign_7', 'benign_8', 'benign_9', 'benign_10', 'benign_11', 'benign_12', 'benign_13', 'benign_14', 'dos_hulk_2', 'dos_slowhttp_2', 'benign', 'hoic_2']
    path = './Datasets/Clean_Data/'
    ext = '.csv'
    files = {}
    for name in names:
        df = pd.read_csv(path+name+ext, header=0, encoding="utf-8")
        df = df.drop_duplicates()
        if len(df) > 25000:
            df = df.sample(n=25000, random_state=42)
        files[name] = df
        print(f'{name} file processed')
    files_combined = pd.concat(files, ignore_index=True)
    mixed = files_combined.sample(frac=1, random_state=42).reset_index(drop=True) 
    mixed.to_parquet('./Datasets/base_data.parquet', index=False)

#def column_filter():

#clean_data()
#combine_files()
