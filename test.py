import pandas as pd

def sample_csv():
    names = ['benign', 'BF_FTP', 'BF_SSH', 'BF_web', 'BF_XSS', 'bot' , 'DoS_Golden_Eye', 'dos_hulk', 'dos_slowhttp', 'DoS_Slowloris', 'hoic', 'infiltration', 'loic_http', 'SQL_Injection', 'SQL_Injection_1', 'BF_web_1', 'BF_XSS_1', 'benign_1', 'benign_2', 'benign_3', 'benign_4', 'benign_5', 'benign_6', 'benign_7', 'benign_8', 'benign_9', 'benign_10', 'benign_11', 'benign_12', 'benign_13', 'benign_14', 'dos_hulk_2', 'dos_slowhttp_2', 'hoic_2']
    path = './Datasets/Raw_Data/'
    ext = '.csv'
    for name in names:
        file_data = []
        input_file = pd.read_csv(path+name+ext, header=0, encoding="utf-8", chunksize=5000)
        first_chunk = next(input_file)
        columns = first_chunk.columns
        data = first_chunk.iloc[:, :].values
        for i in range(3):
            file_data.append(data[i])
        new_path = './Datasets/Test_Data/'
        pd.DataFrame(file_data, columns=columns).to_csv(new_path+name+ext, index=False)

sample_csv()

'''def sample_csv(input):
    file_data = []
    input_file = pd.read_csv(input, header=0, encoding="utf-8")
    columns = input_file.columns
    data = input_file.iloc[:, :].values
    for i in range(30):
        file_data.append(data[i])
    file_name = './Datasets/sample_data_bot.csv'
    pd.DataFrame(file_data, columns=columns).to_csv(file_name, index=False)

if __name__ == "__main__":
    sample_csv(sys.argv[1]) No newline at end of file'''