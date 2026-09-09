import sys
import pandas as pd

def sample_csv(input):
    file_data = []
    input_file = pd.read_csv(input, header=0, encoding="utf-8")
    columns = input_file.columns
    data = input_file.iloc[:, :].values
    for i in range(30):
        file_data.append(data[i])
    file_name = './Datasets/sample_data_bot.csv'
    pd.DataFrame(file_data, columns=columns).to_csv(file_name, index=False)

if __name__ == "__main__":
    sample_csv(sys.argv[1])