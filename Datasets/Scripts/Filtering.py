#Base features for both models
#remove 'label' for unsupervised
#consider dropping handshake_state, duration, active_mean, idle_mean
import sys
import pandas as pd

def label_extractor(input, num):
    columns = ['protocol', 
                'duration',
                'packets_count',
                'fwd_packets_count',
                'bwd_packets_count',
                'total_payload_bytes',
                'fwd_total_payload_bytes',
                'bwd_total_payload_bytes',
                'payload_bytes_max',
                'payload_bytes_min',
                'payload_bytes_mean',
                'payload_bytes_std',
                'total_header_bytes',
                'fwd_total_header_bytes',
                'bwd_total_header_bytes',
                'avg_segment_size',
                'fwd_init_win_bytes',
                'bwd_init_win_bytes',
                'active_mean',
                'active_std',
                'idle_mean',
                'idle_std',
                'bytes_rate',
                'packets_rate',
                'down_up_rate',
                'fin_flag_counts',
                'psh_flag_counts',
                'syn_flag_counts',
                'ack_flag_counts',
                'rst_flag_counts',
                'packets_IAT_mean',
                'subflow_fwd_packets',
                'subflow_bwd_packets',
                'subflow_fwd_bytes',
                'subflow_bwd_bytes',
                'handshake_state',
                'label'
                 ]
    if num == '1':
        for i in range(1, 31):
            path = './Datasets/Data/'
            file = f'friday_02_03_2018_benign.part{i}.csv'
            input_file = pd.read_csv(path+file, header=0, encoding="utf-8")
            file_name = f'./Datasets/Processed_Data/benign_processed.part{i}.csv'
            pd.DataFrame(input_file, columns=columns).to_csv(file_name, index=False)
    else:
        input_file = pd.read_csv(input, header=0, encoding="utf-8")
        file_name = './Datasets/Processed_Data/bot_processed1.csv'
        pd.DataFrame(input_file, columns=columns).to_csv(file_name, index=False)

def duplicate_removal(input, num):
    input_file = pd.read_csv(input, header=0, encoding="utf-8")
    dedup_file = input_file.drop_duplicates()
    if num > 0:
        filename = f'./Datasets/Filtered_Data/benign_filtered.part{num}.csv'
        dedup_file.to_csv(filename, index=False)
    else:
        filename = './Datasets/Filtered_Data/bot_filtered1.csv'
        dedup_file.to_csv(filename, index=False)

if __name__ == "__main__":
    label_extractor(sys.argv[1], sys.argv[2])
    if sys.argv[2] == '1':
        for i in range(1, 31):
            duplicate_removal(f'./Datasets/Processed_Data/benign_processed.part{i}.csv', i)
    else:
        duplicate_removal('./Datasets/Processed_Data/bot_processed1.csv', 0)