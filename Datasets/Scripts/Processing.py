#Base features for both models
#remove 'label' for unsupervised
#consider dropping handshake_state, duration, active_mean, idle_mean
import sys
import pandas as pd

def label_extractor(input):
    input_file = pd.read_csv(input, header=0, encoding="utf-8")
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
                'packets_IAT_std',
                'packets_IAT_max',
                'packets_IAT_min',
                'subflow_fwd_packets',
                'subflow_bwd_packets',
                'subflow_fwd_bytes',
                'subflow_bwd_bytes',
                'handshake_duration',
                'handshake_state',
                'label'
                 ]
    file_name = './Datasets/processed_benign.csv'
    pd.DataFrame(input_file, columns=columns).to_csv(file_name, index=False)

if __name__ == "__main__":
    label_extractor(sys.argv[1])