# Same as the test.py file, but gets results for many test datasets

import pandas as pd
import numpy as np
import joblib
import random
import warnings
warnings.filterwarnings('ignore')

time_group = '15s'
image_length = 40

def transform(df):
    df['Epoch Time'] = pd.to_datetime(df['Epoch Time'], errors='coerce')
    packets_per_min = df.set_index('Epoch Time').groupby(pd.Grouper(freq=time_group))['Length'].mean()
    packets_per_min = packets_per_min.fillna(0)

    time_deltas = df.set_index('Epoch Time').groupby(pd.Grouper(freq=time_group))['Delta Time'].mean()
    time_deltas = time_deltas.fillna(time_deltas.mean())
    df = pd.merge(packets_per_min, time_deltas, left_index=True, right_index=True)

    return df

def detect_outliers(df, comparison_model):
    X = df[['Length', 'Delta Time']]
    #print(X)
    X['scores']=comparison_model.decision_function(X[X.columns[0:2]].values)
    X['anomaly']=comparison_model.predict(X[X.columns[0:2]].values)
    anomaly=df.loc[X['anomaly']==-1]

    return len(anomaly) # percentage of outliers

def compare_models(df_1, df_2, comparison_model, label):

    percent_of_outliers_anchor = detect_outliers(df_1, comparison_model)
    percent_of_outliers_2 = detect_outliers(df_2, comparison_model)
    # print(percent_of_outliers_2, percent_of_outliers_anchor, '=', percent_of_outliers_2 - percent_of_outliers_anchor, label)

    return percent_of_outliers_anchor - percent_of_outliers_2 #((abs(percent_of_outliers_2 - percent_of_outliers_anchor))/percent_of_outliers_anchor)*100


def extract_images_and_labes(df, name_of_mac):

    df = df[:-1] # removing odd row at end of dataframe
    df['Time'] = df.index
    df.index = pd.RangeIndex(len(df.index))
    groups = df.groupby([df.index // image_length])
    
    times = []
    mac_images = []
    mac_labels = []
    for _, g in groups:
        #print(np.array(g[['Length', 'Delta Time']]).shape)
        image = g[['Length', 'Delta Time']]
        times_in_image = g['Time']
        mac_images.append(image)
        mac_labels.append(name_of_mac)
        times.append(times_in_image)
    return mac_images, mac_labels, times

def random_anc_image(images, image_idx_dict, name):
    newDict = dict(filter(lambda elem: elem[1] == name, image_idx_dict.items()))
    keys = list(newDict.keys())
    random.shuffle(list(keys))
    idx = keys[0]
    random_image = images[idx]
    return random_image

# anchor image creation
df_anc = pd.read_csv(r'../test_data/csv2/eth2dump-clean-1h_1.csv')
macs = ['00:0c:29:9d:9e:9e','00:80:f4:09:51:3b','48:5b:39:64:40:79','00:0c:29:e6:14:0d']

df_anc = df_anc.loc[df_anc['MAC Source'].isin(macs)]
grouped_ip_anc = df_anc.groupby(df_anc['MAC Source'])
macs_arr_anc = [grouped_ip_anc.get_group(d) for d in df_anc['MAC Source'].unique()]

anc_image_dict = {}
anc_images = []
names = []
for mac in macs_arr_anc:
    name = mac['MAC Source'].unique()[0]
    mac = transform(mac)
    imgs, device_mac_addresses, _ = extract_images_and_labes(mac, name)
    anc_images += imgs
    names += device_mac_addresses

idxs_of_imgs = [i for i in range(len(anc_images))]
for idx, name in zip(idxs_of_imgs, names):
    anc_image_dict[idx] = name

# test image creation and test

# df = pd.read_csv(r'C:\Users\carlo\Documents\College\reu_cyber\test_data\csv2\eth2dump-mitm-change-30m-6h_1.csv')
import glob
import sys

final_results = []

files = glob.glob('../test_data/csv2/*.csv')
num_of_files = len(files)

sys.stdout.write("[%s]" % ("." * num_of_files))
sys.stdout.flush()
sys.stdout.write("\b" * (num_of_files+1)) # return to start of line, after '['

# iterate through all test files
for file in files:
    rogue_flags = {}
    for mac_name in macs:
        rogue_flags[mac_name] = 0
    # read file
    df = pd.read_csv(file)
    f = file.split('\\')[-1]
    
    # filtering out noise from dataset
    df = df[(df['MAC Source']=='00:0c:29:e6:14:0d') | (df['MAC Source']=='00:0c:29:9d:9e:9e') | (df['MAC Source']=='48:5b:39:64:40:79') | (df['MAC Source']=='00:80:f4:09:51:3b')]

    # print(df[(df['MAC Source']=='00:0c:29:e6:14:0d')])
    # df = df.loc[df['MAC Source'].isin(macs)]
    grouped_ip = df.groupby(df['MAC Source'])
    macs_arr = [grouped_ip.get_group(d) for d in df['MAC Source'].unique()]

    file_results = []
    # iterate through each mac in test data
    for mac in macs_arr:
        name = mac['MAC Source'].unique()[0]
        mac = transform(mac)
        images, device_mac_addresses, times_in_images = extract_images_and_labes(mac, name)
        i = 1
        # iterate through all test images in test data
        for img, times_in_image in zip(images, times_in_images):
            device_flags = {}
            auth_macs = ['00:0c:29:9d:9e:9e','00:80:f4:09:51:3b','48:5b:39:64:40:79'] # authorized macs on the network
            for mac_name in auth_macs:
                device_flags[mac_name] = 0
        
            # iterate through all legit devices to test for authenticity
            for a_mac in auth_macs:
                filename = '../models2'
                S_model = joblib.load(filename + '\\' + a_mac.replace(':','') + '.sav')
                test_image = img
                anchor_image = random_anc_image(anc_images, anc_image_dict, a_mac)
                d = compare_models(test_image, anchor_image, S_model, device_mac_addresses[0])

                filename = '../models2'
                compare_model = joblib.load(filename + '\\' + a_mac.replace(':','') + '_compare.sav')

                result = compare_model.predict([[d]])
                # print(device_mac_addresses[0], '->', a_mac, ':', r2, r1, '!', result)
                if result[0] == 'Normal':
                    device_flags[a_mac] = 1
            
            # final step
            one_many_or_none_rouge_flag = dict(filter(lambda elem: elem[1] == 1, device_flags.items()))
            # get start and end time for image
            time_start, time_end = times_in_image.iloc[0], times_in_image.iloc[-1]

            if len(one_many_or_none_rouge_flag) == 0 or len(one_many_or_none_rouge_flag) > 1:

                file_results.append([time_start, time_end, name, i, 1])
                rogue_flags[name] = 1
                i+=1
            else:
                # print(name+' image '+str(i)+' matches '+ list(one_many_or_none_rouge_flag.keys())[0])
                file_results.append([time_start, time_end, name, i, 0])
                i+=1

    # create results csv for each file
    file_results_df = pd.DataFrame(file_results, columns=['Image Time Start', 'Image Time End', 'MAC', 'Image', 'Status'])
    filepath = '../results/' + f 
    file_results_df.to_csv(filepath)

    # percentage of images coming from rouge devices
    percent = (len(file_results_df[file_results_df['Status']==1])/len(file_results_df))*100

    final_results_row = [f, percent]+list(rogue_flags.values())
    final_results.append(final_results_row)

    sys.stdout.write("#")
    sys.stdout.flush()

# create final results csv file containing stats on all files (datasets) 
final_results_df = pd.DataFrame(final_results, columns=['Filename', 'Rouge Device Percentage']+list(rogue_flags.keys()))
final_results_df.to_csv('results2.csv')
sys.stdout.write("]\n") # this ends the progress bar
