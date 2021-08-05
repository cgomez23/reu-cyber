import pandas as pd
import numpy as np
import joblib
import random
import warnings
warnings.filterwarnings('ignore')

# should match the training ipynb file variables
time_group = '15s'
image_length = 60

# all functions explained in the training file

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

    return percent_of_outliers_2, percent_of_outliers_anchor, abs(percent_of_outliers_anchor - percent_of_outliers_2) #((abs(percent_of_outliers_2 - percent_of_outliers_anchor))/percent_of_outliers_anchor)*100


def extract_images_and_labes(df, name_of_mac):
    df = df[:-1] # removing odd row at end of dataframe
    df['Time'] = df.index
    df.index = pd.RangeIndex(len(df.index))
    groups = df.groupby([df.index // image_length]) # group by image length
    
    mac_images = []
    mac_labels = []
    for _, g in groups:
        image = g[['Length', 'Delta Time']]
        mac_images.append(image)
        mac_labels.append(name_of_mac)
    return mac_images, mac_labels

def random_anc_image(images, image_idx_dict, name):
    newDict = dict(filter(lambda elem: elem[1] == name, image_idx_dict.items()))
    keys = list(newDict.keys())
    random.shuffle(list(keys))
    idx = keys[0]
    random_image = images[idx]
    return random_image

# anchor image creation
df_anc = pd.read_csv(r'C:\Users\carlo\Documents\College\reu_cyber\test_data\csv2\eth2dump-clean-1h_1.csv')
macs = ['00:0c:29:9d:9e:9e','00:80:f4:09:51:3b','48:5b:39:64:40:79','00:00:29:e6:14:0d']

df_anc = df_anc.loc[df_anc['MAC Source'].isin(macs)]
grouped_ip_anc = df_anc.groupby(df_anc['MAC Source'])
macs_arr_anc = [grouped_ip_anc.get_group(d) for d in df_anc['MAC Source'].unique()]

anc_image_dict = {}
anc_images = []
names = []
for mac in macs_arr_anc:
    name = mac['MAC Source'].unique()[0]
    mac = transform(mac)
    imgs, device_mac_addresses = extract_images_and_labes(mac, name)
    anc_images += imgs
    names += device_mac_addresses

idxs_of_imgs = [i for i in range(len(anc_images))]
for idx, name in zip(idxs_of_imgs, names):
    anc_image_dict[idx] = name

# test image creation and test

df = pd.read_csv(r'C:\Users\carlo\Documents\College\reu_cyber\test_data\csv2\eth2dump-mitm-change-30m-6h_1.csv')
# Filtering out noise from VMs
df = df[(df['MAC Source']=='00:0c:29:e6:14:0d') | (df['MAC Source']=='00:0c:29:9d:9e:9e') | (df['MAC Source']=='48:5b:39:64:40:79') | (df['MAC Source']=='00:80:f4:09:51:3b')]

grouped_ip = df.groupby(df['MAC Source'])
macs_arr = [grouped_ip.get_group(d) for d in df['MAC Source'].unique()]

# iterate through each mac in test data
for mac in macs_arr:
    name = mac['MAC Source'].unique()[0]
    mac = transform(mac)
    images, device_mac_addresses = extract_images_and_labes(mac, name)
    # image number
    i = 1
    
    # iterate through all test images in test data
    for img in images:
        # iterate through all legit devices to test for authenticity
        device_flags = {}
        auth_macs = ['00:0c:29:9d:9e:9e','00:80:f4:09:51:3b','48:5b:39:64:40:79'] # authorized macs on the network
        for mac_name in auth_macs:
            device_flags[mac_name] = 0
        for a_mac in auth_macs:
            filename = r'C:\Users\carlo\Documents\College\reu_cyber\models2'
            S_model = joblib.load(filename + '\\' + a_mac.replace(':','') + '.sav')
            test_image = img
            anchor_image = random_anc_image(anc_images, anc_image_dict, a_mac)
            r1, r2, d = compare_models(test_image, anchor_image, S_model, device_mac_addresses[0])

            filename = r'C:\Users\carlo\Documents\College\reu_cyber\models2'
            compare_model = joblib.load(filename + '\\' + a_mac.replace(':','') + '_compare.sav')

            result = compare_model.predict([[d]])
            print(device_mac_addresses[0], '->', a_mac, ':', r1, r2, '=', d, '!', result)
            if result[0] == 'Normal':
                device_flags[a_mac] = 1
        
        # final step: check if the image matches uniquely to any of the auth devices
        one_many_or_none = dict(filter(lambda elem: elem[1] == 1, device_flags.items()))

        # if 0 or more than one flag on a device, mark as image from rogue device
        # else mark as normal
        if len(one_many_or_none) == 0 or len(one_many_or_none) > 1:
            print(name +' image '+str(i)+' is from a rouge deivce, or matches too many other devices.')
            # next image number
            i+=1
        else:
            print(name+' image '+str(i)+' matches '+ list(one_many_or_none.keys())[0])
            i+=1
    print('Testing next device')

