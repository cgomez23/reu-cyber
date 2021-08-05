# Part 1
# Convert pcaps to csvs with tshark

import os
import glob
import pandas as pd

files = glob.glob('../captures3/**/*.pcap')
target_folder = '../test_data/csv'
for filepath in files:
    csv_name = filepath.split("\\")[-1].replace('.pcap', '.csv')
    abs_path = target_folder + '\\' + csv_name
    os.system('tshark -r "%s" -T fields -t ud -e frame.number -e eth.src \
            -e eth.dst -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
            -e frame.protocols -e frame.len -e _ws.col.Time -e frame.time_delta \
            -E header=y -E separator=, > "%s"' % (filepath, abs_path))
    print('Finished with ', csv_name)

# Part 2
# Fix csvs, change column names and edit uneven rows

import pandas as pd
import glob
import csv

def correction(file, outfile):
    with open(file, 'r') as inFile, open(outfile, 'w', newline='') as outfile:
        r = csv.reader(inFile)
        w = csv.writer(outfile)

        next(r, None)  # skip the first row from the reader, the old header
        # write new header
        w.writerow(["No.","MAC Source","MAC Destination","Source","Destination","Source Port","Destination Port","Protocol","Length","Epoch Time","Delta Time"])

        # copy the rest
        for row in r:
            # tshark bug workaround
            if len(row) > 11:
                del row[5:7]
            w.writerow(row)
    # df = pd.read_csv(file)
    # df.columns = ["No.","MAC Source","MAC Destination","Source","Destination","Source Port","Destination Port","Protocol","Length","Epoch Time","Delta Time"]
    # df.to_csv(outfile, index=False)


threads = []
files = glob.glob('../test_data/csv/*.csv')
for file in files:
    correction(file, file[:56]+'2'+file[56:])
    print(file[:56]+'2'+file[56:])
print('done')