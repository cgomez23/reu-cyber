# REU Cybersecurity Project: Rogue Behavior Detection in Idnustrial Control Systems.
- The goal of this project was to develope an algorithm to identify rogue behavior for each device in the ISC
- We use digital fingerprinting to store the know signatures of authorized devices on the network. Then, to detect rogue behavior, we use a threshold learning model for each device to learn the differences between all other devices. Finally, we use this one-shot like learning model to determine if each test behavior matches any of the behaviors in the signatures captured in training.

Dataset Used: https://github.com/tjcruz-dei/ICS_PCAPS/releases

Summery of the file system
- The IDS (Intrusion Detection System) folder contains the files for training and testing our dataset. We use an Isolation Forest to learn normal outlier behavior, then a Decision Tree model to distinquish between normal and rogue outlier behavior.
    - The results are in a results folder and in the results.csv. 
        - results.csv gives an overall summery of each file testes (flagging any devices that experience any rogue behavior in the dataset).
        - The results folder gives a more detailed analysis of each file scanned for rogue behavior. It flags specific time frames for rogue behavior.
- The IDS_copy folder contains mostly the same files, but using a DT for both the normalizing and threshold models. The results were worse in this experiment.
- The Practice folder contains all files that were are redundant to the training and testing process. These files were used specifically for learning purposes in maching learning and digital fingerprinting.
- The models2 and models3 folders contain all the models for the IDS and the IDS_copy training process.
- The best_features file displays which features from the PCAP files are the most important for machine learning techniques.
- The format and format2 files are for data visualizations.
- The convert file is for converting the PCAP data to CSVs.