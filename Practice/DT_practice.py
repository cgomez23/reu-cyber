# practice in identifying MAC labels using various features

from sklearn import datasets
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn import metrics, preprocessing

dataset = pd.read_csv ('test1.csv')
df = dataset.drop(columns =['IP Source','Epoch Time', 'Time', 'Source', 'Destination'])
print('CSV Read')

le = preprocessing.LabelEncoder()
strings_only = df.select_dtypes(include=[object])
df_transformed = strings_only.apply(le.fit_transform)
enc = preprocessing.OneHotEncoder()
enc.fit(df_transformed)
print('Data Transformed')

df_2 = df.drop(columns =['MAC Destination', 'Protocol', 'Info'])
df_3 = df_transformed.iloc[: , 1:]

df = pd.merge(df_2, df_3, left_index=True, right_index=True)

df['Source Port'] = df['Source Port'].fillna(0)
df['Destination Port'] = df['Destination Port'].fillna(0)

print('Starting ML')
X = df[['Length', 'Delta Time', 'Source Port', 'Destination Port', 'Info', 'Protocol', 'MAC Destination']]
#dataset[['Source','MAC Destination','Destination','Length','Source Port','Destination Port','Protocol', 'Delta Time']]
y = dataset['MAC Source']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

#Create a Gaussian Classifier
clf=RandomForestClassifier(n_estimators=100)

#Train the model using the training sets y_pred=clf.predict(X_test)
clf.fit(X_train,y_train)

y_pred=clf.predict(X_test)
print("Accuracy:",metrics.accuracy_score(y_test, y_pred))