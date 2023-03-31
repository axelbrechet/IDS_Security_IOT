import pandas as pd
from keras.models import Sequential
from keras.layers import Dense, LSTM, Dropout
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, LabelEncoder, MinMaxScaler

# Load dataset
df = pd.read_csv('kddcup99_csv.csv')

## Label encoding target column
label_enc = LabelEncoder()
df.label = label_enc.fit_transform(df.label)

## Transforming categorical features into binary features
# Note: In the newer version of sklearn, you don’t need to convert the string to int, as OneHotEncoder does this automatically.
categorical_cols = ['protocol_type', 'service', 'flag']

oh_enc = OneHotEncoder(sparse_output=False).set_output(transform="pandas")
encoded_df = oh_enc.fit_transform(df[categorical_cols])
encoded_df.columns = oh_enc.get_feature_names_out(categorical_cols)
data = df.join(encoded_df)
data.drop(categorical_cols, axis=1, inplace=True)

# Scaling features to a range
scaler = MinMaxScaler(feature_range=(0,1))
data[data.columns] = scaler.fit_transform(data[data.columns])

X = data.iloc[:,:-1]
Y = data.label

samples = X.shape[0]
features = X.shape[1]

# Reshaping
X = X.values.reshape((samples, 1, features))
Y = Y.values.reshape(-1,1)

X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.3, random_state=42)

samples = X_train.shape[0]
time_steps = X_train.shape[1]
features = X_train.shape[2]

model = Sequential()
model.add(LSTM(128, input_shape=(time_steps, features), return_sequences=True))
model.add(Dropout(0.2))
model.add(LSTM(64, return_sequences=True))
model.add(Dropout(0.2))
model.add(LSTM(32))
model.add(Dropout(0.2))
model.add(Dense(1, activation='sigmoid'))

# Compiling an LSTM model with a SGD optimization algorithm
model.compile(optimizer='adam', loss='binary_crossentropy', metrics='accuracy')

model.fit(X_train, Y_train, epochs=5, batch_size=32)

loss, accuracy = model.evaluate(X_test, Y_test)

print(f'Loss     : {loss}')
print(f'Accuracy : {accuracy*100}')

# https://www.mdpi.com/2078-2489/11/5/243
# https://machinelearningmastery.com/evaluate-performance-deep-learning-models-keras/