# Importation des bibliothèques nécessaires
import numpy as np
from keras.models import Sequential
from keras.layers import Dense, LSTM, Dropout
import pandas as pd
from sklearn.model_selection import train_test_split

# Charger le fichier csv dans un dataframe
df = pd.read_csv("C:/Users/axelb/Downloads/kddcup99_csv.csv/kddcup99_csv.csv")

# Diviser le dataframe en ensemble d'entraînement et ensemble de test
train_df, test_df = train_test_split(df, test_size=0.3, random_state=42)

# Sélectionner les colonnes d'entités et la colonne cible (label)
y_train = train_df['label']
X_train = train_df.iloc[:, :-1]
y_test = test_df['label']
X_test = test_df.iloc[:, :-1]
print(X_train.shape)

# Définition de l'architecture du modèle LSTM
model = Sequential()
model.add(LSTM(128, input_shape=(X_train.shape[1], X_train.shape[2]), return_sequences=True))
model.add(Dropout(0.2))
model.add(LSTM(64, return_sequences=True))
model.add(Dropout(0.2))
model.add(LSTM(32))
model.add(Dropout(0.2))
model.add(Dense(1, activation='sigmoid'))

# Compilation du modèle
model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

# Entraînement du modèle
model.fit(X_train, y_train, epochs=100, batch_size=128)

# Évaluation des performances du modèle
loss, accuracy = model.evaluate(X_test, y_test)

# Utilisation du modèle pour la détection d'intrusion en temps réel
'''
input_data = preprocess_input_data(raw_data)
prediction = model.predict(input_data)
if prediction > 0.5:
    print('Intrusion détectée!')
else:
    print('Pas d'intrusion détectée')
    '''
