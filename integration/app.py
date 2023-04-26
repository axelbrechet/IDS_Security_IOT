import numpy as np
import joblib
from keras.models import load_model
from sniffer import Sniffer
from notify.notify import Notify 

# Constants
iface = 'wlan0'
model_path = 'model/lstm.h5'
scaler_path = 'model/scaler.pkl'

# Initializations
sniffer = Sniffer(iface)
model = load_model(model_path)
scaler = joblib.load(scaler_path)

def analyze(pkt):
    # Extract packet information (features)
    values = list(vars(pkt).values())
    
    # Reshape in order to apply the scaler
    data = np.array(values).reshape(1,-1)
    data_scaled = scaler.transform(data)

    # Reshape to fit the model (samples, timesteps, features)
    data_reshaped = data_scaled.reshape(1,1,len(values))

    yhat = model.predict(data_reshaped, verbose=0)
    probability = yhat[0][0]

    if probability > 0.9:
        print(f'Attack detected with probability {probability:.2f}')
        Notify.send_alert("Dos", probability)

sniffer.run(callback=analyze)



