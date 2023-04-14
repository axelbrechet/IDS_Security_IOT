from keras.models import load_model
import numpy as np
from sniffer import Sniffer
from notify.notify import Notify 

# Initializations
sniffer = Sniffer('\\Device\\NPF_{718ADC81-1EAC-4ED0-835F-1E96B7DF7076}')
model = load_model('saved_model.h5')

def analyze(buffer):
    data = np.vstack([list(vars(pkt).values()) for pkt in buffer])
    data = data.reshape(1, data.shape[0], data.shape[1])

    yhat = model.predict(data, verbose=0)
    probability = yhat[0][0]    
    if probability > 0.6:
        print(f'Attack detected with probability {probability:.2f}')
        #Notify.send_alert("Unknown attack", probability)

sniffer.run(callback=analyze)