import requests
 
def metodo():
    risposta =requests.get(http://api.open-notify.org/astros.json)
    dati= risposta.json()
    return dati 

