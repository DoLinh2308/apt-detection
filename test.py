import requests

TOKEN = '7645973969:AAFHTo3C-95Ghs5MOQVSGwfEDcTkXn_2iZQ'
url = f"https://api.telegram.org/bot{TOKEN}/getUpdates"

response = requests.get(url)
data = response.json()
print(data)
