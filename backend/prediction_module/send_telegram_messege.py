from dotenv import load_dotenv
import os
import requests
load_dotenv()

bot_token = os.getenv("BOT_TOKEN")
chat_id = os.getenv("CHAT_ID")

def process_attack_detection(suspicious_df):
    for _, attack_data in suspicious_df.iterrows():
        message = "🚨 *Phát hiện dòng tấn công nghi ngờ!*\n\n"
        message += f"🕒 Thời gian: {attack_data['Timestamp']}\n"
        message += f"🔗 Flow ID: {attack_data['Flow ID']}\n"
        message += f"📡 Src: {attack_data['Src IP']}:{attack_data['Src Port']}\n"
        message += f"🎯 Dst: {attack_data['Dst IP']}:{attack_data['Dst Port']}\n"
        message += f"📶 Protocol: {attack_data['Protocol']}\n"
        message += f"🔍 Prediction: {attack_data['Prediction']}\n"

        send_telegram_message(bot_token, chat_id, message)

    
def send_telegram_message(bot_token, chat_id, message):
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    params = {
        'chat_id': chat_id,
        'text': message
    }
    try:
        response = requests.post(api_url, params=params)
        response.raise_for_status()  # Báo lỗi nếu request không thành công
        print("Tin nhắn Telegram đã được gửi thành công!")
    except requests.exceptions.RequestException as e:
        print(f"Lỗi khi gửi tin nhắn Telegram: {e}")