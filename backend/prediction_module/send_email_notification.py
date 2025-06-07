# prediction_module/send_email_notification.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging
import pandas as pd
from dotenv import load_dotenv
from . import config # For accessing config.PREDICTIONS_OUTPUT_CSV_PATH etc.

load_dotenv()

logger = logging.getLogger(__name__)

EMAIL_SENDER_ADDRESS = os.getenv("EMAIL_SENDER_ADDRESS")
EMAIL_SENDER_PASSWORD = os.getenv("EMAIL_SENDER_PASSWORD")
EMAIL_RECEIVER_ADDRESS = os.getenv("EMAIL_RECEIVER_ADDRESS")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

def format_suspicious_flows_for_email_html(suspicious_df_sample):
    """Formats a sample of suspicious flows DataFrame into an HTML table for email."""
    if suspicious_df_sample.empty:
        return "<p>No specific suspicious flow examples to display.</p>"
    
    html_table = "<h3>Một số luồng nguy hiểm đã được phát hiện:</h3>"
    try:
        html_table += suspicious_df_sample.to_html(index=False, border=1, classes="dataframe", escape=True)
    except Exception as e:
        logger.error(f"Error converting DataFrame to HTML for email: {e}")
        return "<p>Error displaying suspicious flow examples. Please check logs and CSV files.</p>"
    html_table += "<p><em>Note: Only a sample of suspicious flows is shown. Check CSV output for full details.</em></p>"
    return html_table

def send_prediction_results_email(subject, body_html, suspicious_df_sample_for_email=None):
    """
    Sends an email with the prediction results.
    Args:
        subject (str): Email subject.
        body_html (str): Main HTML body content.
        suspicious_df_sample_for_email (pd.DataFrame, optional): A sample of suspicious flows to include.
    """
    if not all([EMAIL_SENDER_ADDRESS, EMAIL_SENDER_PASSWORD, EMAIL_RECEIVER_ADDRESS, SMTP_SERVER]):
        logger.error("Email configuration incomplete. Skipping email notification. Please check .env variables: EMAIL_SENDER_ADDRESS, EMAIL_SENDER_PASSWORD, EMAIL_RECEIVER_ADDRESS, SMTP_SERVER, SMTP_PORT.")
        return False

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER_ADDRESS
    msg['To'] = EMAIL_RECEIVER_ADDRESS

    # Base HTML structure
    full_html_content = f"""
    <html>
      <head>
        <style>
          body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
          .dataframe {{ border-collapse: collapse; width: auto; margin-bottom: 15px; font-size: 0.9em;}}
          .dataframe th, .dataframe td {{ text-align: left; padding: 8px; border: 1px solid #ddd; }}
          .dataframe th {{ background-color: #f2f2f2; color: #333; }}
          h3 {{ color: #555; }}
          ul {{ list-style-type: square; }}
          code {{ background-color: #f9f9f9; padding: 2px 4px; border-radius: 3px; font-family: monospace;}}
        </style>
      </head>
      <body>
        {body_html}
    """
    
    if suspicious_df_sample_for_email is not None and not suspicious_df_sample_for_email.empty:
        full_html_content += format_suspicious_flows_for_email_html(suspicious_df_sample_for_email)
    
    full_html_content += """
      </body>
    </html>
    """

    # Create a plain text version (basic)
    # For a more sophisticated plain text version, you might convert HTML to text
    text_part_content = "Prediction results are available. Please see system logs and output files for details."
    if suspicious_df_sample_for_email is not None and not suspicious_df_sample_for_email.empty:
        text_part_content += "\n\nSuspicious flows detected. Sample:\n"
        text_part_content += suspicious_df_sample_for_email.to_string(index=False)


    part1 = MIMEText(text_part_content, 'plain', 'utf-8')
    part2 = MIMEText(full_html_content, 'html', 'utf-8')

    msg.attach(part1)
    msg.attach(part2)

    try:
        logger.info(f"Attempting to send email via {SMTP_SERVER}:{SMTP_PORT} to {EMAIL_RECEIVER_ADDRESS}")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            if SMTP_PORT == 587: # Standard for TLS
                server.starttls()
                server.ehlo()
            
            if EMAIL_SENDER_PASSWORD: # Only login if password is provided
                 logger.info(f"Logging into SMTP server as {EMAIL_SENDER_ADDRESS}...")
                 server.login(EMAIL_SENDER_ADDRESS, EMAIL_SENDER_PASSWORD)
            
            logger.info(f"Sending email to {EMAIL_RECEIVER_ADDRESS}...")
            server.sendmail(EMAIL_SENDER_ADDRESS, EMAIL_RECEIVER_ADDRESS.split(','), msg.as_string()) # Allow multiple receivers
            logger.info("Email notification sent successfully.")
        return True
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication Error: {e}. Check sender email/password. If using Gmail with 2FA, an App Password is required.")
        return False
    except smtplib.SMTPConnectError as e:
        logger.error(f"SMTP Connect Error: {e}. Check SMTP server/port and network connectivity.")
        return False
    except smtplib.SMTPServerDisconnected as e:
        logger.error(f"SMTP Server Disconnected: {e}. Server might have timed out or closed the connection.")
        return False
    except Exception as e:
        logger.error(f"Failed to send email: {e}", exc_info=True)
        return False

def notify_by_email_on_prediction_completion(all_flows_df, suspicious_flows_df):
    """
    Prepares and sends an email notification based on prediction results.
    Args:
        all_flows_df (pd.DataFrame): DataFrame containing all flows with their predictions.
        suspicious_flows_df (pd.DataFrame): DataFrame containing only suspicious flows.
    """
    num_suspicious = len(suspicious_flows_df)
    num_total = len(all_flows_df)
    
    # Define paths to output files, ensuring they are accessible from config
    predictions_csv = config.PREDICTIONS_OUTPUT_CSV_PATH if hasattr(config, 'PREDICTIONS_OUTPUT_CSV_PATH') else "predictions.csv"
    suspicious_csv = config.SUSPICIOUS_OUTPUT_CSV_PATH if hasattr(config, 'SUSPICIOUS_OUTPUT_CSV_PATH') else "suspicious_flows.csv"


    if num_suspicious > 0:
        subject = f"🚨 Security Alert: {num_suspicious} Suspicious Network Flows Detected"
        body_html = f"""
        <p>Quét an ninh mạng đã xác định được <strong>{num_suspicious} luồng đáng ngờ</strong> trong tổng số {num_total} luồng được phân tích.</p>
        
        """
        # Take a small sample for the email body
        email_sample_size = getattr(config, 'EMAIL_ALERT_SAMPLE_SIZE', 5)
        suspicious_flows_sample_for_email = suspicious_flows_df.head(email_sample_size)
        send_prediction_results_email(subject, body_html, suspicious_flows_sample_for_email)
    else:
        subject = "✅ Security Scan Completed: No Suspicious Activity Detected"
        body_html = f"""
        <p>Network security scan has completed. <strong>No suspicious network flows</strong> were detected out of {num_total} total flows analyzed.</p>
        <p>The full prediction report has been saved to: <code>{predictions_csv}</code></p>
        """
        send_prediction_results_email(subject, body_html)