# ZeroTrustX

# OopsHooked Phishing Email Detector tool

import re  # For detecting links and patterns in the email
import nltk  # For working with text and stop words
import matplotlib.pyplot as plt  # For creating visualisations

# Download NLTK stopwords (only needs to be done once)
nltk.download('stopwords')

# Define a list of suspicious keywords commonly found in phishing emails
suspicious_keywords = [
    "urgent", "verify your account", "click here", "free", "login",
    "congratulations", "action required", "security alert", "update now"
]

# Function to analyse an email for phishing characteristics
def analyse_email(email_text):
    """
    Analyses an email to identify phishing characteristics.

    Args:
    email_text (str): The full text of the email to analyse.

    Returns:
    tuple: Suspicious keyword count, number of links, phishing confidence score, and formatting flag.
    """
    # Convert email text to lowercase for consistent keyword matching
    words = email_text.lower().split()

    # Count suspicious keywords in the email text
    suspicious_count = sum(1 for word in words if word in suspicious_keywords)

    # Use regex to detect links in the email text
    links = re.findall(r'http[s]?://\S+', email_text)

    # Check for unusual formatting (e.g., too many links)
    unusual_format = len(links) > 3  # Flag if there are more than 3 links

    # Calculate the phishing confidence score
    total_words = len(words)
    confidence_score = (suspicious_count + len(links) * 2) / total_words * 100 if total_words > 0 else 0

    # Print analysis results
    print("---- Analysis Results ----")
    print(f"Suspicious Keywords Found: {suspicious_count}")
    print(f"Links Found: {len(links)}")
    print(f"Unusual Formatting Detected: {'Yes' if unusual_format else 'No'}")
    print(f"Confidence Score: {confidence_score:.2f}%")

    # Return analysis summary
    return suspicious_count, len(links), confidence_score, unusual_format


# ((Where to input your phishing email))
# Replace the `email` variable with the full text of the email you want to analyse.
email = """
Dear User,
Your account has been compromised. Please verify your account immediately by clicking here:
http://phishing-link.com.
Congratulations, you have won a free gift! Visit http://free-prizes.com to claim.
Security alert: Update your account details at http://secure-site.org.
"""

# Run the analysis on the sample email
suspicious_count, link_count, score, unusual_format = analyse_email(email)

# Visualise the results using a bar chart
categories = ["Suspicious Keywords", "Links", "Confidence Score"]
values = [suspicious_count, link_count, score]

# Save the chart for visualisation
plt.bar(categories, values, color=["blue", "green", "red"])
plt.title("Phishing Email Analysis")
plt.ylabel("Count/Score")
plt.savefig("sample_graph.png")  # Saves the chart as an image file named "sample_graph.png"
plt.show()  # Displays the chart in the output
