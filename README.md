# -AI-Based-Cybersecurity-Threat-Detection-and-Monitoring-System-
This Model is used to suspect Spam &amp; Safe URL , IP address and Messages
CyberShield – AI Cybersecurity Threat Detector

CyberShield is a beginner-friendly cybersecurity project that uses AI/ML-based detection to identify potentially suspicious or malicious inputs. It provides a simple web interface where users can submit input and check whether it appears safe or potentially dangerous.

🚀 Features

🔍 Detects potentially suspicious inputs
🛡️ Identifies different types of security-related input
🤖 Uses machine learning for threat prediction
🌐 Simple Flask-based web interface
📊 Displays prediction results
💻 Runs locally on your computer

🛠️ Technologies Used
Python
Flask
HTML
CSS
JavaScript
Machine Learning
Pandas
NumPy
Scikit-learn

📁 Project Structure

cyber_shield/
│
├── app.py
├── __init__.py
│
├── core/
│   └── detector.py
│
├── models/
│
├── static/
│   ├── css/
│   └── js/
│
└── templates/
    └── index.html

⚙️ Installation

Clone the repository:

git clone YOUR_GITHUB_REPOSITORY_URL

Go to the project folder:

cd cyber_shield

Install the required libraries:

pip install -r requirements.txt

▶️ Run the Project

Go to the parent folder of cyber_shield:

cd ..

Run the Flask application:

python -m cyber_shield.app

Then open your browser and visit:

http://127.0.0.1:5000
🧪 Example Testing

You can test the application with:

Safe input:

Hello, this is a normal website request.

Suspicious input:

<script>alert('test')</script>

The system will analyze the input and display the prediction.

⚠️ This project is designed for educational purposes. It should not be considered a complete enterprise-level cybersecurity system.

🎯 Purpose

The main purpose of CyberShield is to learn how Python, machine learning, Flask, and cybersecurity concepts can be combined to create a simple threat-detection application.

🔮 Future Improvements
Add more cybersecurity attack categories
Improve the machine learning model
Add a threat history/dashboard
Add database support
Improve prediction accuracy
Add real-time monitoring
Deploy the application online
👨‍💻 Author

Harnoor Singh Walia

BCA Student | Cybersecurity & Technology Enthusiast

