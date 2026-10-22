# Cloud_AI_Sec_Assistant

An ML-powered threat hunting assistant that helps a security analyst understand a week of network traffic: what happened, which hosts and users were involved, and why each alert was raised. Built on a low-cost serverless AWS stack.

**The problem**

Small security teams get far more alerts than they can investigate, and most detection tools don't explain why something was flagged. This project gives an analyst ranked, explained findings and the relationships between them, so they can work through a week of activity quickly.

**What it does**
- Classifies traffic as benign or malicious with a supervised model (XGBoost / Random Forest)
- Explains every prediction with SHAP, showing which features drove the alert
- Finds the unknown with Isolation Forest anomaly detection for activity that matches no known attack
- Connects the dots for threat hunting by correlating alerts across hosts, users, ports and time
- Runs serverless on AWS Lambda, DynamoDB and S3 to keep costs near zero

**Architecture**
- Raw traffic data lands in S3
- A Lambda function cleans the data, engineers time, port and handshake features, and runs the models
- Findings, scores and SHAP explanations are stored in DynamoDB
