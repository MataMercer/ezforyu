# Vons Just 4 U Coupon Clipper
## Overview
This script logs into your Vons account via email and password and clips every Just 4 U coupon. It is 
intended to run as a Cron job that runs every Wednesday morning when there is a new sale, but it can be run as is.

## Usage

1. Once you clone the repo to your computer or server of your choice, navigate to the same directory
as main.py. 

2. Create a file named config.json and copy the following Json code into it. Fill in the < >'s with your information. 
Fields marked with a * symbol are required! 
```
{
  "loginData": {
    "username": "<Your Vons Sign-in Email*>",
    "password": "<Your Vons password*>"
  },
  "emailLoginData": {
    "email": "<Notification Email Sender>",
    "password": "<Notification Email Sender Password>"
  },
  "emailRecipient": "<Email Notification Recipient>"
}
```
Email notifications are for sending whether the script ran successfully to your personal email. 

Note for Notifications: Most email providers, such as Gmail, do not support email and password login due to security. 
One method I've found is using a Yahoo email account with a generated password found in settings.  

3. Run `` python main.py``

## Requirements
- Python 3.9
- pip
- virtualenv
