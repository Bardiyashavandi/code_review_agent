import os
import subprocess

# Intentional issues for the agent to find

SECRET_KEY = "hardcoded-secret-abc123"  # hardcoded credential

def run_command(user_input):
    # shell=True with user input — command injection risk
    subprocess.run(user_input, shell=True)

def get_user(user_id):
    # trusting client-supplied input directly
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

DEBUG = True  # debug flag left on
