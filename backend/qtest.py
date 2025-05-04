import requests

response = requests.post(
    "http://localhost:8000/login",
    data={"username": "admin", "password": "admin123"},
    headers={"Content-Type": "application/x-www-form-urlencoded"}
)

print("Status Code:", response.status_code)
print("Response:", response.json())