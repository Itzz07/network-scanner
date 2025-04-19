import requests

def get_mac_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=3)
        return response.text
    except:
        return "Unknown"


# import requests

# def get_mac_vendor(mac):
#     try:
#         url = f"https://api.macvendors.com/{mac}"
#         response = requests.get(url, timeout=3)
#         return response.text
#     except:
#         return "Unknown"
