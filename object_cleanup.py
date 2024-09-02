import requests
import json
import getpass

# Script Metadata
__author__ = "Anupam Pavithran (anpavith@cisco.com)"
__version__ = "1.0.0"

# Disable warnings for unverified HTTPS requests (not recommended for production)
requests.packages.urllib3.disable_warnings()

def get_fmc_credentials():
    fmc_ip = input("Enter FMC IP address: ")
    username = input("Enter FMC Username: ")
    password = getpass.getpass("Enter FMC Password: ")
    return fmc_ip, username, password

def get_auth_url(fmc_ip):
    return f"https://{fmc_ip}/api/fmc_platform/v1/auth/generatetoken"

def get_base_url(fmc_ip, domain_uuid):
    return f"https://{fmc_ip}/api/fmc_config/v1/domain/{domain_uuid}/"

# Object types to check and delete if unused
AVAILABLE_OBJECT_TYPES = {
    "1": "networks",
    "2": "protocolportobjects",
    "3": "hosts",
    "4": "networkgroups",
    "5": "portgroups",
    "6": "addressranges",
    "7": "securityzones",
    "8": "fqdn",
    "9": "dnsservergroups"
}

def select_object_types():
    print("Select the object types you want to manage (comma-separated list):")
    for key, value in AVAILABLE_OBJECT_TYPES.items():
        print(f"{key}: {value}")
    
    selected_keys = input("Enter your choice(s): ").split(",")
    selected_types = [AVAILABLE_OBJECT_TYPES[key.strip()] for key in selected_keys if key.strip() in AVAILABLE_OBJECT_TYPES]
    
    if not selected_types:
        print("No valid object types selected. Exiting...")
        exit()
    
    return selected_types

def get_auth_token(fmc_ip, username, password):
    auth_url = get_auth_url(fmc_ip)
    headers = {
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(auth_url, auth=(username, password), headers=headers, verify=False)
        response.raise_for_status()
        auth_token = response.headers.get('X-auth-access-token')
        refresh_token = response.headers.get('X-auth-refresh-token')
        domain_uuid = response.headers.get('DOMAIN_UUID')
        if auth_token is None or domain_uuid is None:
            raise Exception("Authentication token or Domain UUID not found. Exiting...")
        return auth_token, refresh_token, domain_uuid
    except Exception as e:
        print(f"Error obtaining auth token: {e}")
        exit()

def refresh_auth_token(fmc_ip, refresh_token):
    auth_url = get_auth_url(fmc_ip)
    headers = {
        'Content-Type': 'application/json',
        'X-auth-refresh-token': refresh_token
    }
    try:
        response = requests.post(auth_url, headers=headers, verify=False)
        response.raise_for_status()
        new_auth_token = response.headers.get('X-auth-access-token')
        new_refresh_token = response.headers.get('X-auth-refresh-token')
        if new_auth_token is None:
            raise Exception("New authentication token not found. Exiting...")
        return new_auth_token, new_refresh_token
    except Exception as e:
        print(f"Error refreshing auth token: {e}")
        exit()

def fetch_unused_objects(base_url, headers, object_type):
    try:
        # Corrected URL structure to match the provided format
        url = f"{base_url}object/{object_type}?filter=unusedOnly%3Atrue&expanded=true"
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        return response.json().get("items", [])
    except requests.exceptions.HTTPError as err:
        # Handle other errors gracefully
        raise

def generate_report(auth_token, refresh_token, fmc_ip, domain_uuid, selected_types):
    base_url = get_base_url(fmc_ip, domain_uuid)
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': auth_token
    }

    with open("unused_objects_report.txt", "w") as report_file:
        report_file.write("Unused Objects Report\n")
        report_file.write("=====================\n\n")

        for object_type in selected_types:
            try:
                objects = fetch_unused_objects(base_url, headers, object_type)

                if not objects:
                    print(f"No unused {object_type} objects found.")
                    report_file.write(f"No unused {object_type} objects found.\n")
                    continue

                report_file.write(f"Unused {object_type} objects:\n")
                for obj in objects:
                    name = obj.get('name', 'N/A')
                    value = obj.get('value', 'N/A')  # Adjust based on the object type
                    object_id = obj.get('id', 'N/A')
                    report_file.write(f"  - Name: {name}, Value: {value}, ID: {object_id}\n")
                report_file.write("\n")

            except requests.exceptions.HTTPError as err:
                print(f"HTTP error occurred: {err}")
                print(f"Response content: {err.response.content.decode('utf-8')}")
                report_file.write(f"Error processing {object_type}: {err}\n")

def delete_unused_objects(auth_token, refresh_token, fmc_ip, domain_uuid, selected_types):
    base_url = get_base_url(fmc_ip, domain_uuid)
    headers = {
        'Content-Type': 'application/json',
        'X-auth-access-token': auth_token
    }

    with open("deleted_objects_report.txt", "w") as report_file, open("undeletable_objects_report.txt", "w") as undeletable_file:
        report_file.write("Deleted Objects Report\n")
        report_file.write("======================\n\n")

        undeletable_file.write("Undeletable Objects Report\n")
        undeletable_file.write("==========================\n\n")

        for object_type in selected_types:
            try:
                objects = fetch_unused_objects(base_url, headers, object_type)

                if not objects:
                    print(f"No unused {object_type} objects found.")
                    report_file.write(f"No unused {object_type} objects found.\n")
                    continue

                for obj in objects:
                    delete_url = f"{base_url}object/{object_type}/{obj['id']}"
                    del_response = requests.delete(delete_url, headers=headers, verify=False)
                    
                    # Check if token is expired during delete operation
                    if del_response.status_code == 401:
                        print("Auth token expired. Refreshing token...")
                        auth_token, refresh_token = refresh_auth_token(fmc_ip, refresh_token)
                        headers['X-auth-access-token'] = auth_token
                        del_response = requests.delete(delete_url, headers=headers, verify=False)
                    
                    # Check for read-only or other deletion issues
                    if del_response.status_code == 403:  # Forbidden, likely read-only
                        name = obj.get('name', 'N/A')
                        value = obj.get('value', 'N/A')
                        object_id = obj.get('id', 'N/A')
                        print(f"Could not delete (read-only) {object_type} object: Name: {name}, Value: {value}, ID: {object_id}")
                        undeletable_file.write(f"Read-Only {object_type} object: Name: {name}, Value: {value}, ID: {object_id}\n")
                    else:
                        del_response.raise_for_status()
                        name = obj.get('name', 'N/A')
                        value = obj.get('value', 'N/A')
                        object_id = obj.get('id', 'N/A')
                        print(f"Deleted {object_type} object: Name: {name}, Value: {value}, ID: {object_id}")
                        report_file.write(f"Deleted {object_type} object: Name: {name}, Value: {value}, ID: {object_id}\n")

            except requests.exceptions.HTTPError as err:
                print(f"HTTP error occurred: {err}")
                print(f"Response content: {err.response.content.decode('utf-8')}")
                report_file.write(f"Error processing {object_type}: {err}\n")

def main():
    fmc_ip, username, password = get_fmc_credentials()
    auth_token, refresh_token, domain_uuid = get_auth_token(fmc_ip, username, password)
    selected_types = select_object_types()
    
    print("\nWhat would you like to do?")
    print("1: Generate a report of unused objects")
    print("2: Delete unused objects and generate a report")
    
    choice = input("Enter your choice (1 or 2): ").strip()
    
    if choice == "1":
        generate_report(auth_token, refresh_token, fmc_ip, domain_uuid, selected_types)
        print("Report generated and saved to 'unused_objects_report.txt'.")
    elif choice == "2":
        delete_unused_objects(auth_token, refresh_token, fmc_ip, domain_uuid, selected_types)
        print("Deletion process complete. Reports saved to 'deleted_objects_report.txt' and 'undeletable_objects_report.txt'.")
    else:
        print("Invalid choice. Exiting...")

if __name__ == "__main__":
    main()