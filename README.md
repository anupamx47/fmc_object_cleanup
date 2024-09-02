# Cisco FMC Object Cleanup Script

## Overview

This script automates the process of managing unused objects in Cisco Firepower Management Center (FMC). It allows users to generate reports of unused objects and optionally delete those unused objects across various object types. The script is designed with error handling, including token expiration and undeletable (read-only) objects, and provides progress feedback during the deletion process.

## Features

- **User Input for FMC Credentials**: The script prompts for FMC IP address, username, and password.
- **Selectable Object Types**: Users can choose which object types they want to manage from a predefined list.
- **Two Actions**: 
  - Generate a report of unused objects.
  - Delete unused objects and generate a report.
- **Progress Indicator**: The script displays a progress bar during the deletion process, showing the percentage of completion.
- **Detailed Reporting**:
  - `unused_objects_report.txt`: Contains a list of unused objects.
  - `deleted_objects_report.txt`: Lists objects that were successfully deleted.
  - `undeletable_objects_report.txt`: Logs objects that could not be deleted, typically due to being read-only.

## Prerequisites

- Python 3.x
- `requests` library (`pip install requests`)

## How to Use

1. **Clone or Download the Script**:
   - Place the `object_cleanup.py` file in your working directory.

2. **Install Required Python Libraries**:
   - Ensure you have the `requests` library installed. You can install it using:
     ```bash
     pip install requests
     ```

3. **Run the Script**:
   - Execute the script using Python:
     ```bash
     python3 object_cleanup.py
     ```

4. **Provide FMC Credentials**:
   - The script will prompt you to enter the FMC IP address, username, and password.

5. **Select Object Types**:
   - Choose the object types you want to manage. Options include:
     ```
     1: networks
     2: protocolportobjects
     3: hosts
     4: networkgroups
     5: portgroups
     6: addressranges
     7: securityzones
     8: fqdn
     9: dnsservergroups
     ```

6. **Choose an Action**:
   - Option 1: Generate a report of unused objects.
   - Option 2: Delete unused objects and generate a report.

7. **Monitor Progress**:
   - If you choose to delete objects, the script will display a progress bar indicating the deletion status.

8. **Review Reports**:
   - Reports will be generated and saved in the following files:
     - `unused_objects_report.txt`: Report of all unused objects.
     - `deleted_objects_report.txt`: Report of objects that were successfully deleted.
     - `undeletable_objects_report.txt`: Report of objects that could not be deleted due to being read-only.

## Error Handling

- **Token Expiration**: The script automatically refreshes the authentication token if it expires during execution.
- **HTTP Errors**: The script provides detailed error messages in case of issues with API requests.
- **Read-Only Objects**: Objects that cannot be deleted (e.g., read-only objects) are logged in `undeletable_objects_report.txt`.

## Example Run

```bash
python3 object_cleanup.py
Enter FMC IP address: 10.127.212.234
Enter FMC Username: admin
Enter FMC Password: 
Select the object types you want to manage (comma-separated list):
1: networks
2: protocolportobjects
3: hosts
4: networkgroups
5: portgroups
6: addressranges
7: securityzones
8: fqdn
9: dnsservergroups
Enter your choice(s): 1,3

What would you like to do?
1: Generate a report of unused objects
2: Delete unused objects and generate a report
Enter your choice (1 or 2): 2
```

## Notes

- **Security Warning**: The script disables SSL verification (`verify=False`) for HTTPS requests. This is not recommended for production environments as it can expose you to security risks. If you are running this script in a production environment, ensure that SSL verification is enabled, or use a properly configured SSL certificate.

- **Disclaimer**: Use this script at your own risk. Ensure you have a backup of your FMC configuration before running any scripts that delete objects.

## License

This script is provided "as-is" without any warranties or guarantees. The author is not responsible for any damage or data loss resulting from the use of this script.
