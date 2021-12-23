# Overview:
LogSpotlight is a highly customizable log monitoring program. It is designed to be simple to use but very effective in monitoring log files. All configuration is set up through a simple to use YAML configuration file, and you can add as many logs as you would like to monitor. This program's key advantage is its message encryption option to protect any sensitive information from being read. A web GUI companion program is offered to allow the ability to decrypt the message. Because this option is not SSL, you should run this program on a VLAN that cannot be snooped with Wireshark. If you have ever wanted to perform another action once a log entry is discovered, this program offers post-processing per software log entry and offers to search the output.

If you use docker and would like to centralize your docker logs to be monitored, check out [DockerLogRedirect] (https://github.com/IncognitoCoding/dockerlogredirect)


## Program Highlights:
* Dynamically add as many log files as you would like to monitor.
* Search for multiple key search words or phrases.
* Email supports standard port 25 or TLS.
* Customizable subject line for each search.
* Customizable program log output and debug options.
* Log check cycle setting.
* Encrypt email messages.
* Message decryption web GUI companion.
* Post-processing option when a log entry gets discovered.
* Post-processing option to send matched info as an argument.
* Post-processing output is searchable.
* The YAML file allows updating on the fly, and each loop will use the updated YAML configuration.

## Setup Recommendations & Setup Hints:
Each log file is considered a separate software entry in the program. You may use the same log file in multiple software entries. A reason this would work is grouping error/warning into a group and info into another group. The email subject line will list the search words, so separating may help identify what alerts are being sent. Add more descriptive keyword entries above the less descriptive entries. The program works top-down, so less descriptive entries will skip if matched on a more descriptive entry.

Each software entry must contain the required YAML keys. Copy the previous sample section when adding a new software entry and change the last number.

The sample file is designed to show you two different software entry examples to show what options you can use. The main thing to take away from the sample_settings.yaml is that the "name, url_log_path, email_subject_line, post_processing_send_info, and post_processing_email_subject_line" are a single entry option, and "info_search, exclude_search, post_processing_args, and post_processing_info_search" can be single entry or multiple entries.

Post-processing offers the ability to add additional functionality when a log entry gets discovered. The matched log entry can be passed as the last argument if the post-processing program/script accepts raw arguments without an options flag. The matched log can be used as a string in the program/script to perform a task based on that entry. You may find this helpful if a specific entry requires a task to be performed, such as deleting a file once a log entry gets discovered.

# Program Prerequisites:
Use the requirements.txt file to make sure you have all the required prerequisites. This program will use an additional package called ictoolkit created by IncognitoCoding for most general function calls. Future programs will utilize the similar ictoolkit package. Feel free to use this package for your Python programming.

## How to Use:
The sample YAML configuration file has plenty of notes to help explain the setup process. The steps below will explain what needs to be done to get the program running.

    Step 1: For the program to recognize the YAML file, you must copy the sample_settings.yaml file and rename it to settings.yaml 
    Step 2: Update the YAML file with your configuration.
    Step 3: Run the program to make sure your settings are entered correctly. 
    Step 4: Depending on your operating system (Linux Ubuntu or Windows), you can set up the program to run automatically, which is recommended. Other Linux versions will work but are not explained below. 
       Step 4.1 (Optional - Windows): Setup a scheduled task to run the program on startup.
                Create a service account and a new scheduled task using these settings. A delayed start may be required.
                    - Run weather user is logged on or not
                    - Run with highest privileges
                    - Run hidden
                    - Set trigger time. Maybe daily around midnight
                    - Set action to start program
                    - Program/Script: "<python.exe path>"
                    - Arguments: "C:\<path to the program>\logspotlight\logspotlight\logspotlight.py"
                    - Uncheck "Stop the task if it runs longer than:"
       Step 4.2 (Optional - Linux Ubuntu): Set up a service to run the program.
            Step 4.2.1:  Create a new service file.
                Run: cd /lib/systemd/system
                Run: sudo nano logspotlight.service
                    Note1: The service account needs to have docker socket access. The root user is added below as an example.
                    Note2: A delayed start can help ensure all processes start before monitoring starts. Your "TimeoutStartSec" must be greater than the "ExecStartPre".
                    Paste:
                        Description=logspotlight
                        After=multi-user.target
                        After=network.target

                        [Service]
                        Type=simple
                        User=root
                        TimeoutStartSec=240
                        ExecStartPre=/bin/sleep 120
                        WorkingDirectory=/<path to program>/logspotlight/logspotlight
                        ExecStart=/usr/bin/python3  /<path to program>/logspotlight/logspotlight/logspotlight.py                                                         
                        Restart=no

                        [Install]
                        WantedBy=multi-user.target
            Step 4.2.2:  Create a new service file.
                Run: sudo systemctl daemon-reload
            Step 4.2.3: Enable the new service.
                sudo systemctl enable logspotlight.service
            Step 4.2.4: Start the new service.
                sudo systemctl start logspotlight.service
            Step 4.2.5: Check the status of the new service.
                sudo systemctl status logspotlight.service
    Step 5: Verify the program is running as a service or scheduled task. 
    Step 6: Once verified, you should set the logging handler to option 2 and the file's log level to INFO. This will cut down on disk space.
## Troubleshooting:
The YAML file offers DEBUG options to troubleshoot any issues you encounter. Please report any bugs.
#### Future Updates:
Offer the companion web GUI to use SSL certificates to protect when not using on a secure VLAN.
