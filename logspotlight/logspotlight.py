"""
This program is designed to search through software logs to determine if an issue is present. The issue is logged into a tracker file, and an email is sent.
The tracker file is used, so previously discovered issues are skipped because they were sent in a previous notification email. Eventually, software like Sonarr, Radarr, etc.
will clear log files because the size and previously discovered issues will be gone.

Each discovered issue will be logged and emailed separately. This is by design to make sure each issue gets individual focus when emailed.
"""
# Built-in/Generic Imports
import os
import logging
import pathlib
import logging
import time
import yaml

# Own module
from ictoolkit.directors.log_director import setup_logger_yaml
from ictoolkit.directors.yaml_director import read_yaml_config, yaml_value_validation
from ictoolkit.directors.error_director import error_formatter
from ictoolkit.helpers.py_helper import get_function_name, get_line_number
from tracker.tracker import start_tracker

__author__ = 'IncognitoCoding'
__copyright__ = 'Copyright 2021, logspotlight'
__credits__ = ['IncognitoCoding']
__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'IncognitoCoding'
__status__ = 'Development'


def merge_software_monitored_settings(config_yaml_read: yaml) -> list:
    """
    This function is part of the yaml import. The function takes the users software name, software path, and software log search strings and merges them into a multidimensional list.
    This function is required to allow monitored software entries in the yaml configuration file. The yaml configuration file allows dynamic software entries. This allows the user to
    add software without updating the script. This function will create an list with the required monitored software settings. Calling the function will pull the monitored software
    settings and merge the user-selected software log path and software log search string.

    Args:
        config_yaml_read (yaml): read in YAML configuration

    Raises:
        ValueError: The YAML software entry section is missing the required keys. Please verify you have set all required keys and try again
        ValueError: No value has been entered for '{key}' nested key 'info_search' in the YAML file
        ValueError: Incorrect '{key}' nested key 'info_search' YAML value. <class 'str' or class 'list'> is required

    Returns:
        list: A list of individual software monitored settings. Each line represents an individual software. The list is returned with individual list elements. Each list element
              will contain the software name, software URL log path, and "software log search info.
              Return Example: [['Sonarr', '\\\\mypath\\sonarr sample.log', ['|Error|', 'Warning'], None, None], ['Radarr', '\\\\mypath\\radarr sample.log', '|Error|', None, None]]
    """
    logger = logging.getLogger(__name__)
    logger.debug(f'=' * 20 + get_function_name() + '=' * 20)
    # Custom flowchart tracking. This is ideal for large projects that move a lot.
    # For any third-party modules, set the flow before making the function call.
    logger_flowchart = logging.getLogger('flowchart')
    logger_flowchart.debug(f'Flowchart --> Function: {get_function_name()}')
    logger.debug(
        'Passing parameters:\n'
        f'  - config_yaml_read (yaml):\n        - {config_yaml_read}\n'
    )
    # Assigns the software path and software search string to create a multidimensional list.
    # Placement Example: [name, url_log_path, info_search, post_processing_args, post_processing_info_search]
    # Return Example: ['Sonarr', '\\\\mypath\\sonarr sample.log', ['|Error|', 'Warning'], None, None]
    software_monitored_settings = []
    try:

        # Finds all software monitoring entries in the YAML configuration and loops through each one to pull the configuration settings.
        for key, monitored_software in config_yaml_read.get('software').items():
            # ####################################################################
            # ###################Dictionary Key Validation########################
            # ####################################################################
            # Gets a list of all expected keys.
            # Return Output: ['name', 'url_log_path', 'info_search', 'exclude_search', 'email_subject_line', 'post_processing_args', 'post_processing_add_match', 'post_processing_info_search', 'post_processing_email_subject_line']
            monitored_software_keys = list(monitored_software.keys())
            # Checks if the key words exist in the dictionary.
            # This validates the correct return dictionary keys from the monitored_software settings.
            if (
                'name' not in str(monitored_software_keys)
                or 'url_log_path' not in str(monitored_software_keys)
                or 'info_search' not in str(monitored_software_keys)
                or 'exclude_search' not in str(monitored_software_keys)
                or 'email_subject_line' not in str(monitored_software_keys)
                or 'post_processing_args' not in str(monitored_software_keys)
                or 'post_processing_add_match' not in str(monitored_software_keys)
                or 'post_processing_info_search' not in str(monitored_software_keys)
                or 'post_processing_email_subject_line' not in str(monitored_software_keys)
            ):
                error_args = {
                    'main_message': 'The YAML software entry section is missing YAML configuration keys.',
                    'error_type': KeyError,
                    'expected_result': ['name', 'url_log_path', 'info_search', 'exclude_search', 'email_subject_line', 'post_processing_args', 'post_processing_add_match', 'post_processing_info_search', 'post_processing_email_subject_line'],
                    'returned_result': monitored_software_keys,
                    'suggested_resolution': 'Please verify you have set all required keys and try again.',
                }
                error_formatter(error_args, __name__, get_line_number())

            # Gets software configuration settings from the yaml configuration.
            name = monitored_software.get('name')
            url_log_path = monitored_software.get('url_log_path')
            info_search = monitored_software.get('info_search')
            exclude_search = monitored_software.get('exclude_search')
            email_subject_line = monitored_software.get('email_subject_line')
            post_processing_args = monitored_software.get('post_processing_args')
            post_processing_add_match = monitored_software.get('post_processing_add_match')
            post_processing_info_search = monitored_software.get('post_processing_info_search')
            post_processing_email_subject_line = monitored_software.get('post_processing_email_subject_line')

            # Validates the YAML value.
            # Email subject and Post-processing values are not required because these are optional settings.
            yaml_value_validation('name', name, str)
            yaml_value_validation('url_log_path', url_log_path, str)
            yaml_value_validation('info_search', info_search, [str, list])

            # Local YAML value validation because multiple types (str or list) are possible.
            if not info_search:
                error_args = {
                    'main_message': f'No value has been entered for \'{key}\' nested key \'info_search\' in the YAML file.',
                    'error_type': KeyError,
                    'expected_result': 'A value in the yaml file for info_search',
                    'returned_result': 'None',
                    'suggested_resolution': 'Please verify you have set all required keys and try again.',
                }
                error_formatter(error_args, __name__, get_line_number())
            if not isinstance(info_search, list) and not isinstance(info_search, str):
                error_args = {
                    'main_message': f'Incorrect \'{key}\' nested key \'info_search\' YAML value. <class \'str\' or class \'list\'> is required.',
                    'error_type': KeyError,
                    'expected_result': 'list or str',
                    'returned_result': type(info_search),
                    'suggested_resolution': 'Please verify you have set all required keys and try again.',
                }
                error_formatter(error_args, __name__, get_line_number())
            # Takes the software path and software search string and creates a single multidimensional list entry.
            software_monitored_settings.append(
                {
                    'name': name,
                    'url_log_path': url_log_path,
                    'info_search': info_search,
                    'exclude_search': exclude_search,
                    'email_subject_line': email_subject_line,
                    'post_processing_args': post_processing_args,
                    'post_processing_add_match': post_processing_add_match,
                    'post_processing_info_search': post_processing_info_search,
                    'post_processing_email_subject_line': post_processing_email_subject_line
                }
            )
        logger.debug(f'Returning value(s):\n  - Return = {software_monitored_settings}')

        return software_monitored_settings
    except Exception as error:
        if 'Originating error on line' in str(error):
            logger.debug(f'Forwarding caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
            raise error
        else:
            error_args = {
                'main_message': 'A general error occurred while merging the software monitoring settings.',
                'error_type': Exception,
                'original_error': error,
            }
            error_formatter(error_args, __name__, get_line_number())


def populate_startup_variables() -> dict:
    """
    This function populates all hard-coded and yaml-configuration variables into a dictionary that is pulled into the main function.
    YAML entry validation checks are performed within this function. No manual configurations are setup within the program. All user
    settings are completed in the "settings.yaml" configuration file.

    Raises:
        ValueError: The 'general' key is missing from the YAML file
        ValueError: The 'software' key is missing from the YAML file
        ValueError: The 'email' key is missing from the YAML file
        ValueError: The 'companion_programs' key is missing from the YAML file
        ValueError: The 'logging' key is missing from the YAML file
        ValueError: {error}Additional traceback reverse path line
        ValueError: An error occurred while merging the software monitoring settings.
        NameError: {error}Additional traceback reverse path line
        KeyError: {error}Additional traceback reverse path line
        ValueError: {error}Additional traceback reverse path line
        ValueError: An error occurred while populating the startup variables.

    Returns:
        dict: A dictionary of all startup variables required for the program to run. These startup variables consist of pre-configured and YAML configuration.
    """
    logger = logging.getLogger(__name__)
    logger.debug(f'=' * 20 + get_function_name() + '=' * 20)
    # Custom flowchart tracking. This is ideal for large projects that move a lot.
    # For any third-party modules, set the flow before making the function call.
    logger_flowchart = logging.getLogger('flowchart')
    logger_flowchart.debug(f'Flowchart --> Function: {get_function_name()}')

    # Initialized an empty dictionary for running variables.
    startup_variables = {}
    # Initialized an empty dictionary for email variables.
    email_settings = {}

    # This is required to start the program. The YAML file is read to set the required variables.
    # No file output or formatted console logging is completed in these variable population sections. Basic print statements will prompt an error.
    # Each configuration section is unique. To make the read easier, each sections will be comment blocked using ############.
    try:
        # Gets the config from the YAML file.
        # Gets the main program root directory.
        main_script_path = pathlib.Path.cwd()
        # Sets the reports directory save path.
        settings_path_name = os.path.abspath(f'{main_script_path}/settings.yaml')
        returned_yaml_read_config = read_yaml_config(settings_path_name, 'FullLoader')

        # Validates required root keys exist in the YAML configuration.
        if 'general' not in returned_yaml_read_config:
            error_args = {
                'main_message': 'The \'general\' key is missing from the YAML file.',
                'error_type': KeyError,
                'suggested_resolution': 'Please verify you have set all required keys and try again.',
            }
            error_formatter(error_args, __name__, get_line_number())
        if 'software' not in returned_yaml_read_config:
            error_args = {
                'main_message': 'The \'software\' key is missing from the YAML file.',
                'error_type': KeyError,
                'suggested_resolution': 'Please verify you have set all required keys and try again.',
            }
            error_formatter(error_args, __name__, get_line_number())
        if 'email' not in returned_yaml_read_config:
            error_args = {
                'main_message': 'The \'email\' key is missing from the YAML file.',
                'error_type': KeyError,
                'suggested_resolution': 'Please verify you have set all required keys and try again.',
            }
            error_formatter(error_args, __name__, get_line_number())
        if 'companion_programs' not in returned_yaml_read_config:
            error_args = {
                'main_message': 'The \'companion_programs\' key is missing from the YAML file.',
                'error_type': KeyError,
                'suggested_resolution': 'Please verify you have set all required keys and try again.',
            }
            error_formatter(error_args, __name__, get_line_number())

        ##############################################################################
        # Gets the monitoring software sleep settings.
        #
        # Time is in seconds.
        monitor_sleep = returned_yaml_read_config.get('general', {}).get('monitor_sleep')
        yaml_value_validation('monitor_sleep', monitor_sleep, int)
        # Sets the sleep time in seconds to the startup_variable dictionary
        startup_variables['monitor_sleep'] = monitor_sleep
        ##############################################################################
        # Gets the option to enable or not enable email alerts.
        email_alerts = returned_yaml_read_config.get('general', {}).get('email_alerts')
        yaml_value_validation('email_alerts', email_alerts, bool)
        # Sets the sleep time in seconds to the startup_variable dictionary
        startup_variables['email_alerts'] = email_alerts
        ##############################################################################
        # Gets the option to enable or not enable program error email alerts.
        #
        alert_program_errors = returned_yaml_read_config.get('general', {}).get('alert_program_errors')
        yaml_value_validation('alert_program_errors', alert_program_errors, bool)
        # Sets the sleep time in seconds to the startup_variable dictionary
        startup_variables['alert_program_errors'] = alert_program_errors
        ##############################################################################
        # Sets email values.
        smtp = returned_yaml_read_config.get('email', {}).get('smtp')
        authentication_required = returned_yaml_read_config.get('email', {}).get('authentication_required')
        use_tls = returned_yaml_read_config.get('email', {}).get('use_tls')
        username = returned_yaml_read_config.get('email', {}).get('username')
        password = returned_yaml_read_config.get('email', {}).get('password')
        from_email = returned_yaml_read_config.get('email', {}).get('from_email')
        to_email = returned_yaml_read_config.get('email', {}).get('to_email')
        send_message_encrypted = returned_yaml_read_config.get('email', {}).get('send_message_encrypted')
        send_email_template = returned_yaml_read_config.get('email', {}).get('send_email_template')
        limit_message_detail = returned_yaml_read_config.get('email', {}).get('limit_message_detail')
        message_encryption_password = returned_yaml_read_config.get('email', {}).get('message_encryption_password')
        # Gets the random "salt".
        # yaml bytes entry being passed is not allowing it to be recognized as bytes.
        # Seems the only way to fix the issue is to strip the bytes section and re-encode.
        # Strips the bytes section off the input.
        # Removes first 2 characters.
        unconverted_encrypted_info = returned_yaml_read_config.get('email', {}).get('message_encryption_random_salt')[2:]

        yaml_value_validation('smtp', smtp, str)
        yaml_value_validation('authentication_required', authentication_required, bool)
        yaml_value_validation('use_tls', use_tls, bool)
        yaml_value_validation('username', username, str)
        yaml_value_validation('password', password, str)
        yaml_value_validation('from_email', from_email, str)
        yaml_value_validation('to_email', to_email, str)
        yaml_value_validation('send_email_template', send_email_template, bool)
        yaml_value_validation('send_message_encrypted', send_message_encrypted, bool)
        yaml_value_validation('limit_message_detail', limit_message_detail, bool)
        yaml_value_validation('message_encryption_password', message_encryption_password, str)
        yaml_value_validation('unconverted_encrypted_info', unconverted_encrypted_info, str)

        # Adds the email_settings into a dictionary.
        email_settings['smtp'] = smtp
        email_settings['authentication_required'] = authentication_required
        email_settings['use_tls'] = use_tls
        email_settings['username'] = username
        email_settings['password'] = password
        email_settings['from_email'] = from_email
        email_settings['to_email'] = to_email
        email_settings['send_email_template'] = send_email_template
        email_settings['send_message_encrypted'] = send_message_encrypted
        email_settings['limit_message_detail'] = limit_message_detail
        email_settings['message_encryption_password'] = message_encryption_password
        # Removes last character.
        unconverted_encrypted_info = unconverted_encrypted_info[:-1]
        # Re-encodes the salt and sets value to the email_settings dictionary.
        # Adds the random "salt" to the email_settings into a dictionary.
        email_settings['message_encryption_random_salt'] = unconverted_encrypted_info.encode()
        # Sets email dictionary settings to the startup_variable dictionary.
        startup_variables['email_settings'] = email_settings
        ##############################################################################
        # Gets the monitoring software settings by calling the function and merging the user-selected software log path and software log search string.
        # Return Example: [['Sonarr', '\\\\mypath\\sonarr sample.log', ['|Error|', 'Warning'], None, None], ['connection skipped'], ['Radarr', '\\\\mypath\\radarr sample.log', '|Error|', None, None]]
        try:
            monitored_software_settings = merge_software_monitored_settings(returned_yaml_read_config)
        except Exception as error:
            if 'Originating error on line' in str(error):
                logger.debug(f'Forwarding caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
                raise error
            else:
                error_args = {
                    'main_message': 'A general error occurred while merging the software monitoring settings.',
                    'error_type': Exception,
                    'original_error': error,
                }
                error_formatter(error_args, __name__, get_line_number())
        ##############################################################################
        # Sets the monitored software settings to the startup_variable dictionary
        startup_variables['monitored_software_settings'] = monitored_software_settings
        ##############################################################################
        # Gets the users option on enabling the web companion.
        decryptor_web_companion_option = returned_yaml_read_config.get('companion_programs', {}).get('decryptor_web_companion_option')
        yaml_value_validation('decryptor_web_companion_option', decryptor_web_companion_option, bool)
        # Sets decriptor web companion option to the startup_variable dictionary.
        startup_variables['decryptor_web_companion_option'] = decryptor_web_companion_option
        ##############################################################################

        logger.debug(f'Returning value(s):\n  - Return = {startup_variables}')

        # Returns the dictionary with all the startup variables.
        return (startup_variables)
    except Exception as error:
        if 'Originating error on line' in str(error):
            logger.debug(f'Forwarding caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
            raise error
        else:
            error_args = {
                'main_message': 'A general error occurred while populating the startup variables.',
                'error_type': Exception,
                'original_error': error,
            }
            error_formatter(error_args, __name__, get_line_number())


def main():
    """
     The netcortex's main function will setup the main logger and kick off the tracker.
    """
    # ############################################################################################
    # ######################Gets the programs main root directory/YAML File Path##################
    # ############################################################################################
    # Gets the main program root directory.
    main_script_path = pathlib.Path.cwd()

    # Checks that the main root program directory has the correct save folders created.
    # Sets the log directory save path.
    save_log_path = os.path.abspath(f'{main_script_path}/logs')
    # Checks if the save_log_path exists and if not it will be created.
    if not os.path.exists(save_log_path):
        os.makedirs(save_log_path)

    # Sets the YAML file configuration location.
    yaml_file_path = os.path.abspath(f'{main_script_path}/settings.yaml')

    try:
        # Calls function to setup the logging configuration with the YAML file.
        setup_logger_yaml(yaml_file_path)
    except Exception as error:
        if 'Originating error on line' in str(error):
            print(error)
            print('Exiting...')
            exit()
        else:
            error_args = {
                'main_message': 'A general error occurred while setting up the logger yaml.',
                'error_type': Exception,
                'original_error': error,
            }
            error_formatter(error_args, __name__, get_line_number())

    logger = logging.getLogger(__name__)
    logger.debug(f'=' * 20 + get_function_name() + '=' * 20)
    # Custom flowchart tracking. This is ideal for large projects that move a lot.
    # For any third-party modules, set the flow before making the function call.
    logger_flowchart = logging.getLogger('flowchart')
    # Deletes the flowchart log if one already exists.
    logger_flowchart.debug(f'Flowchart --> Function: {get_function_name()}')

    try:
        # Calls function to pull in the startup variables.
        startup_variables = populate_startup_variables()
    except KeyError as error:
        # KeyError output does not process the escape sequence cleanly. This fixes the output and removes the string double quotes.
        cleaned_error = str(error).replace(r'\n', '\n')[1:-1]
        logger.debug(f'Captured caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
        logger.error(cleaned_error)
        print('Exiting...')
        exit()
    except Exception as error:
        if 'Originating error on line' in str(error):
            logger.debug(f'Captured caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
            logger.error(error)
            print('Exiting...')
            exit()
        else:
            error_args = {
                'main_message': 'A general error occurred while populating the startup variables.',
                'error_type': Exception,
                'original_error': error,
            }
            error_formatter(error_args, __name__, get_line_number())

    # ####################################################################
    # ###################Dictionary Key Validation########################
    # ####################################################################
    # Gets a list of all expected keys.
    # Return Output: ['monitor_sleep', 'email_alerts', 'alert_program_errors', 'email_settings', 'monitored_software_settings', 'decryptor_web_companion_option']
    startup_variables_keys = list(startup_variables.keys())
    # Checks if the key words exist in the dictionary.
    # This validates the correct return dictionary keys from the monitored_software settings.
    if (
        'monitor_sleep' not in str(startup_variables_keys)
        or 'email_alerts' not in str(startup_variables_keys)
        or 'alert_program_errors' not in str(startup_variables_keys)
        or 'email_settings' not in str(startup_variables_keys)
        or 'monitored_software_settings' not in str(startup_variables_keys)
        or 'decryptor_web_companion_option' not in str(startup_variables_keys)
    ):
        error_args = {
            'main_message': 'The settings.log file is missing required YAML configuration keys.',
            'error_type': KeyError,
            'expected_result': ['monitor_sleep', 'email_alerts', 'alert_program_errors', 'email_settings', 'monitored_software_settings', 'decryptor_web_companion_option'],
            'returned_result': startup_variables_keys,
            'suggested_resolution': 'Please verify you have set all required keys and try again.',
        }
        error_formatter(error_args, __name__, get_line_number())

    # This section checks for required keys and pulls all the start variables to start the tracker.
    # Sets top-level main variables based on the dictionary of presets.
    # Note: Using [] will give KeyError and using get() will return None.
    email_alerts = startup_variables.get('email_alerts')
    alert_program_errors = startup_variables.get('alert_program_errors')
    monitored_software_settings = startup_variables.get('monitored_software_settings')
    email_settings = startup_variables.get('email_settings')
    monitor_sleep = startup_variables.get('monitor_sleep')
    decryptor_web_companion_option = startup_variables.get('decryptor_web_companion_option')
    try:
        start_tracker(save_log_path, email_alerts, alert_program_errors, monitored_software_settings, email_settings, monitor_sleep, decryptor_web_companion_option)
    except KeyError as error:
        # KeyError output does not process the escape sequence cleanly. This fixes the output and removes the string double quotes.
        cleaned_error = str(error).replace(r'\n', '\n')[1:-1]
        logger.debug(f'Captured caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
        logger.error(cleaned_error)
        print('Exiting...')
        exit()
    except Exception as error:
        if 'Originating error on line' in str(error):
            logger.debug(f'Captured caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
            logger.error(error)
            print('Exiting...')
            exit()
        else:
            error_args = {
                'main_message': 'A general exception occurred when starting the tracker.',
                'error_type': Exception,
                'original_error': error,
            }
            error_formatter(error_args, __name__, get_line_number())


# Checks that this is the main program initiates the classes to start the functions.
if __name__ == "__main__":

    # Prints out at the start of the program.
    print('# ' + '=' * 85)
    print('Author: ' + __author__)
    print('Copyright: ' + __copyright__)
    print('Credits: ' + ', '.join(__credits__))
    print('License: ' + __license__)
    print('Version: ' + __version__)
    print('Maintainer: ' + __maintainer__)
    print('Status: ' + __status__)
    print('# ' + '=' * 85)

    # Loops to keep the main program active.
    # The YAML configuration file will contain a sleep setting within the main function.
    while True:

        try:
            main()

            # 1 second delay sleep to prevent system resource issues if the function fails and the loop runs without any pause.
            time.sleep(5)
        except KeyError as error:
            # KeyError output does not process the escape sequence cleanly. This fixes the output and removes the string double quotes.
            cleaned_error = str(error).replace(r'\n', '\n')[1:-1]
            print(cleaned_error)
            print('Exiting...')
            exit()
        except Exception as error:
            if 'Originating error on line' in str(error):
                print(error)
                print('Exiting...')
                exit()
