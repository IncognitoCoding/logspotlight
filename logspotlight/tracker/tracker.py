"""
Performs all log tracking and launches the decryptor companion.
"""

# Built-in/Generic Imports
import os
import logging
import sys
import glob
import threading
import time
import socket
import re
import pathlib
from typing import Union
from datetime import datetime

# Libraries
from functools import partial

# Own modules
from ictoolkit.directors.file_director import file_exist_check, search_file, search_multiple_files
from ictoolkit.directors.email_director import send_email
from ictoolkit.directors.subprocess_director import start_subprocess
from ictoolkit.directors.thread_director import start_function_thread
from ictoolkit.directors.dict_director import remove_duplicate_dict_values_in_list
from ictoolkit.directors.validation_director import value_type_validation
from ictoolkit.directors.error_director import error_formatter
from ictoolkit.helpers.py_helper import get_function_name, get_line_number
# Required for the local companion module.
lib_path = os.path.abspath(os.path.join(__file__, '..', '..'))
sys.path.append(lib_path)
from companion.decryptor.http_info_decryptor import start_decryptor_site

__author__ = 'IncognitoCoding'
__copyright__ = 'Copyright 2021, tracker'
__credits__ = ['IncognitoCoding']
__license__ = 'GPL'
__version__ = '0.2'
__maintainer__ = 'IncognitoCoding'
__status__ = 'Development'


def software_log_info_check(detection_tracking_file_path: str, monitored_software_file_path: str, monitored_software_name: str, info_search: Union[str, list], exclude_search: Union[str, list]) -> Union[list, None]:
    """
    This function is used to check if the searched info exist in the software log. Uses logs, software name, and info information to determine the file matches the search info.

    Args:
        detection_tracking_file_path (str): log tracking file path.
        monitored_software_file_path (str): monitoring software log file path.
        monitored_software_name (str): monitoring software name.
        info_search (str or list): monitoring software log search info.
        exclude_search (str or list): monitoring software log exclude search info.

    Returns:
        list or None: a list of discovered search values that have not been previously matched. Each discovered value is per element. No discovered values will return None
    """
    logger = logging.getLogger(__name__)
    logger.debug(f'=' * 20 + get_function_name() + '=' * 20)
    # Custom flowchart tracking. This is ideal for large projects that move a lot.
    # For any third-party modules, set the flow before making the function call.
    logger_flowchart = logging.getLogger('flowchart')
    logger_flowchart.debug(f'Flowchart --> Function: {get_function_name()}')

    # Requires pre-logger formatting because the logger can not use one line if/else or join without excluding sections of the the output.
    if isinstance(info_search, list):
        formatted_info_search = '  - info_search (list):' + str('\n        - ' + '\n        - '.join(map(str, info_search)))
    else:
        formatted_info_search = f'  - info_search (str):\n        - {info_search}'
    if isinstance(exclude_search, list):
        formatted_exclude_search = '  - exclude_search (list):' + str('\n        - ' + '\n        - '.join(map(str, exclude_search)))
    else:
        formatted_exclude_search = f'  - exclude_search (str):\n        - {exclude_search}'

    logger.debug(
        'Passing parameters:\n'
        f'  - detection_tracking_file_path (str):\n        - {detection_tracking_file_path}\n'
        f'  - monitored_software_file_path (str):\n        - {monitored_software_file_path}\n'
        f'  - monitored_software_name (str):\n        - {monitored_software_name}\n'
        f'{formatted_info_search}\n'
        f'{formatted_exclude_search}\n'
    )

    try:
        # Creates list variable to be used for returning multiple found tracker files (ex. Rotation Backups).
        unreported_spotlight_tracker_info = []

        logger.debug('Using the software file, software name, and issued string to determine the log file spotlight section')
        logger.debug(f'Search for info in log file. Searching software \"{monitored_software_name}\" for search info \"{info_search}\"')
        # Calls function to search for info in the software log file.
        # Return Example: <list with info> or <none>
        found_software_search_entries = search_file(monitored_software_file_path, info_search)
        # Checks if search found the info in the log file.
        if found_software_search_entries is not None:
            # Sets count on matched info entries. Each discovered entry will be one per line.
            count_matched_info = len(found_software_search_entries)
            # Sets the basename variable for logging output only.
            basename_detection_path = os.path.basename(detection_tracking_file_path)
            logger.debug(f'Searching info \"{info_search}\" found {count_matched_info} matches in {monitored_software_name}\'s log file \"{monitored_software_file_path}\"')
            logger.debug('Looping through each discovered match entry and comparing against the info tracker logs.')
            # Loops through each found info entry. Found info entries will be validated against the tracker log. If it does not exist, the info entry will be added to a list.
            for index, info in enumerate(found_software_search_entries):
                # Sets the found_entry value to a variable. This is done to decrease the code complexity.
                found_info = info.get('found_entry')
                logger.debug(f'Looping through matched info {index + 1} of {count_matched_info}')
                logger.debug(f'Checking the detection tracker file \"{basename_detection_path}\" to find previously discovered info \"{found_info}\"')
                # Gets all tracker log files, including backups.
                detection_tracking_file_paths = glob.glob(f'{detection_tracking_file_path}*')

                # Calls function to search if the found entry info has already been found and added into the tracker log(s).
                # Return Example: [{'search_entry': '|Error|', 'found_entry': 'the entry found'}, {'search_entry': '|Warning|', 'found_entry': 'the entry found'}]
                found_spotlight_tracker_file_entries = search_multiple_files(detection_tracking_file_paths, found_info)
                # Checks if no return data is found in the tracker log(s). This is used to determine if the info entry has been previously discovered and needs skipped.
                if found_spotlight_tracker_file_entries is None:
                    # Checks if a value was entered for the exclude_search key.
                    if exclude_search is not None:
                        # Checking if the found spotlight entry has any exclude key words.
                        if isinstance(exclude_search, list):
                            # Skips exclude check if the user does not enter a value or empty value for the excluded search.
                            if (
                                [''] != exclude_search
                                and ['None'] != exclude_search
                            ):
                                # Loops through each excluded word to determine if the entry needs skipped.
                                for word in exclude_search:
                                    if word in found_info:
                                        exclude_entry_flag = True
                                        # Breaks because an exclude was detected.
                                        break
                                    else:
                                        exclude_entry_flag = False
                            else:
                                exclude_entry_flag = False
                        else:
                            # Checks that the entry is not an empty string before attempting to match. An empty string with no space will always match.
                            if (
                                exclude_search in found_info
                                and '' != exclude_search
                            ):
                                exclude_entry_flag = True
                            else:
                                exclude_entry_flag = False
                    else:
                        exclude_entry_flag = False

                    # Checks if the exclude flag has been set.
                    if exclude_entry_flag is False:
                        # Validates entry does not already exist in the tracker file(s) before writting.
                        if found_info not in unreported_spotlight_tracker_info:
                            logger.debug(f'The discovered spotlight info line is a new detection.\n  - Info Line = {found_info}')
                            # Adds the previous discovered issue that was not found in the tracker file to the list for processing.
                            # Returns dictionary entry and not just the second element.
                            unreported_spotlight_tracker_info.append(info)
                        else:
                            logger.debug(f'The discovered spotlight info line is a duplicate found during the same check.\n  - Info Line = {found_info}')
                    else:
                        logger.debug(f'The discovered spotlight info line was found but removed because of an excluded search entry.\n  - Removed Match Line = {found_info}')
                else:
                    logger.debug(f'The discovered spotlight info line has already been detected on a previous check.\n  - Info Line = {found_info}')
                    exclude_entry_flag = False

            # Checks if the list has any entries. Found entries will be returned in list format, and no entries will return none because the notification has already been sent.
            if (
                not unreported_spotlight_tracker_info
                and exclude_entry_flag is False
            ):
                logger.debug('Returning value(s):\n  - Return = None')
                return None
            elif exclude_entry_flag is True:
                logger.debug('Returning value(s):\n  - Return = Excluded')
                return 'Excluded'
            else:
                logger.debug(f'Returning value(s):\n  - Return = {unreported_spotlight_tracker_info}')
                return unreported_spotlight_tracker_info
        else:
            logger.debug('No matching info found. No action is required')
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
            error_formatter(error_args, __name__, error.__traceback__.tb_lineno)


def email_constructor(email_settings: dict, **message_args) -> None:
    """
    The email constructor structures all emails based on the type of message that needs to be sent. This function will setup non-HTML and HTML messages.

    Args:
        email_settings (dict): Email setting values. See the send_email function for 95% of the passing values. A few email settings are local. These are listed below.
            Additional Local email_settings:
                \\- send_email_template\\
                \\- limit_message_detail\\
        **message_args (keyword args): Message arguments to populate and structure the email. Differnet sections based on the log_section value will require
                                                            different dictionary key/values.
            Required/Optional Values for log_selection:\\
                \\- discovery:\\
                    \\- software_name (required)\\
                    \\- email_subject_line (Optional)\\
                    \\- url_log_path (required)\\
                    \\- info_search (required)\\
                    \\- exclude_search (Optional)\\
                    \\- matched_info (required)\\
                    \\- decryptor_url (Optional)\\
                \\- post-processing:\\
                    \\- software_name (required)\\
                    \\- url_log_path (required)\\
                    \\- matched_info (required)\\
                    \\- post_processing_email_subject_line (Optional)\\
                    \\- post_processing_args (Optional)\\
                    \\- post_processing_add_match (Optional)\\
                    \\- post_processing_info_search (Optional)\\
                    \\- post_processing_matched_info (Optional)\\
                    \\- decryptor_url (Optional)\\
                \\- error_message:\\
                    \\- software_name (required)\\
                    \\- email_subject_line (Optional)\\
                    \\- program_error_message (required)\\

    Raises:
        ValueError: The log_section value did not match.
        AttributeError: {error}Additional traceback reverse path line: {error.__traceback__.tb_lineno} in <{__name__}>
        TypeError: {error}Additional traceback reverse path line: {error.__traceback__.tb_lineno} in <{__name__}>
        ValueError: {error}Additional traceback reverse path line: {error.__traceback__.tb_lineno} in <{__name__}>
        ValueError: {error}Additional traceback reverse path line: {error.__traceback__.tb_lineno} in <{__name__}>
    """
    logger = logging.getLogger(__name__)
    logger.debug(f'=' * 20 + get_function_name() + '=' * 20)
    # Custom flowchart tracking. This is ideal for large projects that move a lot.
    # For any third-party modules, set the flow before making the function call.
    logger_flowchart = logging.getLogger('flowchart')
    logger_flowchart.debug(f'Flowchart --> Function: {get_function_name()}')

    # Gets the main program root directory.
    main_script_path = pathlib.Path.cwd()
    # Checks if the user choose to use the built in templates.
    send_email_template = email_settings.get('send_email_template')
    # Checks if the user choose to limit the message output.
    limit_message_detail = email_settings.get('limit_message_detail')
    # Checks the encryption choice to choose the correct template
    send_message_encrypted = email_settings.get('send_message_encrypted')
    # Gets log section to know which email needs constructured.
    log_section = message_args.get('log_section')
    # Checks if email templates are enabled.
    if send_email_template:
        # Sets the default template path.
        email_template_path = os.path.abspath(f'{main_script_path}/email_templates')
    else:
        # No email template. Setting to default values.
        email_template_path = None

    try:
        if 'discovery' == log_section:
            # Gets all requires section software match arguments.
            software_name = message_args.get('software_name')
            email_subject_line = message_args.get('email_subject_line')
            url_log_path = message_args.get('url_log_path')
            info_search = message_args.get('info_search')
            exclude_search = message_args.get('exclude_search')
            matched_info = message_args.get('matched_info')
            decryptor_url = message_args.get('decryptor_url')

            # Validates required types.
            value_type_validation(send_email_template, bool, __name__, get_line_number())
            value_type_validation(limit_message_detail, bool, __name__, get_line_number())
            value_type_validation(software_name, str, __name__, get_line_number())
            value_type_validation(url_log_path, str, __name__, get_line_number())
            value_type_validation(info_search, [str, list], __name__, get_line_number())
            if exclude_search:
                value_type_validation(exclude_search, [str, list], __name__, get_line_number())
            value_type_validation(matched_info, str, __name__, get_line_number())
            if decryptor_url:
                value_type_validation(decryptor_url, str, __name__, get_line_number())

            # Sets the default email subject line if one did not get provided in the YAML.
            if email_subject_line is None:
                email_subject_line = f'LogSpotLight Discovery Event For {software_name}'

            # Builds the message structure and sends the email.
            # Adds template name and template path into the email settings.
            if send_email_template:
                # Sets new variable, so updates can be added without altering the original dictionary.
                updated_email_settings = email_settings.copy()
                updated_email_settings['email_template_path'] = email_template_path
                # Sets template based on encryption choice.
                if send_message_encrypted:
                    if limit_message_detail:
                        # Adds the pre-built encryption template.
                        updated_email_settings['email_template_name'] = 'matched_encryption_limit.html'
                    else:
                        # Adds the pre-built encryption template.
                        updated_email_settings['email_template_name'] = 'matched_encryption.html'
                else:
                    if limit_message_detail:
                        # Adds the pre-built non-encryption template.
                        updated_email_settings['email_template_name'] = 'matched_no_encryption_limit.html'
                    else:
                        # Adds the pre-built non-encryption template.
                        updated_email_settings['email_template_name'] = 'matched_no_encryption.html'

                # Sets the non-HTML body to none because a template is being used.
                body = None
                # Sets the template args.
                template_args = {
                    'software_name': software_name,
                    'matched_info': matched_info,
                    'url_log_path': url_log_path,
                    'info_search': info_search,
                    'exclude_search': exclude_search,
                    'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'decryptor_url': decryptor_url,
                }
            else:
                # Sets new variable, so updates can be added without altering the original dictionary.
                updated_email_settings = email_settings.copy()
                # Sets template based on encryption choice.
                if send_message_encrypted:
                    if limit_message_detail:
                        # Sets encryption identifier flags, so the message gets encrypted.
                        body = (
                            f'LogSpotlight has detected a log match at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.\n'
                            'The matched log entry is encrypted. Please use the code below to decrypt the message.\n\n'
                            f'Decryption Code: @START-ENCRYPT@{matched_info}@END-ENCRYPT@\n\n'
                            f"{f'Decrypt: {decryptor_url}' if (decryptor_url) is not None else ''}".strip()
                        )
                    else:
                        # Sets encryption identifier flags, so the message gets encrypted.
                        body = (
                            f'LogSpotlight has detected a log match at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.\n'
                            f'The detected program\'s name is {software_name}\n'
                            'Below are details on how the LogSpotlight match occurred.\n'
                            f'  - Monitoring Log/File Path = {url_log_path}\n'
                            f'  - Searching Values = {info_search}\n'
                            f'  - Excluded Key Values = {exclude_search}\n'
                            'The matched log entry is encrypted. Please use the code below to decrypt the message.\n\n'
                            f'Decryption Code: @START-ENCRYPT@{matched_info}@END-ENCRYPT@\n\n'
                            f"{f'Decrypt: {decryptor_url}' if (decryptor_url) is not None else ''}".strip()
                        )
                else:
                    if limit_message_detail:
                        # Sets matched info.
                        body = (
                            f'LogSpotlight has detected a log match at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.\n'
                            f'Matched Log: {matched_info}'
                        )
                    else:
                        # Sets matched info.
                        body = (
                            f'LogSpotlight has detected a log match at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.\n'
                            f'The detected program\'s name is {software_name}\n'
                            'Below are details on how the LogSpotlight match occurred.\n'
                            f'  - Monitoring Log/File Path = {url_log_path}\n'
                            f'  - Searching Info = { info_search}\n'
                            f'  - Excluded Key Values = {exclude_search}\n'
                            'The matched log entry is listed below.\n'
                            f'Matched Log: {matched_info}'
                        )
                # Sets the template args to none because a non-HTML body is being used.
                template_args = None
        elif 'post-processing' == log_section:
            # Gets all requires section software match arguments.
            software_name = message_args.get('software_name')
            url_log_path = message_args.get('url_log_path')
            matched_info = message_args.get('matched_info')
            decryptor_url = message_args.get('decryptor_url')
            # Post-processing exclusive message arguments.
            post_processing_email_subject_line = message_args.get('post_processing_email_subject_line')
            post_processing_args = message_args.get('post_processing_args')
            post_processing_add_match = message_args.get('post_processing_add_match')
            post_processing_info_search = message_args.get('post_processing_info_search')
            post_processing_matched_info = message_args.get('post_processing_matched_info')

            # Validates required types.
            value_type_validation(send_email_template, bool, __name__, get_line_number())
            value_type_validation(limit_message_detail, bool, __name__, get_line_number())
            value_type_validation(software_name, str, __name__, get_line_number())
            value_type_validation(url_log_path, str, __name__, get_line_number())
            value_type_validation(matched_info, str, __name__, get_line_number())
            if post_processing_args:
                value_type_validation(post_processing_args, [str, list], __name__, get_line_number())
            if post_processing_add_match:
                value_type_validation(post_processing_add_match, bool, __name__, get_line_number())
            if post_processing_info_search:
                value_type_validation(post_processing_info_search, [str, list], __name__, get_line_number())
            if post_processing_matched_info:
                value_type_validation(post_processing_matched_info, str, __name__, get_line_number())
            if decryptor_url:
                value_type_validation(decryptor_url, str, __name__, get_line_number())

            # Sets the default email subject line if one did not get provided in the YAML.
            if post_processing_email_subject_line is None:
                post_processing_email_subject_line = f'Software Log Post-Processing Event For {software_name}'
            # Convert the email subject line variable for a single send_mail call.
            email_subject_line = post_processing_email_subject_line
            # Builds the message structure and sends the email.
            # Adds template name and template path into the email settings.
            if send_email_template:
                # Sets new variable, so updates can be added without altering the original dictionary.
                updated_email_settings = email_settings.copy()
                updated_email_settings['email_template_path'] = email_template_path
                # Sets template based on encryption choice.
                if send_message_encrypted:
                    if limit_message_detail:
                        # Adds the pre-built encryption template.
                        updated_email_settings['email_template_name'] = 'post-processing_encryption_limit.html'
                    else:
                        # Adds the pre-built encryption template.
                        updated_email_settings['email_template_name'] = 'post-processing_encryption.html'
                else:
                    if limit_message_detail:
                        # Adds the pre-built non-encryption template.
                        updated_email_settings['email_template_name'] = 'post-processing_no_encryption_limit.html'
                    else:
                        # Adds the pre-built non-encryption template.
                        updated_email_settings['email_template_name'] = 'post-processing_no_encryption.html'

                # Sets the non-HTML body to none because a template is being used.
                body = None
                # Sets the template args.
                template_args = {
                    'software_name': software_name,
                    'matched_info': matched_info,
                    'url_log_path': url_log_path,
                    'post_processing_args': post_processing_args,
                    'post_processing_add_match': post_processing_add_match,
                    'post_processing_info_search': post_processing_info_search,
                    'post_processing_matched_info': post_processing_matched_info,
                    'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'decryptor_url': decryptor_url,
                }
            else:
                # Sets new variable, so updates can be added without altering the original dictionary.
                updated_email_settings = email_settings.copy()
                # Sets template based on encryption choice.
                if send_message_encrypted:
                    if limit_message_detail:
                        # Sets encryption identifier flags, so the message gets encrypted.
                        body = (
                            f'LogSpotlight post-processing has been trigged at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.\n'
                            'The post-processing matched log entry is encrypted. Please use the code below to decrypt the message.\n\n'
                            f'Decryption Code: @START-ENCRYPT@{post_processing_matched_info}@END-ENCRYPT@\n\n'
                            f"{f'Decrypt: {decryptor_url}' if (decryptor_url) is not None else ''}".strip()
                        )
                    else:
                        # Sets encryption identifier flags, so the message gets encrypted.
                        body = (
                            f'LogSpotlight post-processing has been trigged at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.\n'
                            f'The triggering program\'s name is {software_name}\n'
                            'Below are details on how the LogSpotlight post-processing event was triggered.\n'
                            f'  - Triggered Monitoring Log/File Path = {url_log_path}\n'
                            f'  - Triggered Log Match = @START-ENCRYPT@{matched_info}@END-ENCRYPT@\n'
                            f'  - Post-processing Args = {post_processing_args}\n'
                            f'  - Send Matched Values As Args = {post_processing_add_match}\n'
                            f'  - Post-processing Searching Values = {post_processing_info_search}\n'
                            f'  - \n'
                            'The post-processing matched log entry is encrypted. Please use the code below to decrypt the message.\n\n'
                            f'Decryption Code: @START-ENCRYPT@{post_processing_matched_info}@END-ENCRYPT@\n\n'
                            f"{f'Decrypt: {decryptor_url}' if (decryptor_url) is not None else ''}".strip()
                        )
                else:
                    if limit_message_detail:
                        # Sets matched info.
                        body = (
                            f'LogSpotlight post-processing has been trigged at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.\n'
                            f'Matched Log: {post_processing_matched_info}<'
                        )
                    else:
                        # Sets matched info.
                        body = (
                            f'LogSpotlight post-processing has been trigged at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.\n'
                            f'The triggering program\'s name is {software_name}\n'
                            'Below are details on how the LogSpotlight post-processing event was triggered.\n'
                            f'  - Triggered Monitoring Log/File Path = {url_log_path}\n'
                            f'  - Triggered Log Match = @START-ENCRYPT@{matched_info}@END-ENCRYPT@\n'
                            f'  - Post-processing Args = {post_processing_args}\n'
                            f'  - Send Matched Values As Args = {post_processing_add_match}\n'
                            f'  - Post-processing Searching Values = {post_processing_info_search}\n'
                            f'  - \n'
                            'The post-processing matched log entry is listed below.\n'
                            f'Matched Log: {post_processing_matched_info}<'
                        )
                # Sets the template args to none because a non-HTML body is being used.
                template_args = None
        elif 'error_message' == log_section:
            # Gets all requires section software match arguments.
            software_name = message_args.get('software_name')
            email_subject_line = message_args.get('email_subject_line')
            program_error_message = message_args.get('program_error_message')

            # Validates required types.
            value_type_validation(software_name, str, __name__, get_line_number())
            value_type_validation(email_subject_line, str, __name__, get_line_number())
            value_type_validation(program_error_message, str, __name__, get_line_number())

            # Builds the message structure and sends the email. Program errors are not encrypted.
            # Adds template name and template path into the email settings.
            if send_email_template:
                # Sets new variable, so updates can be added without altering the original dictionary.
                updated_email_settings = email_settings.copy()
                updated_email_settings['email_template_path'] = email_template_path
                # Adds the pre-built non-encryption template.
                updated_email_settings['email_template_name'] = 'program_error.html'
                # Sets the non-HTML body to none because a template is being used.
                body = None
            else:
                # Sets new variable, so updates can be added without altering the original dictionary.
                updated_email_settings = email_settings.copy()
                # Sets the template args to none because a non-HTML body is being used.
                template_args = None

            # Sets email passing arguments based on the users non-HTML or HTML choice.
            if send_email_template:
                # Sets the template args.
                template_args = {
                    'software_name': software_name,
                    'email_subject_line': email_subject_line,
                    'error_message': program_error_message,
                    'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            else:
                # Sets matched info.
                body = (
                    f'{software_name} has triggered an email alert at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}.\n'
                    'You have received a message from LogSpotlight because an error occurred within the program. Please see below.\n'
                    f'Error Message: {program_error_message}'
                )
        else:
            error_args = {
                'main_message': 'The log_section value did not match.',
                'error_type': ValueError,
                'expected_result': 'discovery, post-processing, or error_message',
                'returned_result': log_section,
            }
            error_formatter(error_args, __name__, get_line_number())

        # Calls function to send the email.
        send_email(updated_email_settings, email_subject_line, body, template_args)
    except Exception as error:
        if 'Originating error on line' in str(error):
            logger.debug(f'Forwarding caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
            raise error
        else:
            error_args = {
                'main_message': 'A general exception occurred when constructing the email message.',
                'error_type': Exception,
                'original_error': error,
            }
            error_formatter(error_args, __name__, error.__traceback__.tb_lineno)


def start_tracker(save_log_path, email_alerts: str, alert_program_errors: bool, monitored_software_settings: list, email_settings: dict, monitor_sleep: str, decryptor_web_companion_option: bool) -> None:
    """
    The start tracker makes all the decisions around a log file having spotlight matches. All the primary logic for tracking is done within this function.

    Args:
        save_log_path (str): The detection tracking file path.
        email_alerts (bool): Enables email alerting.
        alert_program_errors (bool): Enables alerts when the program errors.
        monitored_software_settings (list): A list of dictionary monitored software setting values.
        email_settings (dict): Email setting values.
        monitor_sleep (str): The amount of time between each log file spotlight check.
        decryptor_web_companion_option (bool): Allows a decryption web option for encrypted info.

    Raises:
        ValueError: The software search settings are missing required keys.
        ValueError: {error}Additional traceback reverse path line: {error.__traceback__.tb_lineno} in <{__name__}>
        ValueError: A general exception occurred when attempting to send an email.
        ValueError: Additional mid-traceback details. The system cannot find the file specified while attempting to run the following post-processing commands {subprocess_command}.
        ValueError: Additional mid-traceback details. The system countered the following error ({error}) while running the following post-processing commands {subprocess_command}.
        ValueError: {error}Additional traceback reverse path line: {error.__traceback__.tb_lineno} in <{__name__}>
        ValueError: A general exception occurred when checking if the searched info exist in the software log.
    """
    logger = logging.getLogger(__name__)
    logger.debug(f'=' * 20 + get_function_name() + '=' * 20)
    # Custom flowchart tracking. This is ideal for large projects that move a lot.
    # For any third-party modules, set the flow before making the function call.
    logger_flowchart = logging.getLogger('flowchart')
    logger_flowchart.debug(f'Flowchart --> Function: {get_function_name()}')
    # Custom detection log file for detected alerts.
    detected_logger = logging.getLogger('detected')

    # ###############################################
    # ##########Sets Pre Log Check Settings#########
    # ###############################################
    #
    # Requires pre-logger formatting because the logger can not use one line if/else or join without excluding sections of the the output.
    formatted_monitored_software_settings = '  - monitored_software_settings (list):' + str('\n        - ' + '\n        - '.join(map(str, monitored_software_settings)))
    formatted_email_settings = '  - email_settings (dict):\n        - ' + '\n        - '.join(': '.join((key, str(val))) for (key, val) in email_settings.items())
    logger.debug(
        'Passing parameters:\n'
        f'  - save_log_path (str):\n        - {save_log_path}\n'
        f'  - email_alerts (bool):\n        - {email_alerts}\n'
        f'  - alert_program_errors (bool):\n        - {alert_program_errors}\n'
        f'{formatted_monitored_software_settings}\n'
        f'{formatted_email_settings}\n'
        f'  - monitor_sleep (str):\n        - {monitor_sleep}\n'
        f'  - decryptor_web_companion_option (bool):\n        - {decryptor_web_companion_option}\n'
    )

    # Sets the decryptor companion.
    # Checks if the user enabled the start_decryptor_site companion program program.
    if decryptor_web_companion_option is True:
        # Checks if the start_decryptor_site companion program program is not running for initial startup.
        if 'companion_decryptor_thread' not in str(threading.enumerate()):
            logger.info('Starting the start_decryptor_site companion program')
            # Gets message encryption settings from the yaml configuration to pass to the companion decryptor.
            message_encryption_password = email_settings.get('message_encryption_password')
            message_encryption_random_salt = email_settings.get('message_encryption_random_salt')
            # This calls the start_function_thread function and passes the companion start_decryptor_site function and arguments to the start_function_thread.
            # You have to use functools for this to work correctly. Adding the function without functools will cause the function to start before being passed to the start_function_thread.
            start_function_thread(partial(start_decryptor_site, message_encryption_password, message_encryption_random_salt, False), 'companion_decryptor_thread', False)
            # Sleeps 5 seconds to allow startup.
            time.sleep(5)
            # Gets the hosts IP address for message output.
            host_ip = socket.gethostbyname(socket.gethostname())
            decryptor_url = f'http://{host_ip}:5000/'
            # Validates the start_decryptor_site companion program started.
            if 'companion_decryptor_thread' in str(threading.enumerate()):
                logger.info(f'The decryptor site companion program has started. You may access the webpage via http://127.0.0.1:5000/ or {decryptor_url}')
            else:
                logger.warning('Failed to start the start_decryptor_site companion program. The program will continue, but additional troubleshooting will be required to utilize the decryption companion\'s web interface')
        else:
            # Gets the hosts IP address for message output.
            host_ip = socket.gethostbyname(socket.gethostname())
            decryptor_url = f'http://{host_ip}:5000/'
            logger.debug(f'The decryptor site companion program check passed. The site is still reachable via http://127.0.0.1:5000/ or {decryptor_url}.')
    elif decryptor_web_companion_option is False:
        decryptor_url = None
        # Checks if the start_decryptor_site companion program is running. This can happen when the yaml is modified when the program is running.
        if 'companion_decryptor_thread' in str(threading.enumerate()):
            logger.warning('The user has chosen to turn off the start_decryptor_site companion program. Please restart the program for this change to take effect')
        else:
            logger.debug('The user has chosen not to use the start_decryptor_site companion program')
    logger.debug('Starting the main program function')
    logger.info(f'{monitor_sleep} seconds until next log check')
    # Sleeps for the amount of seconds set in the YAML file.
    time.sleep(monitor_sleep)

    # Setting the hard-coded info tracker log path.
    detection_log_name = 'detected.log'
    detection_tracking_file_path = os.path.abspath(f'{save_log_path}/{detection_log_name}')

    # Loops through each monitored software settings entry.
    for software_settings in monitored_software_settings:
        # ####################################################################
        # ###################Dictionary Key Validation########################
        # ####################################################################
        # Gets a list of all expected keys.
        # Return Output: ['name', 'url_log_path', 'info_search', 'exclude_search', 'email_subject_line', 'post_processing_args', 'post_processing_add_match', 'post_processing_info_search', 'post_processing_email_subject_line']
        software_settings_keys = list(software_settings.keys())
        # Checks if the key words exist in the dictionary.
        # This validates the correct return dictionary keys from the monitored_software settings.
        if (
            'name' not in str(software_settings_keys)
            and 'url_log_path' not in str(software_settings_keys)
            and 'info_search' not in str(software_settings_keys)
            and 'exclude_search' not in str(software_settings_keys)
            and 'email_subject_line' not in str(software_settings_keys)
            and 'post_processing_args' not in str(software_settings_keys)
            and 'post_processing_add_match' not in str(software_settings_keys)
            and 'post_processing_info_search' not in str(software_settings_keys)
            and 'post_processing_email_subject_line' not in str(software_settings_keys)
        ):
            error_args = {
                'main_message': 'The software search settings are missing required keys.',
                'error_type': KeyError,
                'expected_result': ['name', 'url_log_path', 'info_search', 'exclude_search', 'email_subject_line', 'post_processing_args', 'post_processing_add_match', 'post_processing_info_search', 'post_processing_email_subject_line'],
                'returned_result': software_settings_keys,
                'suggested_resolution': 'Please verify you have set all required keys and try again.',
            }
            error_formatter(error_args, __name__, get_line_number())

        # Gets the software monitoring info. Software value validation completed during the YAML import.
        # Entry Example1: ['MySoftware', 'software sample log.txt', '|Error|', 'connection issue', 'Error Detected in MySoftware', '\\mypath\\software.py', True, 'Sample Search' , 'Software.py Ran Successful']
        # Entry Example2: ['Sonarr', '\\\\mypath\\sonarr sample.log', ['|Error|', 'Warning'], None, None, None, None, None, None]
        software_name = software_settings.get('name')
        url_log_path = os.path.abspath(software_settings.get('url_log_path'))
        info_search = software_settings.get('info_search')
        exclude_search = software_settings.get('exclude_search')
        email_subject_line = software_settings.get('email_subject_line')
        post_processing_args = software_settings.get('post_processing_args')
        post_processing_add_match = software_settings.get('post_processing_add_match')
        post_processing_info_search = software_settings.get('post_processing_info_search')
        post_processing_email_subject_line = software_settings.get('post_processing_email_subject_line')
        # Sets the basename for cleaner logging output.
        basename_monitoring_software = os.path.basename(url_log_path)
        logger.debug(f'Processing software \"{software_name}\" with the file name \"{basename_monitoring_software}\" and searching for info \"{info_search}\"')

        try:
            # Verifies monitoring software log file exists.
            file_exist_check(url_log_path, software_name)
            # Calls function to check if the searched info exist in the software log.
            matched_software_info = software_log_info_check(detection_tracking_file_path, url_log_path, software_name, info_search, exclude_search)
            # Validates the return value is not equal to "None". None = nothing was found.
            if (
                matched_software_info is not None
                and 'Excluded' != matched_software_info
            ):
                logger.info(f'A match has occurred when searching \'{url_log_path}\'')
                # Sets count on total entries found
                total_info_entries = len(matched_software_info)

                logger.debug('Starting to loop through matched info')
                # Loops through matched software info. If info exists in the list, an email will be sent.
                for index, info in enumerate(matched_software_info):
                    # Sets the found_entry value to a variable. This is done to decrease the code complexity.
                    matched_info = info.get('found_entry')
                    # Custom log level that has been created for alerts. (39 = ALERT)
                    logger.debug(f'Writing output to tracker log. Entry {index + 1} of {total_info_entries}')
                    # Writes returned software info status.
                    detected_logger.info(matched_info)

                    # Checks if email notifications are enabled
                    if email_alerts:
                        logger.debug(f'Sending email. Entry {index + 1} of {total_info_entries}')
                        email_constructor(
                            email_settings,
                            software_name=software_name,
                            email_subject_line=email_subject_line,
                            url_log_path=url_log_path,
                            info_search=info_search,
                            exclude_search=exclude_search,
                            matched_info=matched_info,
                            log_section='discovery',
                            decryptor_url=decryptor_url,
                        )
                    else:
                        # Custom log level that has been created for alerts. (39 = ALERT)
                        logger.debug('Email alerting is disabled. The found log event is not be sent')

                # ###########################################################
                # #######################Post-Processing#####################
                # ###########################################################
                # Checks if any post-processing arguments are not being used.
                if post_processing_args:
                    # Custom log level that has been created for alerts. (39 = ALERT)
                    logger.info(f'The info is newly discovered. Post-processing task enabled. Please wait while the process completes...')
                    # Checks if matched info should be forward as part of the post-processing arguments.
                    if post_processing_add_match is True:
                        logger.debug(f'The user chooses to forward matched info as post-processing arguments')
                        # Checks if post_process_args is a string or list to know how to add the matched info.
                        if isinstance(post_processing_args, str):
                            # Creates a list with the users post_processing_args with the matched info.
                            post_processing_args = [post_processing_args, matched_info]
                            logger.debug('The user sent only a single post-processing argument and set the post_processing_add_match flag to true.'
                                         ' The program is adding the matched info to the existing list.'
                                         f'\n    - post_processing_args = {post_processing_args}')
                        elif isinstance(post_processing_args, list):
                            # Adds matched info to the users post_processing_args
                            post_processing_args.append(matched_info)
                            logger.debug('The user sent multiple post-processing arguments and set the post_processing_add_match to true.'
                                         f' The program is adding the matched info to the existing list.'
                                         f'\n    - post_processing_args = {post_processing_args}')
                    else:
                        logger.debug(f'The user did not choose to forward matched info as post-processing arguments')

                    # Calls function to perform post processing task.
                    post_processing_output = start_subprocess(post_processing_args)
                    # Make sure a search entry has been entered.
                    if post_processing_info_search:
                        # Validates post-processing information is returned.
                        if post_processing_output.stdout:
                            # Assigns list variable to be used in this function.
                            # Required to return multiple found strings.
                            matched_entries = []
                            # Loops through all the post-processing entries.
                            for post_output_entry in post_processing_output.stdout:
                                # Checks if post_processing_info_search is a str or list.
                                if isinstance(post_processing_info_search, str):
                                    # Checks if the search entry exists.
                                    if post_processing_info_search in post_output_entry:
                                        logger.debug(f'Post-processing search value \"{post_output_entry}\" found. Adding the value to the list \"matched_entries\"')
                                        # Adds found line and search value to list.
                                        matched_entries.append({'search_entry': post_processing_info_search, 'found_entry': post_output_entry})
                                elif isinstance(post_processing_info_search, list):
                                    # Loops through each search value.
                                    for search_value in post_processing_info_search:
                                        # Checks if a value exists as each line is read.
                                        if search_value in post_output_entry:
                                            logger.debug(f'Post-processing search value \"{search_value}\" from value list \"{post_output_entry}\" found. Adding the value to the list \"matched_entries\"')
                                            # Adds found line and search value to list.
                                            matched_entries.append({'search_entry': search_value, 'found_entry': post_output_entry})
                            # Checks if searching_value is str or list to clean up any potential duplicates
                            if isinstance(post_processing_info_search, list):
                                logger.debug(f'A list of all found search matches is listed below: {matched_entries}')
                                logger.debug(f'Removing any duplicate entries that may have matched multiple times with similar search info')
                                # Removes any duplicate matched values using the 2nd entry (1st element). This can happen if a search list has a similar search word that discovers the same line.
                                # Example Return: [{'search_entry': '|Error|', 'found_entry': 'the entry found2'}]
                                matched_entries = remove_duplicate_dict_values_in_list(matched_entries, 1)
                                logger.debug(f'The adjusted match list with removed duplicates is listed below: {matched_entries}')
                            # Checks if email notifications are enabled
                            # Loops post-processing info. If info exists in the list, an email will be sent.
                            for index, info in enumerate(matched_entries):
                                # Sets the found_entry value to a variable. This is done to decrease the code complexity.
                                post_processing_matched_info = info.get('found_entry')
                                # Checks if email notifications are enabled
                                if email_alerts:
                                    logger.debug(f'Sending email. Entry {index + 1} of {total_info_entries}')
                                    email_constructor(
                                        email_settings,
                                        software_name=software_name,
                                        email_subject_line=email_subject_line,
                                        url_log_path=url_log_path,
                                        post_processing_email_subject_line=post_processing_email_subject_line,
                                        post_processing_args=post_processing_args,
                                        post_processing_add_match=post_processing_add_match,
                                        post_processing_info_search=post_processing_info_search,
                                        post_processing_matched_info=post_processing_matched_info,
                                        matched_info=matched_info,
                                        log_section='post-processing',
                                        decryptor_url=decryptor_url,
                                    )
                                    # Custom log level that has been created for alerts. (39 = ALERT)
                                    logger.debug('Email sent and the post-processing event ran')
                                else:
                                    # Custom log level that has been created for alerts. (39 = ALERT)
                                    logger.debug('Email alerting is disabled. The post-processing event ran, but no event was sent')
                        else:
                            logger.info('The post-processing job ran. No return output was sent')
                    else:
                        logger.debug(f'No post-processing search entry configured')
                    # Logs post-processing output by joining the lines. Without .join the info would be grouped on a few lines
                    logger.debug("Post-processing output message listed below: " + '\n'.join(post_processing_output.stdout))
            elif 'Excluded' == matched_software_info:
                logger.info('The discovered spotlight entry was excluded. No action is required')
            else:
                logger.info('The discovered spotlight entry was previously discovered. No action is required')
            logger.info(f'Finished processing log searches for {software_name}')
        except Exception as error:
            if 'Originating error on line' in str(error):
                # Checking if the user chooses not to send program errors to email.
                if alert_program_errors is True and email_alerts is True:

                    try:
                        # Checks if the user entered an incorrect program entry.
                        if 'The system cannot find the file specified' in str(error):
                            # Pulls the subprocess entry name using regex. The .* is used to match any character between ().
                            # Err Example: An error occurred while running the subprocess (noAPP), [WinError 2] The system cannot find the file specified, Originating error on line 80 in <ictoolkit.directors.subprocess_director>
                            # Result: noAPP
                            result = re.search(r"\(.*\)", str(error))
                            # Sets the matching result.
                            subprocess_command = result.group(0)
                            email_subject_line = 'Software Log Monitor - Post-Processing Failed To Run'
                            # Sets program error message.
                            program_error_message = (f'The system cannot find the file specified while attempting to run the following post-processing commands '
                                                     f'{subprocess_command}. This error can happen because of a typo, or the calling program is not referenceable. The program will continue, but the post-processing action '
                                                     'will not complete without manual intervention.')
                        # Checks if the user entered a subprocess that didn't get flagged by an incorrect program entry.
                        elif 'The sub-process' in str(error):
                            # Pulls the subprocess entry name using regex. The .* is used to match any character between ().
                            # Err Example: An error occurred while running the subprocess (noAPP), [WinError 2] The system cannot find the file specified, Originating error on line 80 in <ictoolkit.directors.subprocess_director>
                            # Result: noAPP
                            result = re.search(r"\(.*\)", str(error))
                            # Sets the matching result.
                            subprocess_command = result.group(0)
                            email_subject_line = 'Software Log Monitor - Post-Processing Failed To Run'
                            program_error_message = (f'The system countered the following error ({error}) while running the following post-processing commands '
                                                     f'{subprocess_command}. This error can happen because of a typo, or the calling program is not referenceable. The program will continue, but the post-processing '
                                                     'action will not complete without manual intervention.')
                        else:
                            email_subject_line = 'Software Log Monitor - Program Issue Occurred'
                            program_error_message = f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}|Error|Exception Thrown|{error}'

                        email_constructor(
                            email_settings,
                            software_name=software_name,
                            email_subject_line=email_subject_line,
                            program_error_message=program_error_message,
                            log_section='error_message',
                        )
                    except Exception as error:
                        if 'Originating error on line' in str(error):
                            logger.debug(f'Forwarding caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
                            raise error
                        else:
                            error_args = {
                                'main_message': 'A general exception occurred when attempting to send an email.',
                                'error_type': Exception,
                                'original_error': error,
                            }
                            error_formatter(error_args, __name__, error.__traceback__.tb_lineno)
                elif alert_program_errors is False:
                    logger.debug(f'The user chooses not to send program errors to email')
                else:
                    error_args = {
                        'main_message': 'The user did not choose an option on sending program errors to email. Continuing to exit',
                        'error_type': ValueError,
                    }
                    error_formatter(error_args, __name__, error.__traceback__.tb_lineno)
                # Checks if the user entered an incorrect program entry.
                if 'The system cannot find the file specified' in str(error):
                    # Pulls the subprocess entry name using regex. The .* is used to match any character between ().
                    # Err Example: An error occurred while running the subprocess (noAPP), [WinError 2] The system cannot find the file specified, Originating error on line 80 in <ictoolkit.directors.subprocess_director>
                    # Result: noAPP
                    result = re.search(r"\(.*\)", str(error))
                    # Sets the matching result.
                    subprocess_command = result.group(0)
                    error_args = {
                        'main_message': f'Additional mid-traceback details. The system cannot find the file specified while attempting to run the following post-processing commands {subprocess_command}.',
                        'error_type': Exception,
                        'expected_result': 'A reachable sub-processing program.',
                        'returned_result': 'This error can happen because of a typo, or the calling program is not referenceable. Please check your settings.yaml file settings.',
                        'original_error': error,
                    }
                    error_formatter(error_args, __name__, error.__traceback__.tb_lineno)
                # Checks if the user entered a subprocess that didn't get flagged by an incorrect program entry.
                elif 'The sub-process' in str(error):
                    # Pulls the subprocess entry name using regex. The .* is used to match any character between ().
                    # Err Example: An error occurred while running the subprocess (noAPP), [WinError 2] The system cannot find the file specified, Originating error on line 80 in <ictoolkit.directors.subprocess_director>
                    # Result: noAPP
                    result = re.search(r"\(.*\)", str(error))
                    # Sets the matching result.
                    subprocess_command = result.group(0)
                    error_args = {
                        'main_message': f'Additional mid-traceback details. The system countered the following error ({error}) while running the following post-processing commands {subprocess_command}.',
                        'error_type': Exception,
                        'expected_result': 'A reachable sub-processing program.',
                        'returned_result': 'This error can happen because of a typo, or the calling program is not referenceable. Please check your settings.yaml file settings.',
                        'original_error': error,
                    }
                    error_formatter(error_args, __name__, error.__traceback__.tb_lineno)
                else:
                    logger.debug(f'Forwarding caught {type(error).__name__} at line {error.__traceback__.tb_lineno} in <{__name__}>')
                    raise error
            else:
                error_args = {
                    'main_message': 'A general exception occurred when checking if the searched info exist in the software log.',
                    'error_type': Exception,
                    'original_error': error,
                }
                error_formatter(error_args, __name__, error.__traceback__.tb_lineno)
