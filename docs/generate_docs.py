#
# Python script for generating new documentation
#
# _author_ = Grant Curell <grant_curell@dell.com>
#
#
# Copyright (c) 2022 Dell EMC Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import ast
import logging
import re
import subprocess
import sys
from shutil import copyfile
from os import scandir, getcwd
from os.path import abspath, basename, join
from collections import OrderedDict

import jinja2
import yaml


def _get_powershell_example(script_to_process: str):
    """ Utility method for getting the PowerShell example """
    logging.info("Retrieving PowerShell example for " + script_to_process)
    pipe = subprocess.Popen(["powershell.exe",
                             "Get-Help",
                             abspath(join(categories_dictionary['powershell_path'], script_to_process)),
                             "-Examples"],
                            stdout=subprocess.PIPE)

    try:
        output = pipe.stdout.read().decode('utf-8').split("-------------------------- EXAMPLE 1 "
                                                          "--------------------------")[1].strip()
    except IndexError:
        print("Received an index error while processing " + script_to_process + ". This typically means the help "
              "section of the PowerShell is not formatted correctly. Try running 'Get-Help .\\" + script_to_process +
              " -Examples' and verify that the examples output correctly. It may also mean that the name in "
              "categories does not match the actual filename. It might also mean the spacing on your param argument"
              " in PowerShell is off or that there is not a new line after the closing ')' on param. It must have a "
              "new line or PS does not print the EXAMPLE header as expected.")
        sys.exit(0)
    output = output.splitlines()

    # Remove blank lines - PowerShell otherwise prints with several unnecessary blank lines
    example = ""
    for line_to_clean in filter(lambda x: not re.match(r'^\s*$', x), output):
        example = example + line_to_clean + '\n'
    example = re.sub(r"-------------------------- EXAMPLE \d --------------------------", "\n", example)

    return example


logging.info("Reading in YML...")
with open('categories.yml') as category_file:
    categories_dictionary = yaml.load(category_file, Loader=yaml.SafeLoader)

python_file_list = []
module_data = {'deploy': {}, 'update': {}, 'monitor': {}, 'maintain': {}, 'supportassistenterprise': {}, 'powermanager': {}, 'other': {}}

for entry in scandir(categories_dictionary['python_code_path']):
    if entry.path.endswith(".py"):
        python_file_list.append(entry.path)

logging.info("Scanning Python files for docstrings and extracting them...")
script_tracker = {}  # Used to track if a key has Python scripts, PowerShell scripts, or both
for module_path in python_file_list:

    print("Processing " + module_path)
    with open(module_path, encoding='utf-8') as fd:
        module_contents = fd.read()
    module = ast.parse(module_contents)
    docstring = ast.get_docstring(module)
    if docstring is None:
        docstring = ""

    # Key is the name without py- ex: get_group_details
    key = basename(module_path).replace('.py', '')

    if key in categories_dictionary['deploy']:
        category = 'deploy'
    elif key in categories_dictionary['update']:
        category = 'update'
    elif key in categories_dictionary['monitor']:
        category = 'monitor'
    elif key in categories_dictionary['maintain']:
        category = 'maintain'
    elif key in categories_dictionary['supportassistenterprise']:
        category = 'supportassistenterprise'
    elif key in categories_dictionary['powermanager']:
        category = 'powermanager'
    else:
        category = 'other'
        logging.error(key + " is not in categories! It will not be displayed in the documentation. "
                            "You should add it to categories before continuing.")
        sys.exit(0)

    # Call PowerShell's help and then extract examples from the help page
    script_tracker[key] = {}
    powershell_example = None
    script_tracker[key]['has_powershell'] = False
    script_tracker[key]['has_python'] = False
    for script in categories_dictionary[category][key]:
        if script.endswith('.ps1'):
            if script_tracker[key]['has_powershell']:
                logging.error("It looks like a PowerShell script for " + key + " may have been listed twice. Fix and"
                              " then rerun this script.")
                sys.exit(0)
            logging.info("Retrieving PowerShell example for " + script)
            powershell_example = _get_powershell_example(script)
            script_tracker[key]['has_powershell'] = True
        elif script.endswith('py'):
            if script_tracker[key]['has_python']:
                logging.error("It looks like a Python script for " + key + " may have been listed twice. Fix and"
                              " then rerun this script.")
                sys.exit(0)
            script_tracker[key]['has_python'] = True
        else:
            logging.error(key + " has a script listed that does not end with either"
                          " ps1 or .py. This is probably an error. Fix and then rerun this script.")
            sys.exit(0)

    if not powershell_example:
        logging.warning("No PowerShell script found for " + key)

    module_data[category][key] = {
        'path': abspath(module_path),
        'docstring': docstring,
        'readable_name': key.replace('_', ' ').title(),
        'available_scripts': categories_dictionary[category][key],
        'anchor_link': '#' + key.replace('_', '-').lower(),
        'powershell_example': powershell_example
    }

# Handle cases where a PowerShell script exists, but a Python script does not
# TODO - This doesn't check to see if there are PowerShell files on the file system that aren't in categories
for category, scripts in categories_dictionary.items():
    if category == 'deploy' or category == 'update' or category == 'monitor' or category == 'maintain':
        for key in scripts:
            if key not in script_tracker:
                logging.warning("No Python script found for " + key)
                for script in categories_dictionary[category][key]:
                    script_tracker[key] = {}
                    script_tracker[key]['has_powershell'] = False
                    script_tracker[key]['has_python'] = False
                    if script.endswith('.ps1'):
                        if script_tracker[key]['has_powershell']:
                            logging.error("It looks like a PowerShell script for " + key + " may have been listed "
                                          "twice. Fix and then rerun this script.")
                            sys.exit(0)

                        # Get synopsis from PowerShell
                        logging.info("Retrieving synopsis for " + script)
                        p = subprocess.Popen(["powershell.exe",
                                              "Get-Help",
                                              abspath(join(categories_dictionary['powershell_path'], script))],
                                             stdout=subprocess.PIPE)
                        powershell = p.stdout.read().decode('utf-8')
                        powershell_no_blanklines = ""
                        for line in filter(lambda x: not re.match(r'^\s*$', x), powershell.splitlines()):
                            powershell_no_blanklines = powershell_no_blanklines + line + '\n'
                        results = re.search('SYNOPSIS(.*)SYNTAX', powershell_no_blanklines, re.DOTALL)
                        docstring = "#### Synopsis" + results.group(1)

                        # Get description from PowerShell
                        results = re.search('DESCRIPTION(.*)RELATED LINKS', powershell_no_blanklines, re.DOTALL)
                        docstring = docstring + "#### Description" + results.group(1)

                        # Get rid of the leading whitespaces on each line which would convert the line to code
                        # in markdown
                        docstring = re.sub(r"\n(\s){2,}", "\n", docstring)

                        module_data[category][key] = {
                            'path': abspath(join(categories_dictionary['powershell_path'], script)),
                            'docstring': docstring,
                            'readable_name': key.replace('_', ' ').title(),
                            'available_scripts': categories_dictionary[category][key],
                            'anchor_link': '#' + key.replace('_', '-').lower(),
                            'powershell_example': _get_powershell_example(script)
                        }
                        script_tracker[key]['has_powershell'] = True
                    elif script.endswith('py'):
                        logging.error("We shouldn't be here. Is there something strange about this script? This might"
                                      " mean the script in question is in categories but no longer exists.")
                        sys.exit(0)
                    else:
                        logging.error(key + " has a script listed that does not end with either"
                                            " ps1 or .py. This is probably an error. Fix and then rerun this script.")
                        sys.exit(0)

# Alphabetize all dictionaries by key
for category, scripts in module_data.items():
    if category == 'deploy' or category == 'update' or category == 'monitor' or category == 'maintain':
        module_data[category] = OrderedDict(sorted(module_data[category].items()))

logging.info("Creating API doc from jinja2 template...")
templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader)
TEMPLATE_FILE = "API.md.j2"
template = templateEnv.get_template(TEMPLATE_FILE)
outputText = template.render(module_data=module_data)  # this is where to put args to the template renderer

with open("API.md", "w", encoding='utf-8') as f:
    f.write(outputText)
    current_directory = getcwd()
    copyfile("API.md", join(current_directory, '../PowerShell/README.md'))
    copyfile("API.md", join(current_directory, '../Python/README.md'))

logging.info("API.md generated!")
