#
# Python script for generating new documentation
#
# _author_ = Grant Curell <grant_curell@dell.com>
#
#
# Copyright (c) 2020 Dell EMC Corporation
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
from os import scandir
from os.path import abspath, basename, join

import jinja2
import yaml

logging.info("Reading in YML...")
with open('categories.yml') as category_file:
    categories_dictionary = yaml.load(category_file, Loader=yaml.FullLoader)

python_file_list = []
module_data = {'deploy': {}, 'update': {}, 'monitor': {}, 'maintain': {}, 'other': {}}

for entry in scandir(categories_dictionary['python_code_path']):
    if entry.path.endswith(".py"):
        python_file_list.append(entry.path)

logging.info("Scanning Python files for docstrings and extracting them...")
for module_path in python_file_list:

    with open(module_path) as fd:
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
    else:
        category = 'other'
        logging.error(key + " is not in categories! It will not be displayed in the documentation. "
                            "You should add it to categories before continuing.")
        sys.exit(0)

    # Call PowerShell's help and then extract examples from the help page
    powershell_example = None
    for script in categories_dictionary[category][key]:
        if script.endswith('.ps1'):
            logging.info("Retrieving PowerShell example for " + script)
            p = subprocess.Popen(["powershell.exe",
                                  "Get-Help",
                                  abspath(join(categories_dictionary['powershell_path'], script)),
                                  "-Examples"],
                                 stdout=subprocess.PIPE)
            powershell = p.stdout.read().decode('utf-8').split("-------------------------- EXAMPLE 1 "
                                                               "--------------------------")[1].strip()
            powershell = powershell.splitlines()

            # Remove blank lines - PowerShell otherwise prints with several unnecessary blank lines
            powershell_example = ""
            for line in filter(lambda x: not re.match(r'^\s*$', x), powershell):
                powershell_example = powershell_example + line + '\n'
            powershell_example = re.sub(r"-------------------------- EXAMPLE \d --------------------------", "\n",
                                        powershell_example)
            break

    if not powershell_example:
        logging.warning("No PowerShell script found for " + key)

    if category in categories_dictionary:
        module_data[category][key] = {
            'path': abspath(module_path),
            'docstring': docstring,
            'readable_name': key.replace('_', ' ').title(),
            'available_scripts': categories_dictionary[category][key],
            'anchor_link': '#' + key.replace('_', '-').lower(),
            'powershell_example': powershell_example
        }

logging.info("Creating API doc from jinja2 template...")
templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader)
TEMPLATE_FILE = "API.md.j2"
template = templateEnv.get_template(TEMPLATE_FILE)
outputText = template.render(module_data=module_data)  # this is where to put args to the template renderer

with open("API.md", "w") as f:
    f.write(outputText)

logging.info("API.md generated!")
