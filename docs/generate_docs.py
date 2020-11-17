import ast
from os.path import abspath, basename
from os import scandir
import jinja2
import yaml

with open('categories.yml') as category_file:
    categories_dictionary = yaml.load(category_file, Loader=yaml.FullLoader)

python_directory = categories_dictionary['python_code_path']
python_file_list = []
module_data = {'deploy': {}, 'update': {}, 'monitor': {}, 'maintain': {}, 'other': {}}

for entry in scandir(python_directory):
    if entry.path.endswith(".py"):
        python_file_list.append(entry.path)

for module_path in python_file_list:
    module_contents = ""
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

    if category in categories_dictionary:
        module_data[category][key] = {
            'path': abspath(module_path),
            'docstring': docstring,
            'readable_name': key.replace('_', ' ').title(),
            'available_scripts': categories_dictionary[category][key],
            'anchor_link': '#' + key.replace('_', '-').lower()
        }

templateLoader = jinja2.FileSystemLoader(searchpath="./")
templateEnv = jinja2.Environment(loader=templateLoader)
TEMPLATE_FILE = "API.md.j2"
template = templateEnv.get_template(TEMPLATE_FILE)
outputText = template.render(module_data=module_data)  # this is where to put args to the template renderer

print(outputText)

with open("API.md", "w") as f:
    f.write(outputText)
