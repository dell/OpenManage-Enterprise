# Building Documentation

1. Run `pip install pyyaml jinja2` to install the necessary dependencies.
2. Update `categories.yml` with any new scripts. It uses yaml format. For example if you want to add a new script to the maintenance section of the documenatiton it would follow this format:

        maintain:
          name_of_python_file_without_extension:
            - name_of_python_file.py
            - powershell_equivalent.ps1
            
3. Run `generate_docs.py`. It doesn't require any arguments but it does expect `categories.yml` to be in the same folder. The way it will work is it will scan all the files in `Core/Python` for docstrings and save them to a dictionary. It will then use the metadata from `categories.yml` to correctly annotate any PowerShell scripts available plus what category the script should be placed in.
4. Updated documentation should now be in API.md.

If you would like to update the template `API.md.j2` it is written in Jinja2.