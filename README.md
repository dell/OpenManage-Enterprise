## Translations

- [簡體中文 (Simplified Chinese)](docs/translations/README_zh.md)
- [繁體中文 (Traditional Chinese)](docs/translations/README_zh_TW.md)

## OME/OME-M and Plugin API Samples / Cookbooks

This repository hosts cookbooks for OME/OME-M and associated plugins. Script examples specific to OME/OME-M are in the Core directory. Plugin script examples are in the "Plugin" folder and categorized further by plugin name.

The Core directory is further subdivided into Python and PowerShell. We do our best to maintain functional equivalance between the two, but sometimes they differ. These differences are typically noted in [the docs](docs/API.md).

## PowerShell Scripts Require PS7

In an effort to future proof the repository and make our code portable across multiple platforms, all new scripts added to the repo are written for PowerShell (Core) 7. Microsoft makes PowerShell 7 available [on their GitHub page](https://github.com/PowerShell/PowerShell/releases).

Some older scripts may not carry this requirement. You can tell if a script requires PowerShell 7 by looking at the top of the script. If the top line is `#Requires -Version 7` this means it requires PowerShell 7.

### PS5.1 Support

Currently we do not have any plans to backport new scripts or provide cross compatibility. If there is enough community interest we will raise the priority. If PS5.1 is a hard requirement for you please leave a comment on [this ticket](https://github.com/dell/OpenManage-Enterprise/issues/181).
## Script Documentation

For a listing of each script and its accompanying documentation see our [Example API Documentation](docs/API.md)

## Contributing to this Repository

For more information on contributing to the repository see [the contribution guide](docs/CONTRIBUTING.md).

## devel Branch

The devel branch contains untested scripts or scripts which do not currently meet the contributor guidelines. If you
do not find what you are looking for in the master branch and are willing to be a tester, you may find what you are
looking for there!

If you have scripts you made that you think could be helpful but don't have time to work them over to meet the 
contributor guidelines, feel free to pull request them to the devel branch!

## Requests

If there is a script you would like feel free to put a request [on our issues](https://github.com/dell/OpenManage-Enterprise/issues). This repository is maintained in our free time, but we're happy to take a look at things the community needs. The more descriptive you can be about exactly what you want the better. Screenshots of exactly the functionality you are looking for are fantastic!

## Problems

If you run into problems with a script you can post [on our issues](https://github.com/dell/OpenManage-Enterprise/issues). If possible, provide the exact command you ran to generate the problem, any OME configurations required to recreate it, or if it's a code problem you already found - a good description of where the problem is.

## Authors

* **Raajeev Kalyanaraman** - *Initial work*
* **Vittal Reddy**
* **Laxmi Joshi** 
* **Trevor Squillario**
* **Prasad Rao**
* **Grant Curell**

## Current Maintainer

Grant Curell

If you have any questions that don't fall into the requests or problems category feel free to reach out to grant_curell(at)dell(dot)com.

## License

Copyright (c) 2021 Dell EMC Corporation
