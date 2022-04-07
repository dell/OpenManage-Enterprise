## Translations

- [簡體中文 (Simplified Chinese)](docs/translations/README_zh.md)
- [繁體中文 (Traditional Chinese)](docs/translations/README_zh_TW.md)

## Maintenance Mode

This repo is in a maintenance mode. It is still being watched and all code here is still functional but you may not see commits for long periods of time. We will still accept feature requests and bug reports via the issues. 

## OME/OME-M and Plugin API Samples / Cookbooks

This repository hosts complete examples of how to use the OME/OME-M API. We designed these scripts to standalone but they are also meant to be used in the scripts of others.

Scripts are subdivided into Python and PowerShell. We do our best to maintain functional equivalance between the two, but sometimes they differ. These differences are typically noted in [the docs](docs/API.md).

## Complete List of All Scripts

See [the docs](docs/API.md). Scripts are listed by their functional type in the case of OME or by plugin if they belong to a plugin.

## PowerShell Scripts Require PS7

In an effort to future proof the repository and make our code portable across multiple platforms, all new scripts added to the repo are written for PowerShell (Core) 7. Microsoft makes PowerShell 7 available [on their GitHub page](https://github.com/PowerShell/PowerShell/releases).

Some older scripts may not carry this requirement. You can tell if a script requires PowerShell 7 by looking at the top of the script. If the top line is `#Requires -Version 7` this means it requires PowerShell 7.

### PS5.1 Support

Currently we do not have any plans to backport new scripts or provide cross compatibility. If there is enough community interest we will raise the priority. If PS5.1 is a hard requirement for you please leave a comment on [this ticket](https://github.com/dell/OpenManage-Enterprise/issues/181).

## We Love Feedback

We build, revise, or add features to scripts mostly based on user feedback. If there is something you want to see and it's applicable to a wide audience please open an issue on [our issues page](https://github.com/dell/OpenManage-Enterprise/issues) or feel free to leave a comment on an existing issue. This helps tremendously in determining what kind of functionality the community is looking for.
## Script Documentation

For a listing of each script and its accompanying documentation see our [Example API Documentation](docs/API.md)

## Writing Your Own Code

All scripts are self contained. We deliberately do not use an internal library. To write your own code simply copy one of our scripts and modify it as you please. We have cookie cutter code for common tasks available in the links below:

[Python Common Code](docs/python_library_code.md)
<br>
[PowerShell Common Code](docs/powershell_library_code.md)

## Contributing to this Repository

For more information on contributing to the repository see [the contribution guide](docs/CONTRIBUTING.md).

## devel Branch

The devel branch contains untested scripts or scripts which do not currently meet the contributor guidelines. If you
do not find what you are looking for in the master branch and are willing to be a tester, you may find what you are
looking for there!

If you have scripts you made that you think could be helpful but don't have time to work them over to meet the 
contributor guidelines, feel free to pull request them to the devel branch!

## Problems

If you run into problems with a script you can post [on our issues](https://github.com/dell/OpenManage-Enterprise/issues). If possible, provide the exact command you ran to generate the problem, any OME configurations required to recreate it, or if it's a code problem you already found - a good description of where the problem is.

## Authors

* **Raajeev Kalyanaraman**
* **Vittal Reddy**
* **Laxmi Joshi** 
* **Trevor Squillario**
* **Prasad Rao**
* **Grant Curell**

### Power Manager Plugin Authors

* **Mahendran Panneerselvam**
* **Ashish Singh**
* **Rishi Mukherjee**

## Current Maintainer

Grant Curell

If you have any questions that don't fall into the requests or problems category feel free to reach out to grant_curell(at)dell(dot)com.

## License

Copyright (c) 2021 Dell EMC Corporation
