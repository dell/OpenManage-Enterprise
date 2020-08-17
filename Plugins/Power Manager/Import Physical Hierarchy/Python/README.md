## Importing Physical Group and Device Association from a CSV file

Considering the fact that recreation of physical group hierarchies are a painful and time taking activities for the users, 
OpenManage Power Manager facilitates importing the existing hierarchy of a data center from a csv file.

## Prerequisites
OpenManage Enterprise v3.4 or later

Power Manager plugin v1.2 or later

## Steps
1.	It is expected that this script run on Python version 3.x.

2.	Download the following files to your local system

-	createphysicalgroups.py
-	physicalgroups.csv
-	configfile.properties

3.	Prefilled with the desired inputs in physicalgroups.csv file. The inputs can be incremental. A sample is depicted as below:

DC1,Room1,Aisle1,Rack1,100,42,1,GMJ3GL2
DC1,Room1,Aisle1,Rack1,100,42,3,BN1JR42
DC1,,Aisle1,Rack1,100,21,4,D4QBBS2
DC1,,,Rack1,100,21,10,6SM09X2
,Room1,Aisle1,Rack1,100,48,1,BCF5GY1
,Room1,,Rack1,100,48,5,H2CHH32
,,Aisle1,Rack1,100,48,4,DR6R7C2
,,,Rack1,100,24,4,G72SQ12
,,Aisle4,Rack4,100,24,4,CQ2RG52

4.	The console specific parameters need to be configured in configfile.properties. A sample is depicted as below:

[consoleaccessdetails]
ipaddress = 10.10.10.10
username = admin
password = admin


Usage

Run the file createphysicalgroups.py on the system where it is downloaded as mentioned in pre-requisites. This script can be 
run on Windows and Linux operating systems. The command line interface is:
% python createphysicalgroups.py
The script gets executed in a silent mode and generates following files
-	physicalgroup_automation.log: This includes the script logs
-	Date-timestamp-based report file having name report_<DateTimestamp>.txt: This includes the final outcome of the execution 
that reveals which all physical groups are created, failed and result on device to rack group association.


## Use Cases

1. Physical group creation
2. Device to Rack association

## Authors

Rishi Mukherjee

## License

Copyright Dell EMC


## Acknowledgments

