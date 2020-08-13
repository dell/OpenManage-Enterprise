"""
SYNOPSIS:
   Script to perform power control on device managed by OM Enterprise
DESCRIPTION:
   This script exercises the OME REST API to perform power control operations.
   For authentication X-Auth is used over Basic Authentication.
   Note that the credentials entered are not stored to disk.

EXAMPLE:
   python set_power_state.py --ip <ip addr> --user admin
    --password <passwd> --deviceId 25527  --state {state}
    where {state} can be "On", "Off", "Cold Boot","Warm Boot", "ShutDown"
"""
import sys
import time
import argparse
from argparse import RawTextHelpFormatter
import json
import urllib3
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


LIST_OF_POWER_OPERATIONS = ("On", "Off", "Cold Boot", "Warm Boot")
POWER_STATE_MAP = {"On": "17", "Off": "18",
                   "PoweringOn": "20", "PoweringOff": "21"}

POWER_CONTROL_STATE_MAP = {
    "On": "2",
    "Off": "12",
    "Cold Boot": "5",
    "Warm Boot": "10",
    "ShutDown": "8"
}


def authenticate_with_ome(ip_address, user_name, password):
	""" X-auth session creation """
	auth_success = False
	session_url = "https://%s/api/SessionService/Sessions" % (ip_address)
	user_details = {'UserName': user_name,
                 'Password': password,
                 'SessionType': 'API'}
	headers = {'content-type': 'application/json'}
	session_info = requests.post(session_url, verify=False,
                              data=json.dumps(user_details),
                              headers=headers)
	if session_info.status_code == 201:
		headers['X-Auth-Token'] = session_info.headers['X-Auth-Token']
		auth_success = True
	else:
		error_msg = "Failed create of session with {0} - Status code = {1}"
		print(error_msg.format(ip_address, session_info.status_code))
	return (auth_success, headers)


def get_power_control_payload(device_id, state):
	job_name = {
		"On": "Power On",
		"Off": "Power Off",
		"Cold Boot": "Power Cycle",
		"Warm Boot": "System Reset (Warm Boot)",
		"ShutDown": "Graceful Shutdown"
	}
	power_control = {
		"power_control_details": {
                    "Id": 0,
                				"JobName": "System Reseat",
                				"JobDescription": "DeviceAction_Task",
                				"Schedule": "startnow",
                				"State": "Enabled",
                				"JobType": {
                                                    "Id": 3,
                                                    "Name": "DeviceAction_Task"
                                                },
                    "Params": [
                                                    {
                                                        "Key": "operationName",
                                                        "Value": "VIRTUAL_RESEAT"
                                                    },
                                                    {
                                                        "Key": "connectionProfile",
                                                        "Value": "0"
                                                    }
                                                ],
                    "Targets": [
                                                    {
                                                        "Id": 26593,
                                                        "Data": "",
                                                        "TargetType":
                                                        {
                                                            "Id": 1000,
                                                            "Name": "DEVICE"
                                                        }
                                                    }
                                                ]
                }
	}
	power_details = power_control["power_control_details"]
	power_details["JobName"] = job_name[state]
	power_details["JobDescription"] = "Power Control Task:"+job_name[state]
	power_details["Params"][0]["Value"] = "POWER_CONTROL"
	power_details["Params"][1]["Key"] = "powerState"
	power_details["Params"][1]["Value"] = POWER_CONTROL_STATE_MAP[state]
	power_details["Targets"][0]["Id"] = device_id
	return power_details


def track_job_to_completion(ip_address, headers, job_id, state):
	""" Tracks the  job to completion / error """
	job_status_map = {
		"2020": "Scheduled",
		"2030": "Queued",
		"2040": "Starting",
		"2050": "Running",
		"2060": "Completed",
		"2070": "Failed",
		"2090": "Warning",
		"2080": "New",
		"2100": "Aborted",
		"2101": "Paused",
		"2102": "Stopped",
		"2103": "Canceled"
	}
	status_mapping = {
		"On": "Powered On",
		"Off": "Powered Off",
		"Cold Boot": "Power Cycle",
		"Warm Boot": "Reset",
		"ShutDown": "Shutdown"
	}

	max_retries = 20
	sleep_interval = 30
	failed_job_status = [2070, 2090, 2100, 2101, 2102, 2103]
	job_url = 'https://%s/api/JobService/Jobs(%s)' % (ip_address, job_id)
	loop_ctr = 0
	job_incomplete = True
	print("Polling %s to completion ..." % job_id)
	while loop_ctr < max_retries:
		loop_ctr += 1
		time.sleep(sleep_interval)
		job_resp = requests.get(job_url, headers=headers, verify=False)
		if job_resp.status_code == 200:
			job_status = str((job_resp.json())['LastRunStatus']['Id'])
			job_status_str = job_status_map[job_status]
			print("Iteration %s: Status of %s is %s" %
			      (loop_ctr, job_id, job_status_str))
			if int(job_status) == 2060:
				job_incomplete = False
				print("%s operation successful" %status_mapping[state])
				break
			elif int(job_status) in failed_job_status:
				job_incomplete = False
				if job_status_str == "Warning":
					print("Completed with errors")
				else:
					print("%s operation failed" %status_mapping[state])
				job_hist_url = str(job_url) + "/ExecutionHistories"
				job_hist_resp = requests.get(job_hist_url, headers=headers, verify=False)
				if job_hist_resp.status_code == 200:
					get_execution_detail(job_hist_resp, headers, job_hist_url)
				break
		else:
			print("Unable to poll status of %s - Iteration %s " % (job_id, loop_ctr))
	if job_incomplete:
		print("Job %s incomplete after polling %s times...Check status" %
		      (job_id, max_retries))


def get_execution_detail(job_hist_resp, headers, job_hist_url):
	""" Get execution details """
	job_history_id = str((job_hist_resp.json())['value'][0]['Id'])
	execution_hist_detail = "(" + job_history_id + ")/ExecutionHistoryDetails"
	job_hist_det_url = str(job_hist_url) + execution_hist_detail
	job_hist_det_resp = requests.get(job_hist_det_url,
                                  headers=headers,
                                  verify=False)
	if job_hist_det_resp.status_code == 200:
		print(job_hist_det_resp.text)
	else:
		print("Unable to parse job execution history .. Exiting")


def get_device_list(ip_address, headers):
	""" Get list of devices from OME """
	ome_device_list = []
	next_link_url = 'https://%s/api/DeviceService/Devices' % ip_address
	while next_link_url is not None:
		device_response = requests.get(next_link_url, headers=headers, verify=False)
		next_link_url = None
		if device_response.status_code == 200:
			dev_json_response = device_response.json()
			if dev_json_response['@odata.count'] <= 0:
				print("No devices found at ", ip_address)
				return

			if '@odata.nextLink' in dev_json_response:
				next_link_url = 'https://%s/' %ip_address + dev_json_response['@odata.nextLink']

			if dev_json_response['@odata.count'] > 0:
				ome_device_list = ome_device_list + [x['Id'] for x in dev_json_response['value']]
		else:
			print("No devices found at ", ip_address)

	return ome_device_list

def get_power_states(ip_address, device_id, headers):
	power_state = None
	url = "https://%s/api/DeviceService/Devices(%s)" % (ip_address, device_id)
	device_response = requests.get(url, headers=headers, verify=False)
	if device_response.status_code == 200:
		dev_json_response = device_response.json()
		power_state = dev_json_response["PowerState"]
	else:
		raise ValueError("Unable to fetch power state for device id %s ... Exiting")
	return power_state


if __name__ == '__main__':
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	PARSER = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=RawTextHelpFormatter)
	PARSER.add_argument("--ip", required=True, help="OME Appliance IP")
	PARSER.add_argument("--user", required=True,
                     help="Username for OME Appliance",
                     default="admin")
	PARSER.add_argument("--password", required=True,
                     help="Password for OME Appliance")
	PARSER.add_argument("--deviceId", type=int, required=True,
                     help="Device ID to perform device action on that device")
	PARSER.add_argument("--state", required=True,
                     choices=("On", "Off", "Cold Boot",
                              "Warm Boot", "ShutDown"),
                     help="State to apply power control operation")
	ARGS = PARSER.parse_args()
	IP_ADDRESS = ARGS.ip
	USER_NAME = ARGS.user
	PASSWORD = ARGS.password
	DEVICE_ID = ARGS.deviceId
	STATE = ARGS.state

	try:
		AUTH_SUCCESS, HEADERS = authenticate_with_ome(
			IP_ADDRESS, USER_NAME, PASSWORD)
		if AUTH_SUCCESS:
			DEVICE_LIST = get_device_list(IP_ADDRESS, HEADERS)
			if DEVICE_LIST:
				if int(DEVICE_ID) not in DEVICE_LIST:
					raise ValueError(
						"Device with id %s not found on %s ... Exiting" % (DEVICE_ID, IP_ADDRESS))
			else:
				raise ValueError("Device not found on %s ... Exiting" % IP_ADDRESS)

			POWER_STATE = get_power_states(IP_ADDRESS, DEVICE_ID, HEADERS)
			if POWER_CONTROL_STATE_MAP[STATE] == POWER_STATE:
				print("Device is already in the desired state")
			elif ((STATE == "On") and (POWER_STATE == POWER_STATE_MAP["PoweringOn"])):
				print("Device is already in the desired state")
			elif ((STATE == "Off") and (POWER_STATE == POWER_STATE_MAP["PoweringOff"])):
				print("Device is already in the desired state")
			else:
				POWER_CONTROL_PAYLOAD = get_power_control_payload(DEVICE_ID, STATE)
				JOBS_URL = 'https://%s/api/JobService/Jobs' % IP_ADDRESS
				JOB_RESPONSE = requests.post(JOBS_URL, verify=False,
                                 data=json.dumps(POWER_CONTROL_PAYLOAD),
                                    headers=HEADERS)
				if JOB_RESPONSE.status_code == 201:
					JOB_JSON_RESPONSE = JOB_RESPONSE.json()
					JOB_ID = JOB_JSON_RESPONSE["Id"]
					track_job_to_completion(IP_ADDRESS, HEADERS, JOB_ID, STATE)
				else:
					print("Unable to create job")

		else:
			print("Unable to create a session with appliance %s" % (IP_ADDRESS))
	except OSError:
		print("Unexpected error:", sys.exc_info())
