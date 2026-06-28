import logging
import requests
import json
import datetime
import os
import os.path
import random
import shutil
import time, pwinput
# from ratelimiter import RateLimiter
# rate_limit = RateLimiter(max_calls=100, period=1)
from ratelimit import limits, sleep_and_retry
from tqdm import tqdm
import aiohttp, asyncio, ssl
import urllib3

session_data = {}

# Optional callback invoked with each API endpoint URL as it is called. Used by
# the combined orchestrator / web app to surface used endpoints to the user.
endpoint_hook = None


def _notify_endpoint(url):
    cb = endpoint_hook
    if cb is not None:
        try:
            cb(url)
        except Exception:
            pass


DEFAULT_TIMEOUT = 60

# Session with connection pooling
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
session.mount("https://", adapter)


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(filename='script_log.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Base directory of this script. Used to locate stage1_endpoints.txt and to
# store the generated working directory / zip file. Resolving relative to
# __file__ keeps behaviour identical regardless of the process working dir.
cwd = os.path.dirname(os.path.abspath(__file__))

dt = datetime.datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")
str_dt = str(dt)

# These are initialised per-collection inside run(). They remain module level
# globals because the collection helpers below reference them directly.
zip_file_name = None
r_path = None

def get_jsession(response):
    logging.info("********Inside get_jsession function*******")
    jsession_id = ''
    try:
        if response:
            if response.status_code == 200:
                cookies = response.headers["set-cookie"] if "set-cookie" in response.headers else response.headers["Set-Cookie"]
                if cookies:
                    jsessionid = cookies.split(";")
                    return jsessionid[0]
                else:
                    return jsession_id
        else:
            return jsession_id

    except Exception as e:
        logging.exception("No valid JSESSION ID returned\n" + str(e))
        return jsession_id

def generate_jsession(base_url, username, password):
    try:
        logging.info("*******Inside the get_jsession id function*********")
        url = base_url + "/j_security_check"
        payload = {'j_username' : username, 'j_password' : password}
        url_without_port = ':'.join(base_url.split(':')[:-1]) + "/j_security_check"
        response = {}
        try:
            logging.info("****Get jsession_id without port :: *******{}*************".format(url_without_port))
            response = requests.post(url=url_without_port, data=payload, verify=False)
            logging.info('status_code without port form get jsession_id' + str(response.status_code))
        except Exception as e:
            logging.exception("Exception while getting jsession id without port \n" + str(e))
        jsession_id = get_jsession(response)
        if jsession_id == '':
            logging.info("****Get jsession_id with port :: *******{}*************".format(url))
            try:
                response = requests.post(url=url, data=payload, verify=False)
                logging.info('status_code with port form get jsession_id' + str(response.status_code))
            except Exception as e:
                logging.exception("Exception while getting jsession id with port \n" + str(e))
            jsessionid = get_jsession(response)
            return jsessionid, 'port'
        else:
            return jsession_id, ''

    except Exception as e:
        logging.exception('Exception inside generate_jsession' + str(e))
        return None, 400

def get_token(base_url, username,password):
    try:
        logging.info("*******Inside the token function*********")
        jsessionid, cond = generate_jsession(base_url,username,password)
        if jsessionid:
            headers = {'Cookie': jsessionid}
            url = base_url + "/dataservice/client/token"
            url_without_port = ':'.join(base_url.split(':')[:-1]) + "/dataservice/client/token"
            if cond != 'port':
                logging.info("****Get token without port :: *******{}*************".format(url_without_port))
                response = requests.get(url=url_without_port, headers=headers, verify=False)
                logging.info('status_code without port form get token' + str(response.status_code))
            else:
                logging.info("****Get token with port :: *******{}*************".format(url))
                response = requests.get(url=url, headers=headers, verify=False)
                logging.info('status_code with port form get token' + str(response.status_code))
            if response.status_code == 200:
                return response.text, jsessionid, cond
    except Exception as e:
        logging.exception('Exception inside get_token' + str(e))
    return None, 400, ''

def refresh_credentials(session_data, check=True):
    if session_data['sso_enabled'] == 'Y':
        if check:
            jsessionid = input("Enter your JSESSIONID :- ")
            if not jsessionid.startswith("JSESSIONID="):
                jsessionid = "JSESSIONID=" + jsessionid
            token = input("Enter your X-XSRF-TOKEN :- ")
        else:
            return session_data['header']
    else:
        token, jsessionid, cond = get_token(session_data['base_url'], session_data['admin_username'], session_data['admin_password'])
        
    return {'Content-Type': "application/json", 'Cookie': jsessionid, 'X-XSRF-TOKEN': token}

RATE_LIMIT = 100  # requests
PERIOD = 1  # per second

# Global cap on the number of SD-WAN Manager API calls in flight at any moment.
# This bounds total concurrency across every parallel section so the collection
# is faster without overwhelming the manager.
import threading
API_MAX_CONCURRENCY = 10
_api_semaphore = threading.Semaphore(API_MAX_CONCURRENCY)

@sleep_and_retry
@limits(calls=RATE_LIMIT, period=PERIOD)
def api_checks_execution(url,timeout=DEFAULT_TIMEOUT,retries=3):
    delay = 1
    max_delay = 60  # cap to prevent runaway sleep
    for attempt in range(retries):
        api_response = None
        # Implement the API call with a timeout
        try:
            _notify_endpoint(url)
            # timeout= 40 if "reboothistory" in url else 40
            timeout = DEFAULT_TIMEOUT
            heavy_apis = ["template/config/running", "device/config?deviceId"]
            if any(apis in url for apis in heavy_apis):
                timeout = timeout * 3
            logging.info(f"[Attempt {attempt}] Calling API: {url}")
            with _api_semaphore:
                api_response = session.get(url, verify=False, headers=session_data['header'], timeout=timeout + attempt*10)
            api_response.raise_for_status()
            if api_response.status_code == 200:
                logging.info(f"[Success] API called successfully: {url}")
                content_type = api_response.headers.get("Content-Type", "")
                try:
                    # Try to parse JSON only if content-type indicates JSON or response looks like JSON
                    if "application/json" in content_type or api_response.text.strip().startswith("{"):
                        return api_response.json()
                    else:
                        logging.info(f"[Info] Non-JSON response detected for {url}")
                        return {"raw_text": api_response.text}
                except ValueError as e:
                    logging.warning(f"ValueError for {url}: {e}")
                    if attempt==0 and '<html>' in api_response.text:
                        logging.info("[Action] Refreshing credentials...")
                        session_data['header'] = refresh_credentials(session_data)  
                        continue
        except requests.exceptions.HTTPError as e:
            if api_response is not None and api_response.status_code == 429:
                logging.warning(f"[Attempt {attempt}] 429 Too Many Requests for {url}. Retrying after {delay}s...")
                time.sleep(delay + random.uniform(0, 1))  # add jitter
                delay = min(delay * 2, max_delay)
                continue
            elif api_response is not None and 500 <= api_response.status_code < 600:
                logging.warning(f"[Attempt {attempt}] Server error ({api_response.status_code}) for {url}. Retrying after {delay}s...")
                time.sleep(delay + random.uniform(0, 1))
                delay = min(delay * 2, max_delay)
                continue
            elif attempt==0 and api_response is not None and api_response.status_code in (401, 403):
                logging.info("Refreshing credentials...")
                session_data['header'] = refresh_credentials(session_data)
                continue
            else:
                logging.error(f"[Attempt {attempt}] Non-retryable HTTP error for {url}: {e}")
                return None, 400
        except Exception as e:
            logging.exception(f"[Attempt {attempt}] Exception for {url}: {e}. Retrying after {delay}s...")
            if attempt == retries - 1:
                logging.error(f"[Failed] API failed after {retries} attempts: {url}")
                return None, 400
            time.sleep(delay + random.uniform(0, 1))
            delay = min(delay * 2, max_delay)
    return None, 400

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE
@sleep_and_retry
@limits(calls=RATE_LIMIT, period=PERIOD)
async def vedgeapi_checks_execution(session, url, timeout=DEFAULT_TIMEOUT, retries=3):
    delay=1
    max_delay = 60  # cap
    start_time = time.time()
    for attempt in range(retries):
        # async with rate_limit:
        try:
            _notify_endpoint(url)
            # timeout= 40 if "reboothistory" in url else 40
            timeout = DEFAULT_TIMEOUT
            heavy_apis = ["template/config/running","device/config?deviceId"]

            if any(apis in url for apis in heavy_apis):
                timeout = DEFAULT_TIMEOUT * 3
            async with session.get(url, ssl=ssl_context, headers=session_data['header'], timeout=timeout + attempt*10) as response:
                if response.status == 429:
                    logging.warning(f"[Attempt {attempt}] 429 Too Many Requests for {url}. Retrying after {delay}s...")
                    await asyncio.sleep(delay + random.uniform(0, 1))
                    delay = min(delay * 2, max_delay)
                    continue
                elif attempt==0 and response.status in (401, 403):
                    logging.info("Refreshing credentials")
                    session_data['header'] = refresh_credentials(session_data)
                    continue
                response.raise_for_status()
                if response.status == 200:
                    logging.info(f"[Success] API called successfully: {url}")
                    return await response.json()
        except Exception as e:
            logging.exception(f"[Attempt {attempt}] Exception for {url}: {e}. Retrying after {delay}s...")
            if attempt == retries - 1:
                logging.error(f'FAILED after {retries} attempts: {url}')
                return None
            await asyncio.sleep(delay + random.uniform(0, 1))
            delay = min(delay * 2, max_delay)
        elapsed = round(time.time() - start_time, 2)
        logging.info(f"Time elapsed for {url}: {elapsed}s")

def add_data_to_extract(zip_file_name,file_name,j_data, buffer_size=8192):
    try:
        put_files_fol = os.path.join(r_path, 'extracted', file_name)
        # Start timing
        start_time = time.time()

        # Open the file with a specified buffer size and write the JSON data
        with open(put_files_fol, "w", buffering=buffer_size) as data_to_file:
            json.dump(j_data, data_to_file)

        # Calculate and log the time taken to write the file
        time_taken = time.time() - start_time
        logging.info(f"Data written to {file_name} in {time_taken:.3f} seconds.")
    except Exception as e:
        logging.exception("Exception in add_data_to_extract function" + str(e))

async def vedge_data_json(zip_file_name,base_url, end_point, file_name, type_list):
    async with aiohttp.ClientSession() as session:
        try:
            end_point1 = base_url + end_point[0]  # Calling Vedge main api
            response_main = await vedgeapi_checks_execution(session, end_point1)
            for dev in tqdm(response_main["data"], desc="Fetching vedge data"):
                if 'templateId' in dev:
                    if dev["template"] in type_list or type_list == []:
                        end_point2 = base_url + end_point[1].format(dev['templateId'])  # Calling template device object
                        # pbar.set_description(f"Fetching data from {end_point2}")
                        response2 = await vedgeapi_checks_execution(session, end_point2)
                        dev['template_device_object'] = response2
                        if 'generalTemplates' in response2:
                            for temp in response2['generalTemplates']:
                                end_point3 = base_url + end_point[2].format(temp['templateId'])  # Calling template feature device object
                                # pbar.set_description(f"Fetching data from {end_point3}")
                                temp['template_feature_object'] = await vedgeapi_checks_execution(session, end_point3)
                                if "subTemplates" in temp:
                                    for i in temp['subTemplates']:
                                        end_point4 = base_url + end_point[2].format(i['templateId'])  # Calling sub-template feature device object
                                        # print(end_point4)
                                        # pbar.set_description(f"Fetching data from {end_point4}")
                                        i['template_feature_object'] = await vedgeapi_checks_execution(session, end_point4)
                    # pbar.update(1)
            add_data_to_extract(zip_file_name, file_name, response_main)
        except Exception as e:
            logging.exception("Exception in vedge_data_json function" + str(e))


def details_check_key(base_url,response,key):
    result = {}
    try:
        if key == 'value':
            for index, dev in enumerate(response["data"]):
                if dev[key] > 0:
                    tmp_url = base_url + '/' + dev["detailsURL"][1:]
                    result = api_checks_execution(tmp_url)
                    # SLEEP ADDED AFTER EVERY 100 DEVICE CHECKS (value block)
                    if (index + 1) % 100 == 0:
                        logging.info("Sleeping for 30 seconds after 100 detail checks...")
                        time.sleep(20)

        else:
            for index, dev in enumerate(response["data"]):
                tmp_url = base_url + '/' + dev["detailsURL"][1:]
                result = api_checks_execution(tmp_url)
                # SLEEP ADDED AFTER EVERY 100 DEVICE CHECKS (value block)
                if (index + 1) % 100 == 0:
                    logging.info("Sleeping for 30 seconds after 100 detail checks...")
                    time.sleep(20)

    except Exception as e:
        logging.exception("Exception in details_check_key function" + str(e))
    return result

def details_url(zip_file_name,base_url, end_point):
    response_main= {}
    try:
        end_point1 = base_url + end_point[0]  # Calling tlocutil api
        response1 = api_checks_execution(end_point1)
        response_main["tlocutil_res"] = details_check_key(base_url, response1, 'value')

        end_point2 = base_url + end_point[1]  # Calling connectionssummary api
        response2 = api_checks_execution(end_point2)
        response_main["vSmart_res"] = details_check_key(base_url, response2, 'vSmart')
        response_main["WANEdge_res"] = details_check_key(base_url, response2, 'WAN Edge')
        response_main["vBond_res"] = details_check_key(base_url, response2, 'vBond')

        add_data_to_extract(zip_file_name, 'details_url.json', response_main)
    except Exception as e:
        logging.exception("Exception in details_url function" + str(e))


def dataservice_checks(zip_file_name,devices,base_url, end_point,file_name,type_list):
    result = []
    router_res=[]
    try:
        for index, (dev_id, dev_info) in enumerate(devices.items()):
            if dev_info["device-type"] in type_list or not type_list:
                logging.debug(f"Processing deviceId: {dev_id} for endpoint: {end_point}")
                if file_name in ['template_config_run.json', 'template_attachedconfig.json']:
                    uuid = devices[dev_id]["uuid"]
                    dev_ed = base_url + end_point + uuid
                elif file_name in ['interface_queue_stats.json']:
                    if devices[dev_id]['reachability'] in ['reachable']:                        
                        dev_ed = base_url + end_point.format(dev_id)
                        logging.info(dev_ed)
                    else:
                        continue
                else:
                    dev_ed = base_url + end_point.format(dev_id)
                logging.debug(f"Hitting URL: {dev_ed}")
                response = api_checks_execution(dev_ed)
                time.sleep(0.1)   # Prevent socket exhaustion
                # SLEEP ADDED AFTER EVERY 100 DEVICE CHECKS (value block)
                if (index + 1) % 100 == 0:
                    logging.info("Sleeping for 30 seconds after 100 device checks...")
                    time.sleep(20)
                if ("data" in response and response["data"] != []):
                    # result.append(response["data"])
                    if file_name == 'bfd_sum_device.json':
                        #condition for using bfd_sun_Device response to create wanConnectivity.json
                        re = bfd_sites(zip_file_name, base_url, end_point, response)
                        result.append(re)
                    if file_name in ["bfd_sum_device.json", "device_software.json"]:
                        # additional data required to be added in bfd_Sum_device.json from dataservice/device api
                        re = [i.update(
                            {"deviceId": devices[dev_id]["deviceId"], "host-name": devices[dev_id]["host-name"], "reachability": devices[dev_id]["reachability"]}) for i
                              in response["data"]]
                        result.append(response["data"])
                    elif "data" in response:
                        for i in response["data"]:
                            i["host-name"] = devices[dev_id]["host-name"]
                        result.append(response["data"])
                    else:
                        result.append(response)
                elif file_name in ["template_config_run.json"]:
                    result.append(response)
                    router_res.append({uuid:response})
                elif file_name in ['template_attachedconfig.json']:
                    result.append(response)
                elif file_name in ['hardware_health.json','NTP_server_configuration.json','Controller_Group.json','Enable_Implicit_ACL_Logging.json','Device_Banner.json','Enable_Tunnel_Interface_Validator.json']:
                    result.append(response)
        if file_name in ["template_config_run.json"]:
            add_data_to_extract(zip_file_name,"template_config_router_run.json",router_res)
        add_data_to_extract(zip_file_name, file_name, result)
    except Exception as e:
        logging.exception("Exception in dataservice_checks function" + str(e))
    finally:
        return result


def dataservice_ed_data(zip_file_name,base_url,end_point):
    devices = {}
    v3 = ['vsmart', 'vmanage', 'vbond']
    vmanage = ['vmanage']
    vedge = ['vedge']
    alarms = '/dataservice/alarms'
    event = '/dataservice/event'
    sum_device = '/device?deviceId={}'
    vedge_sum_device = '?deviceId={}'
    try:
        dataservice_file = os.path.join(r_path, 'extracted',
                                        '_dataservice_device.json')

        if os.path.exists(dataservice_file):
            logging.info("_dataservice_device.json file found")
            file_read = open(dataservice_file)
            file_data = json.load(file_read)
            file_read.close()
        else:
            file_ed = base_url + "/dataservice/device"
            file_data = api_checks_execution(file_ed)
            add_data_to_extract(zip_file_name, "_dataservice_device.json", file_data)
        for dev in file_data["data"]:
            devices[dev["deviceId"]] = dev

        all_service_checks_dict = {
            'reboothistory_v3': [end_point[0], "v3_reboothistory.json", v3],
            'reboothistory': [end_point[0], "reboothistory.json", []],
            # 'topology': [end_point[1], "topology.json", vmanage], #removed since it gives list of data for all deviceIds
            'interface_device': [end_point[2], "interface_device.json", vedge],
            'interface_queue_stats': [end_point[3], "interface_queue_stats.json", vedge],
            'interface_error_stats': [end_point[4], "interface_error_stats.json", vedge],
            'hardware_stats': [end_point[5], "hardware_stats.json", vedge],
            # 'alarms_severity': [alarms + end_point[5], "alarms_severity.json", vedge], # removed both apis since we are executing without deviceIDs having normal api query
            # 'event_severity': [event + end_point[5], "event_severity.json", vedge],
            'bfd_sum_device': [end_point[6] + sum_device, "bfd_sum_device.json", vedge],
            'vedge_bfd_sum_device': [end_point[6] + vedge_sum_device, "vedge_bfd_sum_device.json", vedge],
            'interface_operation': [end_point[7], "interface_operation.json", vedge],
            'tloc': [end_point[8], "tloc.json", vedge],
            'template_config_run' : [end_point[9],"template_config_run.json",[]],
            'template_attachedconfig': [end_point[10],"template_attachedconfig.json", vedge],
            'device_software': [end_point[11],"device_software.json", []],
            'nms_running': [end_point[12],"nms_running.json", vmanage],
            'connection_history': [end_point[13],"connection_history.json", []],
            'expiry_system_info': [end_point[14], "expiry_system_info.json", []],
            'approute_statistic': [end_point[15], "approute_statistic.json", vedge],
            'hardware_health': [end_point[17], "hardware_health.json",[]],
            'NTP_server_configuration': [end_point[17], "NTP_server_configuration.json",vmanage],
            'CPU_usage_Validator' : [end_point[1], "CPU_usage_Validator.json",['vbond']],
            'Controller_Group' : [end_point[17], "Controller_Group.json",['vsmart']],
            'Controller_CPU_Utilization' : [end_point[1], "Controller_CPU_Utilization.json",['vsmart']],
            'Crash_Reboot_Reason_Validator' : [end_point[0], "Crash_Reboot_Reason_Validator.json",['vbond']],
            'SDWAN_Manager_Clock' : [end_point[18], "SDWAN_Manager_Clock.json",vmanage],
            'EIGRP_Authentication_check' : [end_point[19], "EIGRP_Authentication_check.json",vedge],
            'Enable_Implicit_ACL_Logging' : [end_point[17], "Enable_Implicit_ACL_Logging.json",vedge],
            'Device_Banner' : [end_point[17], "Device_Banner.json",['vmanage','vedge']],
            'Enable_Tunnel_Interface_Validator' : [end_point[17], "Enable_Tunnel_Interface_Validator.json",['vbond']],
            'Memory_utilization_SDWAN_Manager' : [end_point[20], "Memory_utilization_SDWAN_Manager.json",vmanage],
            'Memory_utilization_Validator' : [end_point[20], "Memory_utilization_Validator.json",['vbond']],
            'Memory_usage_Controller' : [end_point[20], "Memory_usage_Controller.json",['vsmart']],
            'Number_Control_connections_Controller' : [end_point[21], "Number_Control_connections_Controller.json",['vsmart']],
            'SDWAN_Number_Control_connections_Controller' : [end_point[21], "SDWAN_Number_Control_connections_Controller.json",vmanage]
        }
        start = time.perf_counter()
        logging.info("Dataservice device apis multithread execution started " +str(start))
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for endpoint,file_name,type_list in all_service_checks_dict.values():
                future = executor.submit(dataservice_checks, zip_file_name, devices, base_url, endpoint,file_name,type_list)
                futures.append(future)

            for future in tqdm(as_completed(futures), total=len(futures), desc="Fetching devices data"):
                logging.info(f"Dataservice check started for each device , file: {file_name}")
                try:
                    # Get the result of the future, if it raises an exception it will be re-raised here
                    result = future.result()
                    logging.info(f"Dataservice check completed for file: {file_name}, endpoint: {endpoint}")

                except Exception as e:
                    logging.exception("An error occurred in a future: " + str(e))

        finish = time.perf_counter()
        logging.info("Dataservice device apis multithread execution completed" +str(finish))
    except Exception as e:
        logging.exception("Exception in dataservice_ed_data function" + str(e))

def cluster_check(zip_file_name,base_url,end_point):
    result=[]
    try:
        nw_ed = base_url + end_point[0]
        cluster_health_status=api_checks_execution(nw_ed)
        if "data" in cluster_health_status and cluster_health_status["data"] != []:
            add_data_to_extract(zip_file_name, "_dataservice_clusterManagement_health_status.json", cluster_health_status["data"])

            def cluster_device(dev):
                tmp_url = base_url + end_point[1].format(dev['deviceIP'])
                response = api_checks_execution(tmp_url)
                if "data" in response and response["data"] != []:
                    vedge_count=0
                    for item in response["data"]:
                        if item.get("device-type") == "vedge":
                            vedge_count+=1
                    result.append([dev['deviceIP'], vedge_count])

            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=API_MAX_CONCURRENCY) as executor:
                for dev in cluster_health_status["data"]:
                    if "deviceIP" in dev:
                        executor.submit(cluster_device, dev)
        add_data_to_extract(zip_file_name, "_dataservice_clusterManagement_health_status_connectedDevices.json", result)
    except Exception as e:
     logging.exception("Exception in cluster_check function" + str(e))

def uuid_checks(zip_file_name,base_url,end_point):
    result = []
    try:
        nw_ed = base_url + end_point[0]
        networksummary = api_checks_execution(nw_ed)
        if "data" in networksummary and networksummary["data"] != []:
            result.append({"networksummary" : networksummary["data"]})

            def uuid_device(dev):
                tmp_url = base_url + end_point[1].format(dev['uuid'])
                response = api_checks_execution(tmp_url)
                if "data" in response and response["data"] != []:
                    re = [i.update({"host-name": dev["host-name"]}) for i in response["data"]]
                    result.append({"troubleshooting" : response["data"]})

            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=API_MAX_CONCURRENCY) as executor:
                for dev in networksummary["data"]:
                    executor.submit(uuid_device, dev)

        add_data_to_extract(zip_file_name,"networksummary.json",result)
    except Exception as e:
     logging.exception("Exception in uuid_checks function" + str(e))

def n_summary_res(zip_file_name, base_url, end_point):
    result=[]
    try:
        q_url = base_url + end_point
        res = api_checks_execution(q_url)
        if None not in res or 400 not in res:
            for i in res['data']:
                if i["name"] == 'vSmart':
                    uri = i["detailsURL"]
                    uri = uri[1:]
                    tmp_url=base_url + "/" + uri
                    res1 = api_checks_execution(tmp_url)
                    if None not in res1 or 400 not in res1:
                        result.append({"vSmart": res1["data"]})
                elif i["name"] == 'WAN Edge':
                    uri = i["detailsURL"]
                    uri = uri[1:]
                    tmp_url=base_url + "/" + uri
                    res2 = api_checks_execution(tmp_url)
                    if None not in res2 or 400 not in res2:
                        result.append({"WAN Edge": res2["data"]})
                elif i["name"] == 'vBond':
                    uri = i["detailsURL"]
                    uri = uri[1:]
                    tmp_url=base_url + "/" + uri
                    res3 = api_checks_execution(tmp_url)
                    if None not in res3 or 400 not in res3:
                        result.append({"vBond": res3["data"]})
        add_data_to_extract(zip_file_name, "_dataservice_network_connectionssummary.json", result)
    except Exception as e:
        logging.exception("Exception in n_summary_res function" + str(e))

def bfd_sites(zip_file_name, base_url, end_point,details):
    result = []
    try:
        if details == {}:
            nw_ed = base_url + end_point
            bfd_summary = api_checks_execution(nw_ed)
        else:
            bfd_summary = details
        if "data" in bfd_summary and bfd_summary["data"] != []:
            result.append({"bfdSummary": bfd_summary["data"]})
            if "statusList" in bfd_summary["data"][0] and bfd_summary["data"][0]['statusList'] != []:
                for index, dev in enumerate(bfd_summary["data"][0]['statusList']):
                    if dev['detailsURL'] != '':
                        tmp_url = base_url + dev['detailsURL']
                        response = api_checks_execution(tmp_url)
                        # SLEEP ADDED AFTER EVERY 100 DEVICE CHECKS (value block)
                        if (index + 1) % 100 == 0:
                            logging.info("Sleeping for 30 seconds after 100 BFD site checks...")
                            time.sleep(20)
                        if "data" in response and response["data"] != []:
                            re = [i.update({"name": dev["name"]}) for i in response["data"]]
                            result.append({"wanConnectivity": response["data"]})
        add_data_to_extract(zip_file_name, "wanConnectivity.json", result)
    except Exception as e:
        logging.exception("Exception in bfd_sites function" + str(e))
# def process_endpoint(base_url, endpoint,filename=None, url_suffix=""):
#     url = base_url + endpoint + url_suffix
#     auth_response = api_checks_execution(url)
#     if filename:
#         add_data_to_extract(zip_file_name, filename, auth_response)
#     else:
#         fp = endpoint.partition('?')[0].replace('/', '_')
#         filename = fp + (url_suffix.replace('?', '_') if url_suffix else '') + '.json'
#         add_data_to_extract(zip_file_name, filename, auth_response)

def process_endpoint(base_url, endpoint,filename=None, url_suffix=""):
    url = base_url + endpoint + url_suffix
    # if auth_response:
    #     if url_suffix:
    #         print("generating auth response***********")
    auth_response = api_checks_execution(url)
    fp = endpoint.partition('?')[0].replace('/', '_')
    # if checks_run == 'sdwan_sar_report':
    #     l = fp.split("dataservice_")
    #     if len(l) > 1:
    #         fp = l[1]
    #     if filename:
    #         filename = fp + '.json'
    if filename:
        add_data_to_extract(zip_file_name, filename, auth_response)
    else:
        # fp = endpoint.partition('?')[0].replace('/', '_')
        filename = fp + (url_suffix.replace('?', '_') if url_suffix else '') + '.json'
        add_data_to_extract(zip_file_name, filename, auth_response)
    return fp

def ziptron(base_url):
    logging.info(r_path)
    
    sdwan_ep = os.path.join(cwd, 'stage1_endpoints.txt')
    # Perform API query
    file = open(sdwan_ep, 'r')
    # This will print every line one by one in the file
    try:
        logging.info("**************ZIP_FILE_NAME***********"+ str(zip_file_name) + '********')
        os.mkdir(os.path.join(r_path, 'extracted'))
        j_son_files_path = os.path.join(r_path, 'extracted')
        # loop = asyncio.get_event_loop()
        main_start = time.perf_counter()
        logging.info("----MAIN SCRIPT START TIME----" +str(main_start))
        for ed in tqdm(file.readlines(), desc="Overall Progress"):
            print("**************")
            if ',' in ed:
                end_point = ed.strip()
                end_point = end_point.split(',')
                if 'vedges' in end_point[0]:
                    logging.info("Execution started for vedges data checks")
                    asyncio.run(vedge_data_json(zip_file_name, base_url, end_point, 'vedgedata.json',[]))
                    # loop.close()
                    # vedge_strip = end_point[0].strip('vedges')
                    # end_point.pop(0)
                    # end_point.insert(0, vedge_strip + 'controllers')
                    # controllers_response =  vedge_data_json(zip_file_name, base_url, end_point,'controllers.json', ['vSmart'])
                elif 'tlocutil' in end_point[0]:
                    logging.info("Execution started for details url checks")
                    details_url_res = details_url(zip_file_name, base_url, end_point)
                elif 'deviceId={}' in end_point[0]:
                    logging.info("Execution started for dataservice checks")
                    dataservice_ed_res = dataservice_ed_data(zip_file_name, base_url, end_point)
                elif 'networksummary?' in end_point[0]:
                    logging.info("Execution started for uuid checks")
                    uuid_res = uuid_checks(zip_file_name, base_url, end_point)
                elif '/clusterManagement/health/status' in end_point[0]:
                    logging.info("Execution started for clusterManagement health status check")
                    cluster_res = cluster_check(zip_file_name, base_url, end_point)
            elif '/bfd/sites/summary?' in ed:
                logging.info("Execution started for bfd sites summary checks")
                end_point = ed.strip()
                bfd_sites_res = bfd_sites(zip_file_name, base_url, end_point,{})
            elif '/statistics/approute?query' in ed or '/statistics/qos' in ed:
                logging.info("Execution started for approut or qos checks")
                end_point = ed.strip()
                q_url = base_url + end_point
                result = api_checks_execution(q_url)
                if None in result or 400 in result:
                    session_data['header'] = refresh_credentials(session_data, False)
                    q_result=api_checks_execution(q_url)
                    if '/statistics/approute?query' in q_url:
                        add_data_to_extract(zip_file_name, "_dataservice_statistics_approute.json", q_result)
                    elif '/statistics/qos' in q_url:
                        add_data_to_extract(zip_file_name, "_dataservice_statistics_qos.json", q_result)
                else:
                    if '/statistics/approute?query' in q_url:
                        add_data_to_extract(zip_file_name, "_dataservice_statistics_approute.json", result)
                    elif '/statistics/qos' in q_url:
                        add_data_to_extract(zip_file_name, "_dataservice_statistics_qos.json", result)
            
            elif '/network/connectionssummary' in ed:
                logging.info("Execution started for network connection summary check")
                end_point = ed.strip()
                connectionssummary = n_summary_res(zip_file_name, base_url, end_point)

            else:                
                logging.info("Execution started for normal checks")
                end_point = ed.strip()
                # url = base_url + end_point
                if end_point == "/dataservice/template/device":
                    process_endpoint(base_url,end_point)
                    process_endpoint(base_url,end_point,"dataservice_template_featureall", "?feature=all")
                elif end_point == "/dataservice/alarms":
                    process_endpoint(base_url,  end_point, "dataservice_alarms_info")
                else:
                    process_endpoint(base_url,end_point)

                # if end_point == "/dataservice/template/device":
                #     url = base_url + end_point
                #     auth_response = api_checks_execution(url)
                #     fp = end_point.replace('/', '_')
                #     filename = fp + '.json'
                #     add_data_to_extract(zip_file_name, filename, auth_response)
                #     url2 = base_url + end_point + "?feature=all"
                #     auth_response2 = api_checks_execution(url2)
                #     filename1 = "dataservice_template_feature_all.json"
                #     add_data_to_extract(zip_file_name, filename1, auth_response2)
                # else:
                #     auth_response = api_checks_execution(url)
                #     if '?' in end_point:
                #         ed = end_point.partition('?')[0]
                #         fp = ed.replace('/', '_')
                #     else:
                #         fp = end_point.replace('/', '_')
                #     filename = fp + '.json'
                #     add_data_to_extract(zip_file_name, filename, auth_response)

        main_finish = time.perf_counter()
        logging.info("----MAIN SCRIPT END TIME----" + str(round(main_finish - main_start, 2)))
        print(f'\n\nFinished in {round(main_finish - main_start, 2)} second(s) - MULTITHREADING SCRIPT')

        file.close()
        logging.info("SDWAN collector script ran successfully, zip_file_name: " +  str(zip_file_name) + " ,json_files_path: " + str(j_son_files_path) )
        source_file =  open('script_log.log', 'rb')
        destination_file = open(os.path.join(r_path, 'extracted', 'script_log.log'), 'wb')
        shutil.copyfileobj(source_file, destination_file)
        archive = shutil.make_archive(r_path, 'zip', r_path)
        print("SDWAN collector script ran successfully, zip_file_name: " +  str(zip_file_name) + " ,json_files_path: " + str(j_son_files_path) )
    except Exception as e:
        logging.info("Not able to fetch files from the server" + str(e))
        file.close()

def run(base_url, header, admin_username=None, admin_password=None, sso_enabled='N'):
    """Run the Stage 1 SD-WAN data collection programmatically.

    This is the importable entrypoint used by the combined orchestrator. It
    reuses an already-authenticated session by accepting the ready-to-use
    ``header`` dict (Content-Type / Cookie / X-XSRF-TOKEN). No login is
    performed here, so the caller's single authenticated token is reused for
    every API call. The generated files and zip archive are identical to the
    standalone script.

    @param base_url: Base vManage URL (e.g. https://1.2.3.4 or https://1.2.3.4:8443)
    @param header: Authenticated request header dict (Cookie + X-XSRF-TOKEN)
    @param admin_username: Optional, used only to refresh credentials on expiry
    @param admin_password: Optional, used only to refresh credentials on expiry
    @param sso_enabled: 'N' for username/password (default), 'Y' for SSO tokens
    @return: Absolute path to the generated zip archive
    """
    global zip_file_name, r_path

    zip_file_name = str(random.randint(111000, 9999999))
    r_path = os.path.join(cwd, zip_file_name)
    os.makedirs(r_path, exist_ok=True)

    session_data["sso_enabled"] = sso_enabled
    session_data["base_url"] = base_url
    session_data["admin_username"] = admin_username
    session_data["admin_password"] = admin_password
    session_data["header"] = header

    logging.info("********************Calling zip function*********************")
    ziptron(base_url)
    logging.info("********************End of zip function*********************")

    return r_path + ".zip"


if __name__ == "__main__":
    try:
        ip_address = input("Enter your ip address :- ")
        port = input("Enter your port (Leave blank to skip) :- ").strip()
        if port:
            base_url = "https://%s:%s"%(ip_address, port)
        else:
            base_url = "https://%s"%(ip_address)

        admin_username = input("Enter your vmanage username :- ")
        admin_password = pwinput.pwinput(prompt="Enter your vmanage password :- ")
        token, jsessionid, cond = get_token(base_url, admin_username, admin_password)
        if token is None and jsessionid == 400:
            raise Exception('Authentication Failed')
        if '<html>' in token:
            raise Exception('Invalid Token')
        if cond != 'port':
            base_url = "https://%s"%(ip_address)

        header = {'Content-Type': "application/json", 'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
        run(base_url, header, admin_username=admin_username, admin_password=admin_password)
    except Exception as e:
        logging.error("Exception occurred inside main function: " + str(e))
    finally:
        session_data.clear()
