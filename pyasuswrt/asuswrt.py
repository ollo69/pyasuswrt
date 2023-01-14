"""PyAsusWRT Library implementation"""

from __future__ import annotations

import asyncio
import base64
from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime
import logging
import math

import aiohttp

from .exceptions import (
    AsusWrtClientResponseError,
    AsusWrtConnectionError,
    AsusWrtConnectionTimeoutError,
    AsusWrtError,
    AsusWrtLoginError,
)
from .helpers import (
    _calculate_cpu_usage,
    _get_json_result,
    _parse_fw_info,
    _parse_temperatures,
)

_ASUSWRT_USR_AGENT = "asusrouter-Android-DUTUtil-1.0.0.245"
_ASUSWRT_ERROR_KEY = "error_status"
_ASUSWRT_ACTION_KEY = "action_mode"
_ASUSWRT_HOOK_KEY = "hook"
_ASUSWRT_TOKEN_KEY = "asus_token"
_ASUSWRT_LOGIN_PATH = "login.cgi"
_ASUSWRT_GET_PATH = "appGet.cgi"
_ASUSWRT_CMD_PATH = "applyapp.cgi"
_ASUSWRT_APPLY_PATH = "apply.cgi"
_ASUSWRT_FW_PATH = "detect_firmware.asp"
_ASUSWRT_TEMP_PATH = "ajax_coretmp.asp"
_ASUSWRT_SVC_REQ = "rc_service"
_ASUSWRT_SVC_REPLY = "run_service"
_ASUSWRT_SVC_MODIFY = "modify"

_CMD_CLIENT_LIST = "get_clientlist"
_CMD_CPU_USAGE = "cpu_usage"
_CMD_DHCP_LEASE = "dhcpLeaseMacList"
_CMD_MEMORY_USAGE = "memory_usage"
_CMD_NET_TRAFFIC = "netdev"
_CMD_NVRAM = "nvram_get"
_CMD_UPTIME = "uptime"
_CMD_WAN_INFO = "wanlink"
_CMD_REBOOT = "reboot"
_CMD_LED_STATUS = "start_ctrl_led"
_CMD_FW_CHECK = "firmware_check"

_PARAM_APPOBJ = "appobj"

_PROP_MAC_ADDR = "label_mac"
_PROP_MODEL = "productid"
_PROP_LED_STATUS = "led_val"

_NVRAM_INFO = [
    "acs_dfs",
    "model",
    _PROP_MODEL,
    _PROP_MAC_ADDR,
    "buildinfo",
    "firmver",
    "firmver_org",
    "buildno",
    "buildno_org",
    "extendno",
    "extendno_org",
    "innerver",
    "apps_sq",
    "lan_hwaddr",
    "lan_ipaddr",
    "lan_proto",
    "x_Setting",
    "lan_netmask",
    "lan_gateway",
    "http_enable",
    "https_lanport",
    "cfg_device_list",
    "wl0_country_code",
    "wl1_country_code",
    "time_zone",
    "time_zone_dst",
    "time_zone_x",
    "time_zone_dstoff",
    "time_zone",
    "ntp_server0",
]

DEFAULT_TIMEOUT = 5
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 8443
FW_CHECK_INTERVAL = 7200  # seconds, means 2 hour

Device = namedtuple("Device", ["mac", "ip", "name", "node", "is_mesh_node", "is_wl"])

_LOGGER = logging.getLogger(__name__)


def _nvram_cmd(info_type):
    """Return the cmd to get nvram data."""
    return f"{_CMD_NVRAM}({info_type})"


@dataclass()
class AsusWrtFirmware:
    """Represent an AsusWrt firmware."""

    version: str | None
    build: str
    extend: str | None

    def to_str(self) -> str | None:
        """Convert firmware information to a readable string."""
        retval = None
        if self.version:
            retval = self.version
        if retval:
            retval += f".{self.build}"
        else:
            retval = self.build
        if self.extend:
            retval += f"_{self.extend}"
        return retval

    def check_new(self, build: str, extend: str | None) -> str | None:
        """Check if available fw differs from existing."""
        if build != self.build:
            return AsusWrtFirmware(None, build, extend).to_str()
        if extend != self.extend:
            return AsusWrtFirmware(None, build, extend).to_str()
        return None


class AsusWrtHttp:
    """Class for AsusWrt router HTTP/HTTPS connection."""

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        *,
        use_https: bool = False,
        port: int | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        session: aiohttp.ClientSession | None = None,
    ):
        """
        Create the router object

        Parameters:
            hostname: HostName or IP Address of the router
            username: Router username
            password: Password required to login
            use_https: if True use https instead of http (default False)
            port: the tcp port to use (leave None or 0 for protocol default)
            timeout: the tcp timeout (default = 5 sec.)
            session: the AioHttp session to use (if None a new session is created)
        """
        self._hostname = hostname
        self._username = username
        self._password = password
        self._protocol = "https" if use_https else "http"
        if port and port > 0:
            self._port = port
        else:
            self._port = DEFAULT_HTTPS_PORT if use_https else DEFAULT_HTTP_PORT
        self._timeout = timeout if timeout > 0 else DEFAULT_TIMEOUT

        self._auth_headers = None
        if session:
            self._session = session
            self._managed_session = False
        else:
            self._session = None
            self._managed_session = True

        self._mac: str | None = None
        self._model: str | None = None
        self._firmware: AsusWrtFirmware | None = None
        self._last_fw_check = datetime.utcnow()
        self._mesh_nodes = None

        # Transfer rate variable
        self._latest_transfer_data = None
        self._latest_transfer_rate = {"rx_rate": 0.0, "tx_rate": 0.0}
        self._latest_transfer_check = None

        # CPU usage variable
        self._available_cpu = None
        self._latest_cpu_data = None

    def __url(self, path):
        """Return the url to a specific path."""
        return f"{self._protocol}://{self._hostname}:{self._port}/{path}"

    async def __http_post(self, url, headers, payload, *, get_json=False):
        """Perform aiohttp POST request."""
        try:
            async with self._session.post(
                url=url,
                headers=headers,
                data=payload,
                timeout=self._timeout,
                raise_for_status=True,
                ssl=False,
            ) as resp:
                if get_json:
                    result = await resp.json()
                else:
                    result = await resp.text()

        except (asyncio.TimeoutError, aiohttp.ServerTimeoutError) as err:
            raise AsusWrtConnectionTimeoutError(str(err)) from err
        except aiohttp.ClientConnectorError as err:
            raise AsusWrtConnectionError(str(err)) from err
        except aiohttp.ClientConnectionError as err:
            self._auth_headers = None
            raise AsusWrtConnectionError(str(err)) from err
        except aiohttp.ClientResponseError as err:
            raise AsusWrtClientResponseError(
                request_info=err.request_info,
                history=err.history,
                status=err.status,
                message=err.message,
                headers=err.headers,
            ) from err
        except aiohttp.ClientError as err:
            self._auth_headers = None
            raise AsusWrtError(str(err)) from err

        return result

    async def __post(
        self, *, path=_ASUSWRT_GET_PATH, command: str | None = None, retry=True
    ):
        """
        Private POST method to execute a command on the router and return the result

        :param path: Path to send to the command
        :param command: Command to send
        :returns: string result from the router
        """
        payload = command or ""
        try:
            await self.async_connect()
            result = await self.__http_post(
                self.__url(path), self._auth_headers, payload
            )

        except (AsusWrtConnectionError, AsusWrtClientResponseError):
            if retry:
                return await self.__post(path=path, command=command, retry=False)
            raise

        if result.find(_ASUSWRT_ERROR_KEY, 0, len(_ASUSWRT_ERROR_KEY) + 5) >= 0:
            self._auth_headers = None
            if retry:
                return await self.__post(path=path, command=command, retry=False)
            raise AsusWrtConnectionError("Not connected to the router")

        return result

    async def __send_cmd(
        self,
        *,
        path=_ASUSWRT_CMD_PATH,
        commands: dict[str, str] | None = None,
        action_mode: str = "apply",
    ):
        """Command device to run a service or set parameter."""
        add_req = commands or {}
        request: dict = {
            _ASUSWRT_ACTION_KEY: action_mode,
            **add_req,
        }
        return await self.__post(path=path, command=str(request))

    async def __send_req(self, command: str):
        """Send a hook request to the device.

        :param command: Command to send
        :returns: string result from the router
        """
        request = f"{_ASUSWRT_HOOK_KEY}={command}"
        return await self.__post(command=request)

    async def _run_service(
        self, service: str, *, arguments: dict[str, str] | None = None
    ) -> bool:
        """Command device to run a service.

        :param service: Service to run
        :param arguments: Arguments for the service to run (optional)
        :returns: True or False
        """
        commands = {_ASUSWRT_SVC_REQ: service}
        if arguments:
            commands.update(arguments)

        s = await self.__send_cmd(commands=commands)
        result = _get_json_result(s)
        if not all(v in result for v in [_ASUSWRT_SVC_REPLY, _ASUSWRT_SVC_MODIFY]):
            return False
        if result[_ASUSWRT_SVC_REPLY] != service:
            return False
        return True

    @property
    def hostname(self) -> str:
        """Return the device hostname."""
        return self._hostname

    @property
    def mac(self) -> str | None:
        """Return the device mac address."""
        return self._mac

    @property
    def model(self) -> str | None:
        """Return the device mac address."""
        return self._model

    @property
    def firmware(self) -> str | None:
        """Return the device firmware."""
        if self._firmware:
            return self._firmware.to_str()
        return None

    @property
    def is_connected(self) -> bool:
        """Return if connection is active."""
        return self._auth_headers is not None

    async def async_disconnect(self):
        """Close the managed session on exit."""
        if self._managed_session and self._session is not None:
            await self._session.close()
            self._session = None
        self._auth_headers = None

    async def async_connect(self):
        """Authenticate with the router."""
        if self.is_connected:
            return

        if self._managed_session and self._session is None:
            self._session = aiohttp.ClientSession()

        auth = f"{self._username}:{self._password}".encode("ascii")
        login_token = base64.b64encode(auth).decode("ascii")
        payload = f"login_authorization={login_token}"
        headers = {"user-agent": _ASUSWRT_USR_AGENT}

        result = await self.__http_post(
            self.__url(_ASUSWRT_LOGIN_PATH), headers, payload, get_json=True
        )
        if _ASUSWRT_TOKEN_KEY not in result:
            raise AsusWrtLoginError("Login Failed")

        token = result[_ASUSWRT_TOKEN_KEY]
        self._auth_headers = {
            "user-agent": _ASUSWRT_USR_AGENT,
            "cookie": f"{_ASUSWRT_TOKEN_KEY}={token}",
        }

        # try to get the main properties after connect
        await self._load_props()

    async def _load_props(self) -> None:
        """Load device properties from NVRam."""
        # mac address
        if self._mac is None:
            try:
                result = await self.async_get_settings(_PROP_MAC_ADDR)
            except AsusWrtError:
                _LOGGER.debug("Failed to retrieve device mac address")
            else:
                self._mac = result.get(_PROP_MAC_ADDR)
        # model
        if self._model is None:
            try:
                result = await self.async_get_settings(_PROP_MODEL)
            except AsusWrtError:
                _LOGGER.debug("Failed to retrieve device model")
            else:
                self._model = result.get(_PROP_MODEL)
        # firmware
        try:
            await self.async_get_cur_fw()
        except AsusWrtError:
            _LOGGER.debug("Failed to retrieve installed firmware")

    async def async_get_cur_fw(self) -> str | None:
        """Get current device firmware information."""
        version = build = extend = None
        if firmver := await self.async_get_settings("firmver"):
            version = firmver.get("firmver")
        buildno = await self.async_get_settings("buildno")
        if buildno and "buildno" in buildno:
            build = buildno["buildno"]
            if extendno := await self.async_get_settings("extendno"):
                extend = extendno.get("extendno")
        if build:
            self._firmware = AsusWrtFirmware(version, build, extend)
        return self.firmware

    async def async_get_new_fw(self) -> str | None:
        """Get new device firmware available."""
        try:
            await self.async_check_fw_update()
            if not await self.async_get_cur_fw():
                return None
            res = await self.__post(path=_ASUSWRT_FW_PATH)
        except AsusWrtError as ex:
            _LOGGER.debug("Failed checking for new fw version: %s", ex)
            return None

        if not (fw_elem := _parse_fw_info(res)):
            return None

        return self._firmware.check_new(fw_elem[0], fw_elem[1])

    async def async_check_fw_update(self):
        """Check for firmware update."""
        call_time = datetime.utcnow()
        if (call_time - self._last_fw_check).total_seconds() < FW_CHECK_INTERVAL:
            return
        self._last_fw_check = call_time
        try:
            await self.__send_cmd(path=_ASUSWRT_APPLY_PATH, action_mode=_CMD_FW_CHECK)
        except AsusWrtError:
            _LOGGER.debug("Failed to check for new firmware")

    async def async_reboot(self) -> bool:
        """Reboot the router."""
        return await self._run_service(_CMD_REBOOT)

    async def async_get_led_status(self) -> bool:
        """Get device led status."""
        result = await self.async_get_settings(_PROP_LED_STATUS)
        try:
            led = int(result.get(_PROP_LED_STATUS, 0))
        except (TypeError, ValueError):
            return False
        return led != 0

    async def async_set_led_status(self, status: bool) -> bool:
        """Set device led status."""
        arguments = {
            _PROP_LED_STATUS: 1 if status else 0,
        }
        return await self._run_service(_CMD_LED_STATUS, arguments=arguments)

    async def async_get_uptime(self):
        """
        Return uptime of the router

        Format: {'since': 'Thu, 22 Jul 2021 14:32:38 +0200', 'uptime': '375001'}

        :returns: JSON with last boot time and uptime in seconds
        """
        r = await self.__send_req(f"{_CMD_UPTIME}()")
        time = r.partition(":")[2].partition("(")[0]
        up = int(r.partition("(")[2].partition(" ")[0])
        return {"uptime": up, "time": time}

    async def async_get_memory_usage(self):
        """
        Return memory usage of the router

        Format: {'mem_total': 262144, 'mem_free': 107320, 'mem_used': 154824}

        :returns: JSON with memory variables
        """
        s = await self.__send_req(f"{_CMD_MEMORY_USAGE}({_PARAM_APPOBJ})")
        result = _get_json_result(s, _CMD_MEMORY_USAGE)
        result_val = {k: int(v) for k, v in result.items()}

        # calculate memory usage percentage
        try:
            mem_usage = round(
                (result_val["mem_used"] / result_val["mem_total"]) * 100, 2
            )
        except (KeyError, TypeError, ValueError, ZeroDivisionError):
            mem_usage = None

        return {"mem_usage_perc": mem_usage, **result_val}

    async def async_get_cpu_usage(self):
        """
        Return CPUs usage of the router
        Note that at least 2 calls is required to have valid data

        Format: {'cpu1': 0.22, 'cpu2': 0.01, ... 'cpu_total': 0.21}

        :returns: JSON with CPUs load percentage
        """
        if self._available_cpu is not None:
            if not self._available_cpu:
                return {}

        s = await self.__send_req(f"{_CMD_CPU_USAGE}({_PARAM_APPOBJ})")
        result = _get_json_result(s, _CMD_CPU_USAGE)

        cpu_data = {}
        for key, val in result.items():
            if not key.startswith("cpu"):
                continue
            cpu_info = key.split("_")
            if len(cpu_info) != 2:
                continue
            cpu_data.setdefault(f"{cpu_info[0]}_usage", {})[cpu_info[1]] = int(val)

        if self._available_cpu is None:
            self._available_cpu = [k for k in cpu_data]
            if not self._available_cpu:
                return {}

        # calculate the CPU usage
        prev_cpu_data = self._latest_cpu_data or {}
        cpu_usage = {}
        for key in self._available_cpu:
            if not (key in cpu_data and key in prev_cpu_data):
                cpu_usage[key] = 0.0
                continue
            cpu_usage[key] = _calculate_cpu_usage(cpu_data[key], prev_cpu_data[key])

        # calculate the total CPU average usage
        cpu_avg = [v for v in cpu_usage.values()]
        cpu_usage["cpu_total_usage"] = round(sum(cpu_avg) / len(cpu_avg), 2)

        # save last fetched data
        self._latest_cpu_data = cpu_data.copy()

        return cpu_usage

    async def async_get_temperatures(self):
        """
        Return Temperatures from the router

        Format: {'2.4GHz': 42.0, '5.0GHz': 48.0, 'CPU': 64.0, ...}

        :returns: JSON with Temperatures statistics
        """
        s = await self.__post(path=_ASUSWRT_TEMP_PATH)
        result = _parse_temperatures(s)
        return result

    async def async_get_wan_info(self):
        """
        Get the status of the WAN connection

        Format: {"status": "1", "statusstr": "'Connected'", "type": "'dhcp'", "ipaddr": "'192.168.1.2'",
                 "netmask": "'255.255.255.0'", "gateway": "'192.168.1.1'", "dns": "1.1.1.1'",
                 "lease": "86400", "expires": "81967", "xtype": "''", "xipaddr": "'0.0.0.0'",
                 "xnetmask": "'0.0.0.0'", "xgateway": "'0.0.0.0'", "xdns": "''", "xlease": "0",
                 "xexpires": "0"}

        :returns: JSON with status information on the WAN connection
        """
        r = await self.__send_req(f"{_CMD_WAN_INFO}()")
        status = {}
        for f in r.split("\n"):
            if "return" in f:
                if f"{_CMD_WAN_INFO}_" in f:
                    key = f.partition("(")[0].partition("_")[2]
                    value = (f.rpartition(" ")[-1][:-2]).replace("'", "")
                    status[key] = value
        return status

    async def async_is_wan_online(self):
        """
        Returns if the WAN connection in online

        :returns: True if WAN is connected
        """
        r = await self.async_get_wan_info()
        return r["status"] == "1"

    async def async_get_dhcp_leases(self):
        """
        Obtain a list of DHCP leases

        Format: [["00:00:00:00:00:00", "name"], ...]

        :returns: JSON with a list of DHCP leases
        """
        s = await self.__send_req(f"{_CMD_DHCP_LEASE}()")
        return _get_json_result(s, _CMD_DHCP_LEASE)

    async def async_get_traffic_bytes(self):
        """
        Get total amount of traffic since last restart (bytes format)

        Format: {'rx': 15901, 'tx': 10926}

        :returns: JSON with sent and received bytes since last boot
        """
        s = await self.__send_req(f"{_CMD_NET_TRAFFIC}({_PARAM_APPOBJ})")
        meas = _get_json_result(s, _CMD_NET_TRAFFIC)
        if "INTERNET_rx" in meas:
            traffics = ["INTERNET"]
        else:
            traffics = ["WIRED", "WIRELESS0", "WIRELESS1"]
        # elif "BRIDGE_rx" in meas:
        #     traffics = ["BRIDGE"]

        rx = tx = 0
        for traffic in traffics:
            if f"{traffic}_rx" in meas:
                rx += int(meas[f"{traffic}_rx"], base=16)
                tx += int(meas[f"{traffic}_tx"], base=16)

        return {"rx": rx, "tx": tx}

    async def async_get_traffic_rates(self):
        """
        Get total and current amount of traffic since last restart (bytes format)
        Note that at least 2 calls with an interval of min 10 seconds is required to have valid data

        Format: {"rx_rate": 0.13004302978515625, "tx_rate": 4.189826965332031}

        :returns: JSON with current up and down stream in byte/s
        """

        now = datetime.utcnow()
        meas_1 = None
        if self._latest_transfer_data:
            meas_1 = self._latest_transfer_data.copy()
        meas_2 = await self.async_get_traffic_bytes()
        prev_check = self._latest_transfer_check
        self._latest_transfer_data = meas_2.copy()
        self._latest_transfer_check = now

        if meas_1 is None:
            return self._latest_transfer_rate

        meas_delta = (now - prev_check).total_seconds()
        if meas_delta < 10:
            return self._latest_transfer_rate

        rates = {}
        for key in ["rx", "tx"]:
            if meas_2[key] < meas_1[key]:
                rates[key] = meas_2[key]
            else:
                rates[key] = meas_2[key] - meas_1[key]

        self._latest_transfer_rate = {
            "rx_rate": math.ceil(rates["rx"] / meas_delta),
            "tx_rate": math.ceil(rates["tx"] / meas_delta),
        }
        return self._latest_transfer_rate

    async def async_get_settings(self, setting: str = None):
        """
        Get settings from the router NVRam

        Format:{'time_zone': 'MEZ-1DST', 'time_zone_dst': '1', 'time_zone_x': 'MEZ-1DST,M3.2.0/2,M10.2.0/2',
               'time_zone_dstoff': 'M3.2.0/2,M10.2.0/2', 'ntp_server0': 'pool.ntp.org', 'acs_dfs': '1',
               'productid': 'RT-AC68U', 'apps_sq': '', 'lan_hwaddr': '04:D4:C4:C4:AD:D0',
               'lan_ipaddr': '192.168.2.1', 'lan_proto': 'static', 'x_Setting': '1',
               'label_mac': '04:D4:C4:C4:AD:D0', 'lan_netmask': '255.255.255.0', 'lan_gateway': '0.0.0.0',
               'http_enable': '2', 'https_lanport': '8443', 'wl0_country_code': 'EU', 'wl1_country_code': 'EU'}

        :param setting: the setting name to query (leave empty to get all main settings)
        :returns: JSON with main Router settings or specific one
        """
        setting_list = [setting] if setting else _NVRAM_INFO
        result = {}
        for s in setting_list:
            resp = await self.__send_req(_nvram_cmd(s))
            if resp:
                result[s] = _get_json_result(resp, s)
        return result

    async def async_get_clients_fullinfo(self) -> list[dict[str, any]]:
        """
        Obtain a list of all clients

        Format: [
                    "AC:84:C6:6C:A7:C0":{"type": "2", "defaultType": "0", "name": "Archer_C1200",
                                         "nickName": "Router Forlindon", "ip": "192.168.2.175",
                                         "mac": "AC:84:C6:6C:A7:C0", "from": "networkmapd",
                                         "macRepeat": "1", "isGateway": "0", "isWebServer": "0",
                                         "isPrinter": "0", "isITunes": "0", "dpiType": "",
                                         "dpiDevice": "", "vendor": "TP-LINK", "isWL": "0",
                                         "isOnline": "1", "ssid": "", "isLogin": "0", "opMode": "0",
                                         "rssi": "0", "curTx": "", "curRx": "", "totalTx": "",
                                         "totalRx": "", "wlConnectTime": "", "ipMethod": "Manual",
                                         "ROG": "0", "group": "", "callback": "", "keeparp": "",
                                         "qosLevel": "", "wtfast": "0", "internetMode": "allow",
                                         "internetState": "1", "amesh_isReClient": "1",
                                         "amesh_papMac": "04:D4:C4:C4:AD:D0"},
                     "maclist": ["AC:84:C6:6C:A7:C0"],
                     "ClientAPILevel": "2" }
                ]
        :returns: JSON with list of mac address and all client related info
        """
        s = await self.__send_req(f"{_CMD_CLIENT_LIST}()")
        result = _get_json_result(s)
        return [result.get(_CMD_CLIENT_LIST, {})]

    async def async_get_connected_mac(self):
        """
        Obtain a list of MAC-addresses from online clients

        Format: ["00:00:00:00:00:00", ...]
        :returns: JSON list with MAC adresses
        """
        clnts = await self.async_get_clients_fullinfo()
        lst = [
            mac
            for mac, info in clnts[0].items()
            if len(mac) == 17 and info.get("isOnline", "0") == "1"
        ]
        return lst

    async def async_get_connected_devices(self):
        """
        Obtain info on all clients

        Format: {"AC:84:C6:6C:A7:C0": {mac: "AC:84:C6:6C:A7:C0", ip: "x.x.x.x" name: "Archer_C1200"}, ...}
        :return: JSON dict with mac as key and a namedtuple with mac, ip address and name as value
        """
        clnts = await self.async_get_clients_fullinfo()
        dev_list = []
        mesh_nodes = {self._mac: self._hostname} if self._mac else {}
        for mac, info in clnts[0].items():
            if len(mac) == 17 and info.get("isOnline", "0") == "1":
                if is_mesh_node := info.get("amesh_isRe", "0") == "1":
                    mesh_nodes[mac] = info.get("ip")
                if not (name := info.get("nickName")):
                    name = info.get("name")
                is_wl = info.get("isWL", "0") != "0"
                dev_list.append(
                    Device(
                        mac,
                        info.get("ip"),
                        name,
                        info.get("amesh_papMac"),
                        is_mesh_node,
                        is_wl,
                    )
                )

        self._mesh_nodes = mesh_nodes
        result = {}
        for dev in dev_list:
            node_ip = mesh_nodes.get(dev.node) if dev.node else None
            result[dev.mac] = Device(
                dev.mac,
                dev.ip,
                dev.name,
                node_ip or self._hostname,
                dev.is_mesh_node,
                dev.is_wl,
            )

        return result

    async def async_get_mesh_nodes(self):
        """
        Return a list of available mesh nodes

        Format: {"AC:84:C6:6C:A7:C0": "x.x.x.x"}, ...}
        :return: JSON dict with mac as key and ip address as value
        """
        if self._mesh_nodes is None:
            await self.async_get_connected_devices()

        return self._mesh_nodes

    async def async_get_client_info(self, client_mac):
        """
        Get info on a single client

        :param client_mac: MAC address of the client requested
        :return: JSON with clientinfo (see async_get_clients_fullinfo() for description)
        """
        clnts = await self.async_get_clients_fullinfo()
        return clnts[0].get(client_mac)
