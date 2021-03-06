"""PyAsusWRT Library implementation"""

from __future__ import annotations

import aiohttp
import asyncio
import base64
from collections import namedtuple
from datetime import datetime
import json
import logging
import math
from typing import Any, Optional

ASUSWRT_USR_AGENT = "asusrouter-Android-DUTUtil-1.0.0.245"
ASUSWRT_ERROR_KEY = "error_status"
ASUSWRT_TOKEN_KEY = "asus_token"
ASUSWRT_LOGIN_PATH = "login.cgi"
ASUSWRT_GET_PATH = "appGet.cgi"
ASUSWRT_CMD_PATH = "applyapp.cgi"

PARAM_APPOBJ = "appobj"

CMD_CLIENT_LIST = "get_clientlist"
CMD_CPU_USAGE = "cpu_usage"
CMD_DHCP_LEASE = "dhcpLeaseMacList"
CMD_MEMORY_USAGE = "memory_usage"
CMD_NET_TRAFFIC = "netdev"
CMD_NVRAM = "nvram_get"
CMD_UPTIME = "uptime"
CMD_WAN_INFO = "wanlink"

DEFAULT_TIMEOUT = 5
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 8443

PROP_MAC_ADDR = "label_mac"

NVRAM_INFO = [
    "acs_dfs",
    "model",
    "productid",
    PROP_MAC_ADDR,
    "firmver",
    "innerver",
    "buildinfo",
    "buildno",
    "buildno_org",
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

Device = namedtuple("Device", ["mac", "ip", "name", "node", "is_mesh_node", "is_wl"])

_LOGGER = logging.getLogger(__name__)


def _nvram_cmd(info_type):
    """Return the cmd to get nvram data."""
    return f"{CMD_NVRAM}({info_type})"


def _get_json_result(result: str, json_key: str | None = None):
    """Return the json result from a text result."""
    try:
        json_res = json.loads(result)
    except json.JSONDecodeError as exc:
        raise AsusWrtValueError(str(exc)) from exc

    if not json_key:
        return json_res

    if (json_val := json_res.get(json_key)) is None:
        raise AsusWrtValueError("No value available")
    return json_val


class AsusWrtError(Exception):
    """Base class for all errors raised by this library."""

    def __init__(self, *args: Any, message: Optional[str] = None, **_kwargs: Any) -> None:
        """Initialize base UpnpError."""
        super().__init__(*args, message)


class AsusWrtConnectionError(AsusWrtError, aiohttp.ClientConnectionError):
    """Error connecting with the router."""


class AsusWrtConnectionTimeoutError(AsusWrtError, aiohttp.ServerTimeoutError, asyncio.TimeoutError):
    """Timeout while communicating with the device."""


class AsusWrtLoginError(AsusWrtError):
    """Login error / invalid credential."""


class AsusWrtResponseError(AsusWrtError, aiohttp.ClientResponseError):
    """Error communicating with the router."""


class AsusWrtValueError(AsusWrtError, ValueError):
    """Error invalid value received."""


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
            self._session = aiohttp.ClientSession()
            self._managed_session = True

        self._mac = None
        self._latest_transfer_data = None
        self._latest_transfer_rate = {"rx_rate": 0.0, "tx_rate": 0.0}
        self._latest_transfer_check = None

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
            raise AsusWrtResponseError(
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

    async def __post(self, command, path=ASUSWRT_GET_PATH, *, retry=True):
        """
        Private POST method to execute a hook on the router and return the result

        :param command: Command to send to the return
        :returns: string result from the router
        """
        payload = f"hook={command}"
        try:
            await self.async_connect()
            result = await self.__http_post(self.__url(path), self._auth_headers, payload)

        except (AsusWrtConnectionError, AsusWrtResponseError):
            if retry:
                return await self.__post(command, path, retry=False)
            raise

        if result.find(ASUSWRT_ERROR_KEY, 0, len(ASUSWRT_ERROR_KEY) + 5) >= 0:
            self._auth_headers = None
            if retry:
                return await self.__post(command, path, retry=False)
            raise AsusWrtConnectionError("Not connected to the router")

        return result

    async def __send_cmd(self, commands: dict[str, str], action_mode: str = "apply"):
        """Command device to run a service or set parameter"""
        request: dict = {
            "action_mode": action_mode,
            **commands,
        }
        result = await self.__post(str(request), ASUSWRT_CMD_PATH)
        return result

    @property
    def hostname(self) -> str:
        """Return the device hostname."""
        return self._hostname

    @property
    def mac(self) -> str | None:
        """Return the device mac address."""
        return self._mac

    @property
    def is_connected(self) -> bool:
        """Return if connection is active."""
        return self._auth_headers is not None

    async def async_disconnect(self):
        """Close the managed session on exit."""
        if self._managed_session:
            await self._session.close()
        self._auth_headers = None

    async def async_connect(self):
        """Authenticate with the router."""
        if self.is_connected:
            return

        auth = f"{self._username}:{self._password}".encode("ascii")
        login_token = base64.b64encode(auth).decode("ascii")
        payload = f"login_authorization={login_token}"
        headers = {"user-agent": ASUSWRT_USR_AGENT}

        result = await self.__http_post(self.__url(ASUSWRT_LOGIN_PATH), headers, payload, get_json=True)
        if ASUSWRT_TOKEN_KEY not in result:
            raise AsusWrtLoginError("Login Failed")

        token = result[ASUSWRT_TOKEN_KEY]
        self._auth_headers = {
            "user-agent": ASUSWRT_USR_AGENT,
            "cookie": f"{ASUSWRT_TOKEN_KEY}={token}",
        }

        # try to get the main properties after connect
        await self._load_props()

    async def _load_props(self) -> str | None:
        """Load device properties from NVRam."""
        if self._mac is not None:
            return
        try:
            result = await self.async_get_settings(PROP_MAC_ADDR)
        except AsusWrtError:
            return
        self._mac = result.get(PROP_MAC_ADDR)

    async def async_get_uptime(self):
        """
        Return uptime of the router

        Format: {'since': 'Thu, 22 Jul 2021 14:32:38 +0200', 'uptime': '375001'}

        :returns: JSON with last boot time and uptime in seconds
        """
        r = await self.__post(f"{CMD_UPTIME}()")
        since = r.partition(":")[2].partition("(")[0]
        up = int(r.partition("(")[2].partition(" ")[0])
        return {"since": since, "uptime": up}

    async def async_get_memory_usage(self):
        """
        Return memory usage of the router

        Format: {'mem_total': 262144, 'mem_free': 107320, 'mem_used': 154824}

        :returns: JSON with memory variables
        """
        s = await self.__post(f"{CMD_MEMORY_USAGE}({PARAM_APPOBJ})")
        result = _get_json_result(s, CMD_MEMORY_USAGE)
        return {k: int(v) for k, v in result.items()}

    async def async_get_cpu_usage(self):
        """
        Return CPUs usage of the router

        Format: {'cpu1_total': 38106047, 'cpu1_usage': 3395512,
                 'cpu2_total': 38106008, 'cpu2_usage': 2384694, ...}

        :returns: JSON with CPUs load statistics
        """
        s = await self.__post(f"{CMD_CPU_USAGE}({PARAM_APPOBJ})")
        result = _get_json_result(s, CMD_CPU_USAGE)
        return {k: int(v) for k, v in result.items()}

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
        r = await self.__post(f"{CMD_WAN_INFO}()")
        status = {}
        for f in r.split("\n"):
            if "return" in f:
                if f"{CMD_WAN_INFO}_" in f:
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
        s = await self.__post(f"{CMD_DHCP_LEASE}()")
        return _get_json_result(s, CMD_DHCP_LEASE)

    async def async_get_traffic_bytes(self):
        """
        Get total amount of traffic since last restart (bytes format)

        Format: {'rx': 15901, 'tx': 10926}

        :returns: JSON with sent and received bytes since last boot
        """
        s = await self.__post(f"{CMD_NET_TRAFFIC}({PARAM_APPOBJ})")
        meas = _get_json_result(s, CMD_NET_TRAFFIC)
        traffic = None
        if "INTERNET_rx" in meas:
            traffic = "INTERNET"
        elif "BRIDGE_rx" in meas:
            traffic = "BRIDGE"

        if traffic:
            rx = int(meas[f"{traffic}_rx"], base=16)
            tx = int(meas[f"{traffic}_tx"], base=16)
        else:
            rx = tx = 0

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
        setting_list = [setting] if setting else NVRAM_INFO
        result = {}
        for s in setting_list:
            resp = await self.__post(_nvram_cmd(s))
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
        s = await self.__post(f"{CMD_CLIENT_LIST}()")
        result = _get_json_result(s)
        return [result.get(CMD_CLIENT_LIST, {})]

    async def async_get_connected_mac(self):
        """
        Obtain a list of MAC-addresses from online clients

        Format: ["00:00:00:00:00:00", ...]
        :returns: JSON list with MAC adresses
        """
        clnts = await self.async_get_clients_fullinfo()
        lst = [mac for mac, info in clnts[0].items() if len(mac) == 17 and info.get("isOnline", "0") == "1"]
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
                dev_list.append(Device(mac, info.get("ip"), name, info.get("amesh_papMac"), is_mesh_node, is_wl))

        result = {}
        for dev in dev_list:
            node_ip = mesh_nodes.get(dev.node) if dev.node else None
            result[dev.mac] = Device(dev.mac, dev.ip, dev.name, node_ip or self._hostname, dev.is_mesh_node, dev.is_wl)

        return result

    async def async_get_client_info(self, client_mac):
        """
        Get info on a single client

        :param client_mac: MAC address of the client requested
        :return: JSON with clientinfo (see async_get_clients_fullinfo() for description)
        """
        clnts = await self.async_get_clients_fullinfo()
        return clnts[0].get(client_mac)
