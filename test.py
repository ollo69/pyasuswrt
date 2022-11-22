"""Test for PyAsusWrt."""

import asyncio
from datetime import datetime
import logging

import sys

from pyasuswrt import AsusWrtHttp, AsusWrtError

NUM_LOOP = 1

component = AsusWrtHttp("192.168.10.1", "admin", "****", use_https=False)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)


async def print_data():
    for i in range(NUM_LOOP):
        try:
            logger.debug("Starting loop at: %s", datetime.now())
            logger.debug("await async_get_settings()")
            dev = await component.async_get_settings()
            logger.debug(dev)
            logger.debug("await async_get_clients_fullinfo()")
            dev = await component.async_get_clients_fullinfo()
            logger.debug(dev)
            logger.debug("await async_get_connected_devices()")
            dev = await component.async_get_connected_devices()
            logger.debug(dev)
            logger.debug("await async_get_memory_usage()")
            dev = await component.async_get_memory_usage()
            logger.debug(dev)
            logger.debug("await async_get_cpu_usage()")
            dev = await component.async_get_cpu_usage()
            logger.debug(dev)
            logger.debug("await async_get_traffic_bytes()")
            dev = await component.async_get_traffic_bytes()
            logger.debug(dev)
            logger.debug("await async_get_uptime()")
            dev = await component.async_get_uptime()
            logger.debug(dev)
            logger.debug("await async_get_wan_info()")
            dev = await component.async_get_wan_info()
            logger.debug(dev)
        except AsusWrtError as ex:
            logger.exception("Time: %s, Error: %s", datetime.now(), ex)
        if i < NUM_LOOP - 1:
            await asyncio.sleep(10)

    await component.async_disconnect()


loop = asyncio.get_event_loop()

loop.run_until_complete(print_data())
