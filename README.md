## PyAsusWrt

**PyAsusWrt** is a small API wrapper written in python for communication with ASUSWRT-powered routers using the 
HTTP or HTTPS protocols.

It is based on Asynchronous HTTP Client [AioHTTP](https://docs.aiohttp.org/en/stable/).

It was mainly developed to be used with HomeAssistant AsusWRT integration as an alternative to the excellent library 
currently in use [AIOAsusWrt](https://github.com/kennedyshead/aioasuswrt). The purpose of this library is not to replace 
AIOAsusWrt (which uses the `SSH` and `Telnet` protocols) but to work alongside it to allow also the use the HTTP(s) protocols, 
so you can choose the best solution according to your model of router.

Of course, you can use this library for any other purpose, respecting the open source license to which this library is licensed.

### Note

Pull Request to HA integration is under development and will be available **when and if** it will be approved by HA teams.

If you cannot wait for the completion of the PR, it is possible to replace the native HA integration with 
[this custom integration](https://github.com/ollo69/ha_asuswrt_custom) that already contains support for this new library.
This custom integration is based on the native one and is to be considered for test purpose only.


## Installation

Installation of the latest release is available from PyPI:

```
pip install pyasuswrt
```

## How open issue and run tests
There are many versions of `asuswrt` firmware, sometimes they just don't work in current implementation.
If you have a problem with your specific router open an issue on this repository, but please add as much info as you can and 
at least:

* Model and version of router
* Version of Asuswrt

If possible before open issue run a test on your environment, using the code inside the module `test.py` (you must set
right login credential inside the module before running it) and then provide the error log printed by the test.

To run the test:

```
python test.py
```

## Be nice!
If you like the library, why don't you support me by buying me a coffee?
It would certainly motivate me to further improve this work.

[![Buy me a coffee!](https://www.buymeacoffee.com/assets/img/custom_images/black_img.png)](https://www.buymeacoffee.com/ollo69)
