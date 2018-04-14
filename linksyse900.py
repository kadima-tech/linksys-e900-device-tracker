"""
Support for Linksys E900 router.
"""
import base64
import hashlib
import logging
import re
from datetime import datetime, timezone

import requests
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_USERNAME): cv.string
})


def get_scanner(hass, config):
    """Validate the configuration and return a Linksys E900 scanner."""
    try:
        return LinksysE900DeviceScanner(config[DOMAIN])
    except ConnectionError:
        return None


class LinksysE900DeviceScanner(DeviceScanner):
    """This class queries a wireless router running Linksys firmware."""

    def __init__(self, config):
        """Initialize the scanner."""
        host = config[CONF_HOST]
        username, password = config[CONF_USERNAME], config[CONF_PASSWORD]

        self.parse_macs = re.compile('[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}\:[0-9A-Fa-f]{2}')

        self.host = host
        self.username = username
        self.password = self.encode_password(password)

        self.last_results = {}
        self.success_init = self._update_info()

    def get_session_id(self, response):
        """Linksys returns an HTML body with the session id in it - parse it and return"""
        string_to_match = "index.asp;session_id="
        session_id_start = response.find(string_to_match) + len(string_to_match)
        session_id_end   = response.find("\"", session_id_start)
        return response[session_id_start:session_id_end]

    def encode_password(self, password):
        pseed2 = ""
        buffer1 = password
        length2 = len(password)

        if length2 < 10:
            buffer1 += "0"

        buffer1 += str(length2)
        length2 += 2

        for p in range(64):
            tempCount = p % length2
            pseed2 += buffer1[tempCount:tempCount+1]

        return hashlib.md5(pseed2.encode('utf-8')).hexdigest()


    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return self.last_results

    # pylint: disable=no-self-use
    def get_device_name(self, device):
        """Get firmware doesn't save the name of the wireless device."""
        return None

    def _update_info(self):
        """Ensure the information from the Linksys router is up to date.
        Return boolean if scanning successful.
        """
        _LOGGER.info("Loading wireless clients...")

        login_payload = {
            "http_username": self.username,
            "http_passwd": self.password,
            "action": "Apply",
            "change_action": "",
            "submit_type": "",
            "submit_button": "login"
        }

        login_url = 'http://{}/login.cgi'.format(self.host)

        # Login to get a session
        login_response = requests.post(login_url, data = login_payload)

        # Extract the session id
        session_id = self.get_session_id(login_response.text)

        # Contruct the data url with the session id
        data_url = 'http://{}/WL_ClientList.asp;session_id={}'.format(self.host, session_id)

        # Get the data
        data_page = requests.get(data_url)
        result = self.parse_macs.findall(data_page.text)

        # Logging off is unnecessary, as the session expires in a few minutes

        if result:
            self.last_results = result
            return True

        return False
