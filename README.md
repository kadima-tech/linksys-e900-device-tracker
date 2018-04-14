# Linksys E900 Device Tracker for Home Assistant

This module is a device tracker for Home Assistant. It allows users of the Linksys E900 router to
enable presence detection in Home Assistant.

## Setup

1. Clone this repository to your local machine.
2. Copy the file named ***linksyse900.py*** to ***/config/custom_components/device_tracker/*** on your Home Assistant Samba/SSH share. If the folder does not exist, create it.
3. Configure the module with the credentials as listed below.
4. Reboot Home Assistant. A new file called ***known_devices.yaml*** will be created in your /config directory. This will contain all known devices.

## Configuration

As mentioned in step 3 of the setup, the module needs to be configured for your router before anything happens. Open ***/config/configuration.yaml*** and add the following to the bottom of the file:

```yaml
device_tracker:
  - platform: linksyse900
    host: <IP OF ROUTER>
    username: admin
    password: <PASSWORD>
    track_new_devices: no
```

## Contributing

Please read [CONTRIBUTING.md](https://github.com/kadima-tech/experia-v10-device-tracker/blob/master/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/kadima-tech/linksys-e900-device-tracker/tags).

## Authors

* **Sjaak Meulen** - *Migration from Experia v10 to Linksys E900* - [sjaakiejj](https://github.com/sjaakiejj)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments
Credit where credit is due. A big thanks to:

* [Mark van den Berg](https://community.home-assistant.io/t/device-tracker-for-arcadyan-vgv7519-router-experia-box-v8/29362) for sharing the Experia Box V8 script upon which this script was built.
