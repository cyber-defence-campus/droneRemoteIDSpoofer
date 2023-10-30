# Drone Remote ID Spoofer
This python scripts allows to spoof drone Remote IDs via Wifi . It supports the ASD-STAN format which is used for example by Parrot drones. It can spoof a single drone or multiple drones, randomly or in a specific area. 

**Disclaimer**: This repository was created by students as part of a thesis. It is not meant to be maintained nor updated. It is a proof of concept and is not intended for production use. The authors do not take any responsibility or liability for the use of the software. Please exercise caution and use at your own risk.

**Note:** A [drone monitoring system](https://github.com/cyber-defence-campus/RemoteIDReceiver) based on Remote IDs was also developed and is is published in another repository. The spoofed Remote IDs can be  can be used to test the drone monitoring system.

## Authors
The work in this project was  done by:
- [Fabia Müller](https://github.com/alessmlr), Zurich University of Applied Sciences
- [Sebastian Brunner](https://github.com/Wernerson),Zurich University of Applied Sciences
- [Llorenç Romá](https://github.com/llorencroma),  Cyber-Defence Campus

and supervised by:
- [Prof. Dr. Marc Rennhard](https://github.com/rennhard),  Zurich University of Applied Sciences
- [Llorenç Romá](https://github.com/llorencroma),  Cyber-Defence Campus

## Usage
### Requirements
- the spoofer uses `scapy` to broadcast 802.11 packets, which requires root privileges
- an 802.11 WiFi adapter capable of injecting traffic is required e.g., EDIMAX EW-7811Un Wi-Fi adapter

### Set up interface in monitor mode
First, you need to know the interface's name. Run the following command and copy the name of the interface to be used for transmiting:

`$ ip a` 

Second: 

`$ sudo ./interface-monitor.sh <interface-name>`

### 1. Spoof a single Remote ID
A single Remote ID with random values will be sent.

`$ sudo python3 ./spoof_drones.py -i <interface-name> `

### 2. Spoof multiple Remote IDs
With that feature, `m` Remote IDs are spoofed. Parameters cannot be controlled. The drones will be spoofed at fixed random position.

`$ sudo python3 ./spoof_drones.py -i <interface-name> -r <m>`

### 3. Spoof multiple Remote IDs around a specific location
With that feature, `m` Remote IDs are spoofed around the specified coordinates. The drones will be spoofed at fixed random position around the specified coordinates.

`$ sudo python3 ./spoof_drones.py -i <interface-name> -r <m> -l '<latitude> <longitude>'`



### Script Flags:

The script can be customized with the following parameters.

| Flag short | Flag extended | Parameter                  | Default                                           | Description                                    |
|------------|---------------|----------------------------|---------------------------------------------------|------------------------------------------------|
| `-h`       | `--help`      | -                          | -                                                 | Displays help message                          |
| `-i`       | `--interface` | `n`: str                   | wlx00c0ca99160d                                   | Interface name                                 |
| `-m`       | `--manual`    | -                          | -                                                 | Spoof one drone and control its movement       |
| `-r`       | `--random`    | `m`: int                   | 1                                                 | Spoof `m` drones that move automatically       |
| `-n`       | `--seconds`   | `s`: int                   | 3                                                 | Time between sending packets                   |
| `-l`       | `--location`  | `lat`: int <br> `lng`: int | 47.3763399, 8.5312562 <br/> Kasernenareal, Zurich | Latitude and Longitude of drone starting point |

