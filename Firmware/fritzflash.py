#! /usr/bin/env python3
import argparse
import ipaddress
import os
import socket
import time
from ftplib import FTP

AUTODISCOVER_TIMEOUT = 1
FTP_TIMEOUT = 2
FTP_MAX_RETRY = 10


class FritzFTP(FTP):
    class ConnectionTimeout(Exception):
        pass

    def __init__(self, ip, username='adam2', password='adam2', timeout=1, max_retry=0, retry_cb=None):
        i = 1
        while i <= max_retry:
            try:
                retry_cb(i, max_retry)
                super().__init__(ip, user=username, passwd=password, timeout=timeout)
                break
            except socket.timeout:
                i += 1
            except OSError as e:
                time.sleep(1)
                i += 1
        if i > max_retry:
            raise FritzFTP.ConnectionTimeout()
        self.set_pasv(True)

    def getenv(self):
        env = [b'']
        fritzenv = {}

        def storeenv(x):
            env[0] += x

        self.voidcmd('MEDIA SDRAM')
        try:
            self.retrbinary('RETR env', storeenv)
        except socket.timeout:
            pass

        for line in env[0].decode('ascii').splitlines():
            l = line.split()
            fritzenv[l[0]] = l[1]

        return fritzenv

    def set_flash_timeout(self):
        self.sock.settimeout(60 * 5)

    def upload_image(self, image):
        self.set_flash_timeout()
        self.voidcmd('MEDIA FLSH')
        self.storbinary('STOR mtd1', image)

    def reboot(self):
        self.voidcmd('REBOOT')
        self.close()


def connection_refused_message():
    print("\nIt seems you have a booted-up AVM device running in your Network.\n"
          "This might be because you missed the 10 second window after powering on your AVM device.\n"
          "In this case: Powercycle your device and retry.\n"
          "If this problem persits, check if you might have connections to another AVM device, e.g. via WiFi/WLAN.\n\n")


def start_message(ip_address):
    print(
        "This program will help you installing Gluon, a widely used Firmware for Freifunk networks, onto your AVM device.\n"
        "You can always find the most current version of this script at https://www.github.com/freifunk-darmstadt/fritz-tools\n\n"
        "It is strongly recommended to only connect your computer to the device you want to flash.\n"
        "Try to disable all other connections (Ethernet, WiFi/WLAN, VMs) if detection fails.\n\n"
        "Sometimes an unmanaged switch between your AVM device and your computer is helpfull.\n\n"
        "Before we start, make sure you have assigned your PC a static IP Address in the Subnet of the device you want to flash.\n"
        "The following example would be a completely fine option:\n")
    print("IP-Address: %s" % str(ipaddress.ip_address(ip_address) + 1))
    print("Subnet: 255.255.255.0")
    print("Gateway: %s" % str(ipaddress.ip_address(ip_address)))
    print("DNS Servers: Leave blank\n")
    print("Once you're ready to flash, press enter, disconnect power from your AVM device and reconnect the power-supply.")


def connect_message():
    print("We will now connect to your devices bootloader.")


def flash_message():
    print("\nWriting Gluon image to your AVM device...\n"
          "This process may take a lot of time.\n\n"
          "First, the device will erase its current Operating System.\n"
          "Next, the device will write the Gluon image to its memory.\n"
          "The red Info LED will illuminate in this step. Don't worry, this is expected behavior.\n\n"
          "Do *not* turn off the device!\n\n"
          "We will tell you when your device has finished installing Gluon (this may take a while).")


def finish_message():
    print("\n== Congratulations! ==\n\n"
          "Your device is now running Gluon.\n"
          "It will restart and in 2-5 minutes you will be able to visit its config-mode.\n"
          "Remember to reconfigure your interface to automatically obtain an IP-address!\n"
          "You can reach config-mode by typing in http://192.168.1.1/ in your preferred Webbrowser.\n")
    print("Press any key to exit.")
    input()


def retry_status(current_try, max_try):
    print("--> Try %d of %d" % (current_try, max_try))


def autodiscover_avm_ip():
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sender.bind(('192.168.178.2', 0))
    except OSError as e:
        if e.errno == 99:
            print('\rIP address 192.168.178.2 is not configured on any interface.')
            exit(1)
        else:
            raise e from None
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sender.settimeout(1)

    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.settimeout(AUTODISCOVER_TIMEOUT)
    receiver.bind(('192.168.178.2', 5035))

    i = 1
    while True:
        try:
            print("\rTry %d..." % i, end='')
            receiver.sendto(b'aa', ("192.168.178.1", 5035))  # Dirty hack to add conntrack entry
            sender.sendto(bytearray.fromhex("0000120101000000c0a8b20100000000"), ('255.255.255.255', 5035))
            while 1:
                data, addr = receiver.recvfrom(64)
                if addr[0] == '192.168.178.1':
                    print("\rFritzBox found at %s" % addr[0])
                    return addr[0]
        except socket.timeout:
            i += 1
        except OSError:
            i += 1
            time.sleep(0.1)
        except KeyboardInterrupt:
            print('\rAborting...\n')
            return None

    return None


def determine_image_name(env_string):
    models = {
        "172": {
            "gluon": [
                "avm-fritz-box-7320-sysupgrade.bin"
            ],
            "openwrt": [
                "avm-fritz7320-squashfs-sysupgrade.bin"
            ],
        },
        "173": {
            "gluon": [
                "avm-fritz-wlan-repeater-300e-sysupgrade.bin"
            ],
            "openwrt": [
                "fritz300e-squashfs-sysupgrade.bin"
            ],
        },
        "179": {
            "gluon": [
                "avm-fritz-box-7330-sysupgrade.bin"
            ],
            "openwrt": [
                "avm-fritz7320-squashfs-sysupgrade.bin"
            ],
        },
        "181": {
            "gluon": [
                "avm-fritz-box-7360-sl-sysupgrade.bin"
            ],
            "openwrt": [
                "avm-fritz7360sl-squashfs-sysupgrade.bin"
            ],
        },
        "183": {
            "gluon": [
                "avm-fritz-box-7360-v1-sysupgrade.bin"
            ],
            "openwrt": [
                "avm-fritz7360sl-squashfs-sysupgrade.bin"
            ],
        },
        "188": {
            "gluon": [
                "avm-fritz-box-7330-sl-sysupgrade.bin"
            ],
            "openwrt": [
                "avm-fritz7320-squashfs-sysupgrade.bin"
            ],
        },
        "189": {
            "gluon": [
                "avm-fritz-box-7312-sysupgrade.bin"
            ],
            "openwrt": [
                "avm-fritz7312-squashfs-sysupgrade.bin"
            ],
        },
        "196": {
            "gluon": [
                "avm-fritz-box-7360-v2-sysupgrade.bin"
            ],
            "openwrt": [
                "avm-fritz7360sl-squashfs-sysupgrade.bin"
            ],
        },
        "200": {
            "gluon": [
                "avm-fritz-wlan-repeater-450e-sysupgrade.bin"
            ],
            "openwrt": [
                "fritz450e-squashfs-sysupgrade.bin"
            ]
        },
        "219": {
            "gluon": [
                "avm-fritz-box-4020-sysupgrade.bin"
            ],
            "openwrt": [
                "fritz4020-squashfs-sysupgrade.bin",
                "avm-fritz4020-squashfs-sysupgrade.bin"
            ]
        },
        "227": {
            "gluon": [
                "avm-fritz-box-4040-bootloader.bin"
            ],
            "openwrt": [
                "avm-fritzbox-4040-squashfs-eva.bin"
            ]
        }
    }
    for model in models.keys():
        if model == env_string:
            image_names = []
            print("\nModels")
            if "gluon" in models[model]:
                image_names += models[model]["gluon"]
            if "openwrt" in models[model]:
                image_names += models[model]["openwrt"]
            return image_names
    return None


def autoload_image(ip):
    print("\nStarting automatic image-selection!")
    print("-> Establishing connection to device!")

    try:
        ftp = FritzFTP(ip, timeout=FTP_TIMEOUT, max_retry=FTP_MAX_RETRY, retry_cb=retry_status)
    except FritzFTP.ConnectionTimeout:
        print("-> Max retrys exceeded! Check connection and try again.")
        exit(1)
    except ConnectionRefusedError:
        connection_refused_message()
        exit(1)

    env = ftp.getenv()
    ftp.close()

    if 'HWRevision' not in env:
        print("\nAutomatic image-selection unsuccessful!")
        print("-> No model saved on device!")
        print("\n HWRevision")
        exit(1)

    image_names = determine_image_name(env["HWRevision"])

    if image_names is None:
        print("\nAutomatic image-selection unsuccessful!")
        print("-> Unknown Model %s!" % env["HWRevision"])
        print("Press any key to exit.")
        input()
        exit(1)

    file_name = os.path.abspath(__file__)
    new_dir = os.path.dirname(file_name)
    # print(file_name) 
    # print(new_dir)
    # print(os.getcwd())
    os.chdir(new_dir)
    dir_content = os.listdir(os.getcwd())
    files = []
    for file in dir_content:
        cwd = os.getcwd()
        file = os.path.join(cwd, file)
        if not os.path.isfile(file):
            continue
        for image_name in image_names:
            if image_name in file:
                files.append(file)

    if len(files) > 1:
        print("\nAutomatic image-selection unsuccessful!")
        print("-> Multiple potential image files found!")
        for file in files:
            print("--> %s" % file)
        print("\nPlease specify the image via `--image` parameter.")
        print("Press any key to exit.")
        input()
        exit(1)

    if not files:
        print("\nAutomatic image-selection unsuccessful!")
        print("--> No potential image file found!")
        print("\nPlease download and specify the image via `--image` parameter.")
        print("Press any key to exit.")
        input()
        exit(1)

    print("-> Automatic image-selection successful!")
    print("--> Will flash %s" % files[0])

    return open(files[0], 'rb')


def perform_flash(ip, file):
    print("-> Establishing connection to device!")

    try:
        ftp = FritzFTP(ip, timeout=FTP_TIMEOUT, max_retry=FTP_MAX_RETRY, retry_cb=retry_status)
    except FritzFTP.ConnectionTimeout:
        print("-> Max retries exceeded! Check connection and try again.")
        print("Press any key to exit.")
        input()
        exit(1)
    except ConnectionRefusedError:
        connection_refused_message()
        print("Press any key to exit.")
        input()
        exit(1)

    print("-> Flash image")
    flash_message()
    ftp.upload_image(file)
    print("-> Image write successful")
    print("-> Performing reboot")
    ftp.reboot()
    finish_message()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Flash Gluon image to AVM devices using EVA.')
    parser.add_argument('--ip', type=str, help='IP Address of device. Autodiscovery if not specified.')
    parser.add_argument('--image', type=str, help='Image file to transfer.')
    args = parser.parse_args()

    imagefile = None

    if args.ip:
        try:
            socket.inet_aton(args.ip)
        except socket.error:
            print("%s is not a valid IPv4 address!" % args.ip_address)
            exit(1)

    if args.image:
        try:
            imagefile = open(args.image, 'rb')
        except FileNotFoundError:
            print("Image file \"%s\" does not exist!" % os.path.abspath(args.image_path))
            exit(1)

    start_message("192.168.178.1")
    input()

    ip = args.ip
    if ip is None:
        print("Trying to autodiscover! Abort via Ctrl-c.")
        ip = autodiscover_avm_ip()

        if ip is None:
            print("\nAutodiscovery failed!")
            print("Press any key to exit.")
            input()
            exit(1)

        print("\nAutodiscovery succesful!")
        print("-> Device detected at %s." % ip)

    if args.image is None:
        # Try to automatically locate an image to use
        imagefile = autoload_image(ip)

    perform_flash(ip, imagefile)
