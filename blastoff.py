#!/usr/bin/env python3

"""
A guide on how to configure and run the 'blastoff' script for build automation.

Prerequisites:
    Ensure the paths of global variables in the script match your build directories.

Steps:
    1. Save this script in a directory where you intend to keep log files.

    2. Optionally, create a symlink to make 'blastoff' accessible from any location:
       Execute the following command, which may require sudo permissions:
       ln -s "$(pwd)/blastoff.py" /usr/local/bin/blastoff

    3. To set up the script initially, run the 'blastoff --setup' command. This will guide you through
       setting up SSH credentials for the appliances and the build server. For example:

           $ blastoff --setup
           You are now setting up ssh credentials for appliance #0
           Enter appliance name (or 'done' to finish): nori
           Enter IP address: 10.133.64.215
           Enter username: root
           Enter password:

           You are now setting up ssh credentials for appliance #1
           Enter appliance name (or 'done' to finish): done

           You are now setting up ssh credentials for your build server

           Enter build host address (e.g., opensores.us.oracle.com): opensores.us.oracle.com
           Enter your username for build host: your_username_here

       Note: The script currently supports key-based authentication for build machines only.

    4. After entering all necessary information, the script will save the data and be ready for use.

This docstring serves as a comprehensive guide to preparing and running the 'blastoff' script for
automating builds and deployments.

"""
"""
    Creates and returns an argparse parser for the 'Blastoff' utility.

    The 'Blastoff' utility streamlines the building and installing process of the 'fish' shell and associated
    source code on development machines, along with providing options for managing different configurations.

    Usage:
        blastoff [options]

    Options:
        -h, --help            Show this help message and exit.
        --setup               Prepare the environment for first-time use.
        -ss, --skip_src       Skip the compilation of the source code.
        -sf, --skip_fish      Skip the compilation of the fish shell.
        -fu, --fuweb          Perform the fuweb installation procedure.
        --fast                Perform the fuweb installation in fast mode, with reduced checks.
        -hs, --headers        Install the necessary header files.
        -r, --rig             Specify the rig identifier for targeted installation.
        --add_rig             Add a new rig configuration to the system.
        --show                Display the current configuration and status.

    Common Command Combinations:
        Initial Setup:
            blastoff --setup
            Sets up user data and configurations necessary for first-time use.

        Full Installation:
            blastoff --fuweb --headers
            Executes a full installation, including fuweb install and headers, without compiling source or fish.

        Skipping Compilation:
            blastoff --skip_src --skip_fish
            Runs the installation process but skips compilation steps.

        Fast Installation:
            blastoff --fuweb --fast
            Performs a fuweb installation quickly, with reduced checks.

        Installation on a Specific Rig:
            blastoff --fuweb -r DEV001
            Targets the fuweb installation to a specific rig, identified by 'DEV001'.

        Add a New Rig Configuration:
            blastoff --add_rig
            Initiates the process to add a new rig configuration to the system.

        Show Current Configuration:
            blastoff --show
            Outputs the current configuration and status of the utility.

    Returns:
        An instance of argparse.ArgumentParser configured for 'Blastoff'.
"""

import pdb
import sys
import select
import paramiko
import logging
import time
import argparse
import subprocess
import hashlib
from cryptography.fernet import Fernet
import getpass
import os
import pickle


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("logfile.log"),
        logging.StreamHandler()
    ])

USER_DATA_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "user_data.pkl")
KEY_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "key.key")

NFS_MOUNT_COMMAND = None
INSTALL_SCRIPT_COMMAND = None
INSTALL_FILENAME = "/install.ksh"
INSTALL_FILENAME_PATH = None
LOG_FILE_PATH = None
INSTALL_SOURCE_COMMAND = None
REBOOT_COMMAND = "confirm maintenance system reboot"


# Function to construct NFS mount command
def create_nfs_mount_command(build_host, build_location, gate_location):
    return f"confirm shell mkdir -p /tmp/on && mount -F nfs {build_host}:{build_location}/{gate_location} /tmp/on/"

# Other base strings
INSTALL_KSH = "confirm shell /tmp/on/sbin/./install.ksh"
FULIB_COMMAND = "confirm shell /usr/lib/ak/tools/fulib /tmp/on"
FUWEB_COMMAND = "confirm shell /usr/lib/ak/tools/fuweb -p /tmp/on/data/proto/fish-root_i386"
FUWEB_FAST_COMMAND = "confirm shell /usr/lib/ak/tools/fuweb -Ip /tmp/on/data/proto/fish-root_i386"
BUILD_BASE = "/export/ws"

def create_sbin_directory_path(build_location, gate_location):
    return f"{build_location}/{gate_location}/sbin"

BUILD_COMMANDS = [
    "pwd && cd usr/src/ && build here -Cid && echo $?",
    "pwd && cd usr/fish/ && build here -Cid && echo $?",
    "pwd && cd usr/src/ && build -iP make sgsheaders"
]

def create_log_file_path(build_location, gate_location):
    return f"{build_location}/{gate_location}/log.i386/here.log"

AWK_COMMANDS = ["awk", '/: error:/ {for(i=1; i<=5; i++) {print; if(!getline) exit}}']

# Function to construct and return the full command strings
def create_commands(build_host, build_location, gate_location):
    global NFS_MOUNT_COMMAND, INSTALL_SCRIPT_COMMAND, LOG_FILE_PATH, INSTALL_SOURCE_COMMAND, INSTALL_FILENAME_PATH
    NFS_MOUNT_COMMAND = create_nfs_mount_command(build_host, build_location, gate_location)
    sbin_directory = create_sbin_directory_path(build_location, gate_location)
    LOG_FILE_PATH = create_log_file_path(build_location, gate_location)
    INSTALL_FILENAME_PATH = build_location + '/' + gate_location + '/sbin' + INSTALL_FILENAME
    # Construct INSTALL_SCRIPT_COMMAND
    INSTALL_SCRIPT_COMMAND = f"confirm shell {sbin_directory}{INSTALL_FILENAME}"
    INSTALL_SOURCE_COMMAND = f"confirm shell /tmp/on/sbin/.{INSTALL_FILENAME}"


def write_key():
    """
    Generates a key and save it into a file
    """
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)


def load_key():
    """
    Loads the key named `key.key`
    """
    return open(KEY_FILE, "rb").read()


def setup_user_data(cipher_suite):
    rigs = {}

    banner("Application Setup")
    i = 0
    while True:
        print(f"\nYou are now setting up ssh credentials for appliance #{i}")

        name = input("Enter appliance name (or 'done' to finish): ")
        if name.lower() == 'done':
            break
        ip_address = input("Enter IP address: ")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        encrypted_password = cipher_suite.encrypt(password.encode())
        rigs[name] = (ip_address, username, encrypted_password)
        i += 1

    print("\nYou are now setting up ssh credentials for your build server")
    print("Note: script currently only works with keys for build machines.\n")

    host = input("Enter build host address (ex: opensores.us.oracle.com): ")
    # username = input("Enter username for build host: ")

    gate = input("\nEnter gate home on build host \n"
                 "Example: if your gate is located at /export/ws/username/on-gate,\n"
                 "then the gate home would be just 'on-gate': ")

    user_data = {'rigs': rigs, 'host': host, 'gate': gate}

    with open(USER_DATA_FILE, "wb") as f:
        pickle.dump(user_data, f)

    print("Data saved.")
    return user_data


def use_user_data(cipher_suite):
    banner("Confirming appliance info")
    try:
        with open(USER_DATA_FILE, "rb") as f:
            user_data = pickle.load(f)
    except (FileNotFoundError, IOError):
        print("Error: User data file not found.")
        return

    loaded_rigs_dict = user_data['rigs']

    rigs = {}
    for name, data in loaded_rigs_dict.items():
        ip_address, username, encrypted_password = data
        decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
        print(
            f"{name} IP Address: {ip_address}, Username: {username}")
        rigs[name] = (ip_address, username, decrypted_password)

    user_data['rigs'] = rigs

    return user_data


def add_rig_to_user_data(user_data, cipher_suite):
    name = input("Enter name: ")
    ip_address = input("Enter IP address: ")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    encrypted_password = cipher_suite.encrypt(password.encode())

    # Update the existing user data dictionary
    rigs = user_data.get('rigs', {})
    rigs[name] = (ip_address, username, encrypted_password)
    user_data['rigs'] = rigs

    with open(USER_DATA_FILE, "wb") as f:
        pickle.dump(user_data, f)

    print(f"Data for {name} added to the user data.")
    return user_data


class Commands:
    def __init__(self, retry_time=20, host=None, username=None, password=None):
        self.retry_time = retry_time
        self.host = host
        self.connected = False
        self.username = username
        self.password = password
        self.cmd_list = None
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def save(self):
        with open('data.pkl', 'wb') as f:
            pickle.dump(self, f)

    @classmethod
    def load(cls):
        with open('data.pkl', 'rb') as f:
            return pickle.load(f)

    def connect(self):
        for i in range(self.retry_time):
            logging.info("Trying to connect to %s (%i/%i) with %s", self.host, i + 1, self.retry_time, self.password)
            print(f"Trying to connect to {self.host} ({i + 1}/{self.retry_time})")

            try:
                self.ssh_client.connect(self.host, username=self.username, password=self.password)
                self.connected = True
                break
            except paramiko.AuthenticationException:
                logging.error("Authentication failed when connecting to %s with %s" % self.host, self.password)
                self.connected = False
                # sys.exit(1)
            except Exception as e:
                logging.error("Could not SSH to %s, waiting for it to start" % self.host)
                logging.error(f"Encountered the following error: {e}")
                logging.error("This is normal!! Do not exit. Continue to wait.")
                self.connected = False
                time.sleep(2 ** i)  # Exponential backoff

        if not self.connected:
            logging.error("Could not connect to %s. Giving up" % self.host)
            sys.exit(1)


    def run_cmd(self):
        logging.info(f"Run command on {self.host}.")
        output = None

        if not self.ensure_connection():
            logging.error(f"There is no connection to {self.host}.")
            return output

        for command in self.cmd_list:
            logging.info(f"{self.host}: {command}")
            stdin, stdout, stderr = self.ssh_client.exec_command(command, get_pty=True)
            while not stdout.channel.exit_status_ready():
                if stdout.channel.recv_ready():
                    rl, wl, xl = select.select([stdout.channel], [], [], 0.0)
                    if len(rl) > 0:
                        tmp = stdout.channel.recv(1024)
                        output = tmp.decode()
                        logging.info(f"{self.host}: {output}")

            time.sleep(3)
        return output

    def ensure_connection(self):
        logging.info(f"Ensure connection to {self.host}.")
        if not self.ssh_client.get_transport() or not self.ssh_client.get_transport().is_active():
            logging.info(f"No active transport available to {self.host}. Trying to connect...")
            self.connect()

        return self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active()

    def close_client(self):
        self.ssh_client.close()
        self.connected = False

    def reboot_rig(self):
        logging.info("Rebooting %s" % self.host)
        self.cmd_list = [REBOOT_COMMAND]
        self.run_cmd()

    def wait_for_rig_reboot(self, timeout=600, retry_interval=45, max_retries=20, log_callback=None):
        if log_callback is None:
            log_callback = logging.info

        log_callback("Waiting for reboot on %s" % self.host)
        reboot_start_time = time.time()
        time.sleep(60)  # Required for time to initiate reboot
        retries = 0
        while retries < max_retries:
            time_elapsed = time.time() - reboot_start_time
            if time_elapsed >= timeout:
                log_callback(f"{self.host}: Reboot timeout reached. Aborting.")
                break
            try:
                time.sleep(retry_interval)
                log_callback(f"Attempting to connect to {self.host}.")
                pwd_command = "confirm shell pwd"
                self.cmd_list = [pwd_command]
                self.run_cmd()
                log_callback(f"{self.host}: Reboot complete.")
                break
            except (paramiko.SSHException, paramiko.AuthenticationException) as e:
                retries += 1
                log_callback(f"{self.host}: Waiting for reboot. Exception: {str(e)}. Retrying...")
        else:
            log_callback(f"{self.host}: Maximum retries reached. Aborting.")

    def install_source(self):
        logging.info("%s: INSTALL SOURCE" % self.host)

        self.cmd_list = [NFS_MOUNT_COMMAND]
        self.run_cmd()
        self.cmd_list = [INSTALL_SOURCE_COMMAND]
        self.run_cmd()

    def install_fulib(self):
        logging.info("%s: INSTALL FISH" % self.host)
        self.cmd_list = [NFS_MOUNT_COMMAND]
        self.run_cmd()
        self.cmd_list = [FULIB_COMMAND]
        self.run_cmd()

    def install_fuweb(self, **kwargs):
        fast = kwargs.get('fast', False)
        logging.info("%s: INSTALL FUWEB" % self.host)
        self.cmd_list = [NFS_MOUNT_COMMAND]
        self.run_cmd()

        if fast:
            fuweb_cmd = FUWEB_FAST_COMMAND
        else:
            fuweb_cmd = FUWEB_COMMAND

        self.cmd_list = [fuweb_cmd]
        self.run_cmd()

    def create_install_file(self):
        logging.info("%s: CREATE INSTALL FILE" % self.host)
        try:
            sftp = self.ssh_client.open_sftp()
        except paramiko.ssh_exception.SSHException as e:
            # Handle SSHException, such as re-establishing SSH connection
            print("SSHException occurred:", str(e))
            time.sleep(5)  # Wait for a few seconds before retrying
            self.connect()
            self.ensure_connection()
            sftp = self.ssh_client.open_sftp()

        try:
            sftp.stat("/export/ws/bousborn/on-gate/sbin")
        except FileNotFoundError:
            sftp.mkdir("/export/ws/bousborn/on-gate/sbin")

        remote_file = sftp.file(INSTALL_FILENAME_PATH, 'w')
        remote_file.write("""ROOT=
BASE=/tmp/on
FBASE=$BASE
BLD=$BASE/data/build.i386/usr/src
FBLD=$FBASE/data/build.i386/usr/fish
AK=/usr/lib/ak

PYTHONDIRVP=python3.7

svcadm disable repld
svcadm disable -s akd

mount -o rw,remount /
cp $BLD/uts/intel/zfs/debug64/zfs     $ROOT/kernel/fs/amd64/ || exit 1
cp $BLD/uts/intel/zfs/debug64/zfs     $ROOT/kernel/drv/amd64/
cp $BLD/lib/libzfs/amd64/libzfs.so.1  $ROOT/lib/amd64/libzfs.so.1
cp $BLD/cmd/zfs/zfs                   $ROOT/usr/sbin/zfs
cp $BLD/cmd/ztest/amd64/ztest         $ROOT/usr/bin/ztest

cp $FBLD/lib/ak/libak/amd64/libak.so.1           $ROOT/$AK/amd64/libak.so.1
cp $FBLD/lib/ak/librepl/amd64/librepl.so.1       $ROOT/$AK/amd64/librepl.so.1
cp $FBLD/appliance/nas/modules/core/amd64/nas.so $ROOT/$AK/modules/appliance/nas/amd64/nas.so
mount -o ro,remount /

echo "copied
cp $BLD/uts/intel/zfs/debug64/zfs     $ROOT/kernel/fs/amd64/ || exit 1
cp $BLD/uts/intel/zfs/debug64/zfs     $ROOT/kernel/drv/amd64/
cp $BLD/lib/libzfs/amd64/libzfs.so.1  $ROOT/lib/amd64/libzfs.so.1
cp $BLD/cmd/zfs/zfs                   $ROOT/usr/sbin/zfs
cp $BLD/cmd/ztest/amd64/ztest         $ROOT/usr/bin/ztest

cp $FBLD/lib/ak/libak/amd64/libak.so.1           $ROOT/$AK/amd64/libak.so.1
cp $FBLD/lib/ak/librepl/amd64/librepl.so.1       $ROOT/$AK/amd64/librepl.so.1
cp $FBLD/appliance/nas/modules/core/amd64/nas.so $ROOT/$AK/modules/appliance/nas/amd64/nas.so
"

echo "Setting mountpoints... \c";
zfs set mountpoint=none system
bootadm update-archive
zfs set mountpoint=legacy system

echo "Restarting services... \c";
svcadm enable -s akd
svcadm enable repld
echo "Installation Complete. If kernel was installed, please restart machine...";""")
        remote_file.close()

        # Make the file executable
        stdin, stdout, stderr = self.ssh_client.exec_command("chmod +x " + INSTALL_FILENAME_PATH)
        sftp.close()

    def remove_install_file(self):
        logging.info("%s: REMOVE INSTALL FILE" % self.host)
        try:
            sftp = self.ssh_client.open_sftp()
        except paramiko.ssh_exception.SSHException as e:
            # Handle SSHException, such as re-establishing SSH connection
            print("SSHException occurred:", str(e))
            time.sleep(5)  # Wait for a few seconds before retrying
            self.connect()
            self.ensure_connection()
            sftp = self.ssh_client.open_sftp()

        try:
            sftp.stat(INSTALL_FILENAME_PATH)
            # File exists, so remove it
            sftp.remove(INSTALL_FILENAME_PATH)
            print("File removed successfully.")
        except FileNotFoundError:
            # File does not exist
            print("File does not exist.")

        sftp.close()

    def build_source(self):
        logging.info("%s: BUILD SOURCE" % self.host)
        self.cmd_list = [BUILD_COMMANDS[0]]
        ret = self.run_cmd()
        print(f"build source ret: {ret}")
        if ret.find("failed") != -1:
            print(f"build SOURCE ret false and print")
            self.print_here_log_errors()
            print(f"build SOURCE ret false")
            return False
        else:
            print(f"build SOURCE ret true")
            return True

    def build_fish(self):
        logging.info("%s: BUILD FISH" % self.host)
        self.cmd_list = [BUILD_COMMANDS[1]]
        ret = self.run_cmd()
        print(f"build FISH ret: {ret}")
        if ret.find("failed") != -1:
            print(f"build FISH ret false and print")
            self.print_here_log_errors()
            print(f"build FISH ret false")
            return False
        else:
            print(f"build FISH ret true")
            return True

    def install_headers(self):
        logging.info("%s: INSTALL HEADERS" % self.host)
        self.cmd_list = [BUILD_COMMANDS[2]]
        ret = self.run_cmd()
        # self.cmd_list = ["pwd && cd usr/src/ && make install_h"]
        # ret = self.run_cmd()
        print(f"install headers ret: {ret}")


    def print_here_log_errors(self):
        print(f"printing log errors!")
        if not self.ssh_client.get_transport():
            print("No transport available to %s." % self.host)
            self.connect()
        if self.ssh_client.get_transport():
            if not self.ssh_client.get_transport().is_active():
                print("Not connected to %s." % self.host)
                self.connect()
        sftp = self.ssh_client.open_sftp()
        with sftp.open(LOG_FILE_PATH, "r") as f:
            contents = f.read()
            decoded_contents = contents.decode()
            command = [AWK_COMMANDS[0], AWK_COMMANDS[1]]
            result = subprocess.run(command, input=decoded_contents, check=True, stdout=subprocess.PIPE,
                                    universal_newlines=True)
            print(f"print log results!")
            print(result.stdout)
            print(f"done print")


from concurrent.futures import ThreadPoolExecutor


def run_process(instances, method, **kwargs):
    with ThreadPoolExecutor() as executor:
        # Pass the extra parameters to the method
        results = executor.map(lambda instance: method(instance, **kwargs), instances)
    return list(results)


def create_parser():
    # Descriptive text for the program usage
    description_text = (
        'This utility program streamlines the process of building and installing '
        'the "fish" shell and associated "source" code on development machines.'
    )

    # Text to display after the argument help
    epilog_text = 'Execute "blastoff --setup" to configure the tool for initial use.'

    # Create the parser with the specified program description and epilog
    parser = argparse.ArgumentParser(description=description_text, epilog=epilog_text)

    # Define arguments with improved help descriptions
    parser.add_argument('-ss', '--skip_src', action='store_true',
        help='Skip the compilation of the source code.')
    parser.add_argument('-sf', '--skip_fish', action='store_true',
        help='Skip the compilation of the fish shell.')
    parser.add_argument('-fu', '--fuweb', action='store_true',
        help='Perform the fuweb installation procedure.')
    parser.add_argument('--fast', action='store_true',
        help='Perform the fuweb installation in fast mode, with reduced checks.')
    parser.add_argument('-r', '--rig', action='store', type=str,
        help='Specify the rig identifier for targeted installation.')
    parser.add_argument('-hs', '--headers', action='store_true',
        help='Install the necessary header files.')
    parser.add_argument("--setup", action='store_true',
        help="Prepare the environment for first-time use.")
    parser.add_argument("--add_rig", action='store_true',
        help="Add a new rig configuration to the system.")
    parser.add_argument("--show", action='store_true',
        help="Display the current configuration and status.")

    return parser


def banner(text):
    print('\n')
    print('*' * (len(text) + 4))
    print('* ' + text + ' *')
    print('*' * (len(text) + 4))
    print('\n')

write_key()
key = load_key()
cipher_suite = Fernet(key)

def main():

    parser = create_parser()
    args = parser.parse_args()

    user_data = None
    if args.setup:
        user_data = setup_user_data(cipher_suite)
        return
    else:
        user_data = use_user_data(cipher_suite)

    # Example user inputs (these would be obtained through user input in the actual script)
    build_host = user_data['host']
    build_location = BUILD_BASE + '/' + user_data['username']
    gate_location = user_data['gate']

    # Get and print the commands
    create_commands(build_host, build_location, gate_location)
    commands = [
        NFS_MOUNT_COMMAND,
        FULIB_COMMAND,
        FUWEB_COMMAND,
        INSTALL_SCRIPT_COMMAND,
        INSTALL_SOURCE_COMMAND,
        BUILD_COMMANDS[0],
        BUILD_COMMANDS[1],
        BUILD_COMMANDS[2],
        LOG_FILE_PATH,
        AWK_COMMANDS[0],
        AWK_COMMANDS[1]
    ]
    for command in commands:
        print(command)
    # Check for --fast without -f or --fuweb
    if args.fast and not args.fuweb:
        print(NFS_MOUNT_COMMAND)
        parser.error("--fast requires -fu or --fuweb")
    if args.add_rig:
        user_data = use_user_data(cipher_suite)
        if user_data is not None:
            user_data = add_rig_to_user_data(user_data, cipher_suite)

    if args.show:
        data = use_user_data(cipher_suite)
        if user_data is not None:
            for each in user_data:
                print(f"{each}\n")
        return

    banner("Setup Rigs")
    # rigs_dict = {
    #     "nori": ("nori", "root", "l1admin1"),
    #     "chutoro": ("chutoro", "root", "l1admin1")
    # }

    for rig_name in user_data['rigs']:
        print(rig_name)
    rigs_dict = user_data['rigs']
    # You can also access the 'host' and 'username' data like this:
    print("Host:", user_data['host'])
    print("Username:", user_data['username'])

    rigs = []
    if args.rig:
        if args.rig in rigs_dict:
            rig = rigs_dict[args.rig]
            commands_instance = Commands(host=rig[0], username=rig[1], password=rig[2])
            rigs.append(commands_instance)
    else:
        for rig in rigs_dict.values():
            commands_instance = Commands(host=rig[0], username=rig[1], password=rig[2])
            rigs.append(commands_instance)

    banner("Setup Sores Instance")
    sores = []
    sores_instance = Commands(host=user_data['host'], username=user_data['username'])
    sores.append(sores_instance)

    if args.headers:
        banner("Install Headers")
        headers_results = run_process(sores, Commands.install_headers)
        headers_results = headers_results[0]

    if not args.skip_src:
        banner("Build Source")
        print("main: did NOT skip build src")
        print("main: building source")
        build_results = run_process(sores, Commands.build_source)
        build_result = build_results[0]
        print(f"build SOURCE result: {build_result}")
        if build_result:
            print("main: completed build source")
            banner("Create Install Files")
            run_process(sores, Commands.create_install_file)
            print("main: completed create source install file")
        else:
            print("main: failed to build source")
            sys.exit(1)

    if not args.skip_fish:
        banner("Build Fish")
        print("main: did NOT skip build fish")
        print("main: building fish")
        build_results = run_process(sores, Commands.build_fish)
        build_result = build_results[0]
        if not build_result:
            print("main: Failed build source")
            sys.exit(1)
        print("main: completed build fish")


    if not args.skip_src:
        banner("Install Source")
        print("main: did NOT skip install src")
        print("main: installing source")
        run_process(rigs, Commands.install_source)
        print("main: completed install source")

    if not args.skip_fish:
        banner("Install fulib")
        print("main: enable fulib compile and install")
        run_process(rigs, Commands.install_fulib)
        print("main: completed fulib install")

    if args.fuweb:
        banner("Install fuweb")
        print("main: install fuweb")
        run_process(rigs, Commands.install_fuweb, fast=True)
        print("main: completed fuweb install")

    if not args.skip_src:
        banner("Remove Install File")
        run_process(sores, Commands.remove_install_file)

    # banner("Delete Sores Instance")
    # # Make sure I don't run following on sores
    # del sores_instance
    if not args.skip_src:
        # Reboot the rigs
        # for rig in rigs:
            # rig.reboot_rig()
        banner("Reboot for Source Install or fuweb")
        run_process(rigs, Commands.reboot_rig)

        print("main: finished rebooting rigs")

        banner("Wait for Reboot")
        # Wait for the rigs to reboot
        run_process(rigs, Commands.wait_for_rig_reboot)
        # for rig in rigs:
            # rig.wait_for_rig_reboot()

        print("main: finished waiting for reboot on rigs")


    banner("Process Complete.")
    print("main: FULL PROCESS COMPLETE")


if __name__ == '__main__':
    main()
