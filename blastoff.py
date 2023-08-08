#!/usr/bin/env python3

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

    while True:
        name = input("Enter name (or 'done' to finish): ")
        if name.lower() == 'done':
            break
        ip_address = input("Enter IP address: ")
        username = input("Enter username: ")
        password = getpass.getpass("Enter password: ")
        encrypted_password = cipher_suite.encrypt(password.encode())
        rigs[name] = (ip_address, username, encrypted_password)

    host = input("Enter build host address (ex: opensores.us.oracle.com): ")
    username = input("Enter username for build host: ")

    user_data = {'rigs': rigs, 'host': host, 'username': username}

    with open(USER_DATA_FILE, "wb") as f:
        pickle.dump(user_data, f)

    print("Data saved.")
    return user_data


def use_user_data(cipher_suite):
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
            f"Access granted for {name} with IP Address: {ip_address}, Username: {username}, and Password: {decrypted_password}")
        rigs[name] = (ip_address, username, decrypted_password)

    user_data['rigs'] = rigs

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
        reboot_command = "confirm maintenance system reboot"
        self.cmd_list = [reboot_command]
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
        logging.info("%s: INSTALL SOURCE pass" % self.password)

        self.cmd_list = ["confirm shell mkdir -p /tmp/on && mount -F nfs opensores.us.oracle.com:/export/ws/bousborn/on-gate /tmp/on/"]
        self.run_cmd()
        self.cmd_list = ["confirm shell /tmp/on/sbin/./install.ksh"]
        self.run_cmd()

    def install_fulib(self):
        logging.info("%s: INSTALL FISH" % self.host)
        self.cmd_list = ["confirm shell mkdir -p /tmp/on && mount -F nfs opensores.us.oracle.com:/export/ws/bousborn/on-gate /tmp/on/"]
        self.run_cmd()
        self.cmd_list = ["confirm shell /usr/lib/ak/tools/fulib /tmp/on"]
        self.run_cmd()

    def install_fuweb(self):
        logging.info("%s: INSTALL FUWEB" % self.host)
        self.cmd_list = ["confirm shell mkdir -p /tmp/on && mount -F nfs opensores.us.oracle.com:/export/ws/bousborn/on-gate /tmp/on/"]
        self.run_cmd()
        # if fast:
        #     self.cmd_list = ["confirm shell /usr/lib/ak/tools/fuweb -Ip /tmp/on/data/proto/fish-root_i386"]
        # else:
        #     self.cmd_list = ["confirm shell /usr/lib/ak/tools/fuweb -p /tmp/on/data/proto/fish-root_i386"]
        self.cmd_list = ["confirm shell /usr/lib/ak/tools/fuweb -p /tmp/on/data/proto/fish-root_i386"]
        self.run_cmd()
        # self.cmd_list = ["confirm shell svcadm restart -s akd"]
        # self.run_cmd()

    def create_install_file(self):
        logging.info("%s: CREATE INSTALL FILE" % self.host)
        # self.host = "opensores.us.oracle.com"
        # self.username = "bousborn"
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

        remote_filename = "/export/ws/bousborn/on-gate/sbin/install.ksh"
        remote_file = sftp.file(remote_filename, 'w')
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
        stdin, stdout, stderr = self.ssh_client.exec_command("chmod +x /export/ws/bousborn/on-gate/sbin/install.ksh")
        sftp.close()

    def remove_install_file(self):
        logging.info("%s: REMOVE INSTALL FILE" % self.host)
        # self.host = "opensores.us.oracle.com"
        # self.username = "bousborn"
        try:
            sftp = self.ssh_client.open_sftp()
        except paramiko.ssh_exception.SSHException as e:
            # Handle SSHException, such as re-establishing SSH connection
            print("SSHException occurred:", str(e))
            time.sleep(5)  # Wait for a few seconds before retrying
            self.connect()
            self.ensure_connection()
            sftp = self.ssh_client.open_sftp()

        remote_filename = "/export/ws/bousborn/on-gate/sbin/install.ksh"
        try:
            sftp.stat(remote_filename)
            # File exists, so remove it
            sftp.remove(remote_filename)
            print("File removed successfully.")
        except FileNotFoundError:
            # File does not exist
            print("File does not exist.")

        sftp.close()

    def build_source(self):
        logging.info("%s: BUILD SOURCE" % self.host)
        # self.host = "opensores.us.oracle.com"
        # self.username = "bousborn"
        self.cmd_list = ["pwd && cd usr/src/ && build here -Cid && echo $?"]
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
        # self.host = "opensores.us.oracle.com"
        # self.username = "bousborn"
        self.cmd_list = ["pwd && cd usr/fish/ && build here -Cid && echo $?"]
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
        self.cmd_list = ["pwd && cd usr/src/ && build -iP make sgsheaders"]
        ret = self.run_cmd()
        # self.cmd_list = ["pwd && cd usr/src/ && make install_h"]
        # ret = self.run_cmd()
        print(f"install headers ret: {ret}")


    def print_here_log_errors(self):
        # self.host = "opensores.us.oracle.com"
        # self.username = "bousborn"
        print(f"printing log errors!")
        if not self.ssh_client.get_transport():
            print("No transport available to %s." % self.host)
            self.connect()
        if self.ssh_client.get_transport():
            if not self.ssh_client.get_transport().is_active():
                print("Not connected to %s." % self.host)
                self.connect()
        sftp = self.ssh_client.open_sftp()
        with sftp.open("/export/ws/bousborn/on-gate/log.i386/here.log", "r") as f:
            contents = f.read()
            decoded_contents = contents.decode()
            command = ["awk", '/: error:/ {for(i=1; i<=5; i++) {print; if(!getline) exit}}']
            result = subprocess.run(command, input=decoded_contents, check=True, stdout=subprocess.PIPE,
                                    universal_newlines=True)
            print(f"print log results!")
            print(result.stdout)
            print(f"done print")

    def rig_test(self):
        self.cmd_list = [
            'shares select prj20 replication select action-000 sendestimate',
            'shares select prj20 replication select action-001 sendestimate',
            'shares select prj1 replication select action-002 sendestimate'
        ]
        self.run_cmd()


from concurrent.futures import ThreadPoolExecutor


def run_process(instances, method):
    with ThreadPoolExecutor() as executor:
        results = executor.map(method, instances)
    return list(results)


def create_parser():
    desc = 'This program facilitates in helping build both fish and source, ' \
           'as well as installing it on developer rigs.'
    parser = argparse.ArgumentParser(description=desc,
                                     epilog='run "blastoff --setup" to set it up for the first time.')
    # parser.add_argument('-u', '--fulib', action='store_true',
    #                     help='enable fulib compile and install')
    parser.add_argument('-ss', '--skip_src', action='store_true',
                        help='skip source compile')
    parser.add_argument('-sf', '--skip_fish', action='store_true',
                        help='skip fish compile')
    parser.add_argument('-f', '--fuweb', action='store_true',
                        help='do fuweb install')
    parser.add_argument('--fast', action='store_true', help='do fuweb install quickly')
    parser.add_argument('-r', '--rig', action='store', type=str, help='store a value for rig')
    parser.add_argument('-hs', '--headers', action='store_true', help='install headers')
    parser.add_argument("--setup", help="Set to True to setup user data", action='store_true')

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

    banner("Pickle Setup")


    parser = create_parser()
    args = parser.parse_args()

    banner("Pickle Setup")
    if args.setup:
        user_data = setup_user_data(cipher_suite)
    user_data = use_user_data(cipher_suite)

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
        run_process(rigs, Commands.install_fuweb)
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

        # Run rig test
        # run_process(rigs, Commands.rig_test)

        print("main: finished running rig test")

    banner("Process Complete.")
    print("main: FULL PROCESS COMPLETE")


if __name__ == '__main__':
    main()
