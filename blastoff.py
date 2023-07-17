#!/usr/bin/env python3

import pdb
import sys
import select
import paramiko
import logging
from logging.handlers import QueueHandler, RotatingFileHandler
import time
import multiprocessing
import argparse
import subprocess

from queue import Queue

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("logfile.log"),
        logging.StreamHandler()
    ])

class Commands:
    def __init__(self, retry_time=10, host=None, username=None, password=None):
        self.retry_time = retry_time
        self.host = host
        self.connected = False
        self.username = username
        self.password = password
        self.cmd_list = None
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        i = 0
        logging.info("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
        print(f"Trying to connect to {self.host} ({i}/{self.retry_time})")
        while True:
            logging.info("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
            try:
                self.ssh_client.connect(self.host, username=self.username, password=self.password)
                self.connected = True
                break
            except paramiko.AuthenticationException:
                logging.info("Authentication failed when connecting to %s" % self.host)
                self.connected = False
                sys.exit(1)
            except:
                logging.info("Could not SSH to %s, waiting for it to start" % self.host)
                self.connected = False
                i += 1
                time.sleep(2)

            # If we could not connect within time limit
            if i >= self.retry_time:
                logging.info("Could not connect to %s. Giving up" % self.host)
                self.connected = False
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

    def wait_for_rig_reboot(self, timeout=600, retry_interval=30, max_retries=5, log_callback=None):
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
        self.cmd_list = ["confirm shell /usr/lib/ak/tools/fuweb -p /tmp/on/data/proto/fish-root_i386"]
        self.run_cmd()
        self.cmd_list = ["confirm shell svcadm restart -s akd"]
        self.run_cmd()

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


# class SSHController:
#     def __init__(self, host, user, key, retry_time=10):
#         self.host = host
#         self.user = user
#         self.key = key
#         self.retry_time = retry_time
#         self.ssh_client = paramiko.SSHClient()
#         self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#
#     def connect(self):
#         i = 0
#         print(f"SSHController Trying to connect to {self.host} ({i}/{self.retry_time})")
#         while True:
#             try:
#                 self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#                 self.ssh_client.connect(self.host, username=self.user, key_filename=self.key)
#                 self.connected = True
#                 break
#             except paramiko.AuthenticationException:
#                 self.connected = False
#                 sys.exit(1)
#             except:
#                 self.connected = False
#                 i += 1
#                 time.sleep(2)
#
#             if i >= self.retry_time:
#                 self.connected = False
#                 sys.exit(1)
#
#     def run_cmd(self):
#         output = None
#         if not self.ssh_client.get_transport():
#             print("No transport available to %s." % self.host)
#             self.connect()
#         if self.ssh_client.get_transport():
#             if not self.ssh_client.get_transport().is_active():
#                 print("Not connected to %s." % self.host)
#                 self.connect()
#
#         if not self.ssh_client.get_transport().is_active():
#             print("There is no connection to %s." % self.host)
#
#         chan = self.ssh_client.get_transport().open_session()
#         chan.get_pty()
#
#         for command in self.cmd_list:
#             print(f"SSHController {self.host}: {command}")
#             stdin, stdout, stderr = self.ssh_client.exec_command(command, get_pty=True)
#
#             while not stdout.channel.exit_status_ready():
#                 if stdout.channel.recv_ready():
#                     rl, wl, xl = select.select([stdout.channel], [], [], 0.0)
#                     if len(rl) > 0:
#                         tmp = stdout.channel.recv(1024)
#                         output = tmp.decode()
#                         print(f"{self.host}: {output}")
#                         continue
#
#             time.sleep(3)
#         return output
#
#     def close_client(self):
#         self.ssh_client.close()
#         self.connected = False


# def worker(host_queue, user, key, cmd):
#     text = "IN THE WORKER"
#     print('\n')
#     print('*' * (len(text) + 4))
#     print('* ' + text + ' *')
#     print('*' * (len(text) + 4))
#     print('\n')
#     while not host_queue.empty():
#         host = host_queue.get()
#         try:
#             controller = SSHController(host, user, key)
#             controller.connect()
#             stdout, stderr = controller.run_cmd()
#             if stdout:
#                 print(f"[{host}] {stdout}")
#             if stderr:
#                 print(f"[{host}] {stderr}", file=sys.stderr)
#             controller.close()
#         except Exception as e:
#             print(f"[{host}] {e}", file=sys.stderr)
#         finally:
#             host_queue.task_done()


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
    parser.add_argument('-u', '--fulib', action='store_true',
                        help='enable fulib compile and install')
    parser.add_argument('-ss', '--skip_src', action='store_true',
                        help='skip source compile')
    parser.add_argument('-sf', '--skip_fish', action='store_true',
                        help='skip fish compile')
    parser.add_argument('-f', '--fuweb', action='store_true',
                        help='skip fish compile')
    return parser


def banner(text):
    print('\n')
    print('*' * (len(text) + 4))
    print('* ' + text + ' *')
    print('*' * (len(text) + 4))
    print('\n')

def main():
    parser = create_parser()
    args = parser.parse_args()

    banner("Setup Rigs")
    rigs = []
    for rig in [("nori", "root", "l1admin1"), ("chutoro", "root", "l1admin1")]:
        commands_instance = Commands(host=rig[0], username=rig[1], password=rig[2])
        rigs.append(commands_instance)

    banner("Setup Sores Instance")
    sores = []
    sores_instance = Commands(host="opensores.us.oracle.com", username="bousborn")
    sores.append(sores_instance)

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

    if not args.fulib:
        banner("Install fulib")
        print("main: enable fulib compile and install")
        run_process(rigs, Commands.install_fulib)
        print("main: completed fulib install")

    if args.fuweb:
        banner("Install fuweb")
        print("main: install fuweb")
        run_process(rigs, Commands.install_fuweb)
        print("main: completed fuweb install")

    banner("Remove Install File")
    run_process(sores, Commands.remove_install_file)

    # banner("Delete Sores Instance")
    # # Make sure I don't run following on sores
    # del sores_instance
    if not args.skip_src:
        # Reboot the rigs
        # for rig in rigs:
            # rig.reboot_rig()
        banner("Reboot for Source Install")
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
