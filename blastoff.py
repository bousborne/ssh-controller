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
import argparse
import sys
import threading
import time
from queue import Queue

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-5.5s]  %(message)s",
    handlers=[
        logging.FileHandler("logfile.log"),
        logging.StreamHandler()
    ])

class Commands():
    def __init__(self, retry_time=10, host=None, username=None, password=None):
        super().__init__()
        self.retry_time = retry_time
        self.host = host
        self.connected = False
        self.username = username
        self.password = password
        self.cmd_list = None
        self.known_keys = SORES_KNOWN_KEYS
        self.ssh_client = paramiko.SSHClient()
        self.rigs = AK_RIGS_INFO
        self.build_loc = SORES_HOST


    def connect(self):
        i = 0
        logging.info("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)

        print(f"Trying to connect to {self.host} ({i}/{self.retry_time})")
        while True:
            logging.info("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
            try:
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
        logging.info(f"run command on {self.host}.")
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
        logging.info(f"ensure connection to {self.host}.")
        if not self.ssh_client.get_transport() or not self.ssh_client.get_transport().is_active():
            logging.info(f"No active transport available to {self.host}. Trying to connect...")
            self.connect()

        return self.ssh_client.get_transport() and self.ssh_client.get_transport().is_active()

    def close_client(self):
        self.ssh_client.close()
        self.connected = False

    def reboot_rig(self):
        logging.info(f"Rebooting {self.host}.")
        reboot_command = AK_REBOOT_COMMAND
        self.cmd_list = [reboot_command]
        self.run_cmd()

    def wait_for_rig_reboot(self, timeout=600, retry_interval=15):
        logging.info(f"Waiting for reboot on {self.host}.")
        reboot_start_time = time.time()
        # Required for time to initiate reboot
        time.sleep(60)
        while True:
            time_elapsed = time.time() - reboot_start_time
            if time_elapsed >= timeout:
                logging.warning(f"{self.host}: Reboot timeout reached. Aborting.")
                break
            try:
                time.sleep(retry_interval)
                logging.info(f"Attempting to connect to {self.host}.")
                pwd_command = AK_PWD_COMMAND
                self.cmd_list = [pwd_command]
                self.run_cmd()
                logging.info(f"{self.host}: Reboot complete")
                break
            except Exception as e:
                logging.info(f"{self.host}: Waiting for reboot. Exception: {e}")

    def install_source(self):
        logging.info("%s: INSTALL SOURCE" % self.host)
        self.cmd_list = [AK_MOUNT_COMMAND]
        self.run_cmd()
        self.cmd_list = [AK_INSTALL_SOURCE_COMMAND]
        self.run_cmd()

    def install_fulib(self):
        logging.info("%s: INSTALL FISH" % self.host)
        self.cmd_list = [AK_MOUNT_COMMAND]
        self.run_cmd()
        self.cmd_list = [AK_INSTALL_FISH_COMAND]
        self.run_cmd()

    def install_fuweb(self):
        logging.info("%s: INSTALL FUWEB" % self.host)
        self.cmd_list = [AK_MOUNT_COMMAND]
        self.run_cmd()
        self.cmd_list = [AK_INSTALL_FUWEB_COMAND]
        self.run_cmd()
        self.cmd_list = [AK_INSTALL_RESTART_SVCADM_COMAND]
        self.run_cmd()

    def create_install_file(self):
        logging.info("%s: BUILD SOURCE" % self.host)
        self.host = SORES_HOST
        self.username = SORES_USERNAME
        sftp = self.ssh_client.open_sftp()
        try:
            sftp.stat(KERNEL_INSTALL_PATH)
        except FileNotFoundError:
            sftp.mkdir(KERNEL_INSTALL_PATH)

        # Create the file on the remote machine
        remote_filename = f"{KERNEL_INSTALL_PATH}/{KERNEL_INSTALL_FILE}"
        remote_file = sftp.file(remote_filename, 'w')
        remote_file.write(KERNEL_INSTALL_CONTENT)
        remote_file.close()

        # Make the file executable
        stdin, stdout, stderr = self.ssh_client.exec_command(f"chmod +x {KERNEL_INSTALL_PATH}/{KERNEL_INSTALL_FILE}")
        sftp.close()

    def remove_install_file(self):
        logging.info("%s: BUILD SOURCE" % self.host)
        self.host = SORES_HOST
        self.username = SORES_USERNAME
        sftp = self.ssh_client.open_sftp()
        remote_filename = f"{KERNEL_INSTALL_PATH}/{KERNEL_INSTALL_FILE}"
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
        self.host = SORES_HOST
        self.username = SORES_USERNAME
        self.cmd_list = [SORES_BUILD_SOURCE_COMMAND]
        ret = self.run_cmd()
        if ret.find("failed") != -1:
            return False
        else:
            return True

    def build_fish(self):
        logging.info("%s: BUILD FISH" % self.host)
        self.host = SORES_HOST
        self.username = SORES_USERNAME
        self.cmd_list = [SORES_BUILD_FISH_COMMAND]
        ret = self.run_cmd()
        if ret.find("failed") != -1:
            return False
        else:
            return True

    def print_here_log(self):
        self.host = SORES_HOST
        self.username = SORES_USERNAME
        if not self.ssh_client.get_transport():
            print("No transport available to %s." % self.host)
            self.connect()
        # if self.connected is False:
        if self.ssh_client.get_transport():
            if not self.ssh_client.get_transport().is_active():
                print("Not connected to %s." % self.host)
                self.connect()
        sftp = self.ssh_client.open_sftp()
        with sftp.open(SORES_HERE_LOG, "r") as f:
            contents = f.read()
            decoded_contents = contents.decode()
            self.logger.info(decoded_contents)

    def rig_test(self):
        self.cmd_list = [AK_TEST_ESTIMATE, AK_TEST_ESTIMATE2, AK_TEST_ESTIMATE3]
        self.run_cmd()


class SSHController:
    def __init__(self, host, user, key, retry_time=10):
        self.host = host
        self.user = user
        self.key = key
        self.retry_time = retry_time
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        i = 0
        # logging.getLogger('log_writer')
        # self.logging.critical("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
        # print(f"logger: {self.logger}, host: {self.host}")
        # self.logger.info("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
        # self.logger.critical("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)

        print(f"SSHController Trying to connect to {self.host} ({i}/{self.retry_time})")
        while True:
            # self.logger.info("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
            try:
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh_client.connect(self.host, username=self.user, password=self.password)
                self.connected = True
                break
            except paramiko.AuthenticationException:
                # self.logger.info("Authentication failed when connecting to %s" % self.host)
                self.connected = False
                sys.exit(1)
            except:
                # self.logger.info("Could not SSH to %s, waiting for it to start" % self.host)
                self.connected = False
                i += 1
                time.sleep(2)

            # If we could not connect within time limit
            if i >= self.retry_time:
                # self.logger.info("Could not connect to %s. Giving up" % self.host)
                self.connected = False
                sys.exit(1)

    def run_cmd(self):
        # if self.connected is False:
        output = None
        if not self.ssh_client.get_transport():
            print("No transport available to %s." % self.host)
            self.connect()
        # if self.connected is False:
        if self.ssh_client.get_transport():
            if not self.ssh_client.get_transport().is_active():
                print("Not connected to %s." % self.host)
                self.connect()

        if not self.ssh_client.get_transport().is_active():
            print("There is no connection to %s." % self.host)
        # After connection is successful
        chan = self.ssh_client.get_transport().open_session()
        chan.get_pty()
        for command in self.cmd_list:
            # self.logger.info(self.host, ": ", command)
            print(f"SSHController {self.host}: {command}")
            # execute commands
            stdin, stdout, stderr = self.ssh_client.exec_command(command, get_pty=True)
            # TODO() : if an error is thrown, stop further rules and revert back changes
            # Wait for the command to terminate
            while not stdout.channel.exit_status_ready():
                # Only print data if there is data to read in the channel
                if stdout.channel.recv_ready():
                    rl, wl, xl = select.select([stdout.channel], [], [], 0.0)
                    if len(rl) > 0:
                        tmp = stdout.channel.recv(1024)
                        output = tmp.decode()
                        # self.logger.info(self.host, ": ", output)
                        # logging.info(f"{self.host}: {output}")
                        print(f"{self.host}: {output}")
                        continue
            time.sleep(3)
        return output

    def close_client(self):
        self.ssh_client.close()
        self.connected = False


def worker(host_queue, user, key, cmd):
    while not host_queue.empty():
        host = host_queue.get()
        try:
            controller = SSHController(host, user, key)
            controller.connect()
            stdout, stderr = controller.run_command(cmd)
            if stdout:
                print(f"[{host}] {stdout}")
            if stderr:
                print(f"[{host}] {stderr}", file=sys.stderr)
            controller.close()
        except Exception as e:
            print(f"[{host}] {e}", file=sys.stderr)
        finally:
            host_queue.task_done()


def run_process(processlist, proc_target):
    threads = []
    for item in processlist:
        t = threading.Thread(target=proc_target, args=(item,))
        t.start()
        threads.append(t)

    for thread in threads:
        thread.join()


def create_parser():
    # Create an argument parser
    desc = 'This program facilitates in helping build both fish and source, ' \
        'as well as installing it on developer rigs.'
    parser = argparse.ArgumentParser(description=desc,
                                     epilog='run "blastoff --setup" to set it up for the first time.')
    # Add boolean options
    parser.add_argument('-u', '--fulib', action='store_true',
                        help='enable fulib compile and install')
    parser.add_argument('-ss', '--skip_src', action='store_true',
        help='skip source compile')
    parser.add_argument('-sf', '--skip_fish', action='store_true',
        help='skip fish compile')
    parser.add_argument('-f', '--fuweb', action='store_true',
        help='skip fish compile')
    return parser


def main():
    logging.info("Running the main function")
    parser = create_parser()
    args = parser.parse_args()

    AK_RIGS_INFO = [('nori', 'root', 'l1admin1'), ('chutoro', 'root', 'l1admin1')]
    rigs = []
    for rig in AK_RIGS_INFO:
        commands_instance = Commands(host=rig[0], username=rig[1], password=rig[2])
        rigs.append(commands_instance)
    sores = []
    sores_instance = Commands(host=SORES_HOST, username=SORES_USERNAME)
    sores.append((sores_instance))

    if not args.skip_src:
        logging.info("main: did NOT skip build src")
        logging.info("main: building source")
        run_process(sores, Commands.build_source)
        logging.info("main: completed build source")
        run_process(sores, Commands.create_install_file)
        logging.info("main: completed create source install file")


    if not args.skip_fish:
        logging.info("main: did NOT skip build fish")
        logging.info("main: building fish")
        run_process(sores, Commands.build_fish)
        logging.info("main: completed build fish")


    if not args.skip_src:
        logging.info("main: did NOT skip install src")
        logging.info("main: installing source")
        run_process(rigs, Commands.install_source)
        logging.info("main: install source complete")
        logging.info("main: rebooting rigs")
        run_process(rigs, Commands.reboot_rig)
        logging.info("main: waiting for rigs to reboot")
        run_process(rigs, Commands.wait_for_rig_reboot)
        logging.info("main: completed install source and reboot")
        run_process(rigs, Commands.remove_install_file)
        logging.info("main: removed source install file")


    if not args.skip_fish:
        logging.info("main: did NOT skip install fish")
        logging.info("main: installing fish")
        run_process(rigs, Commands.install_fulib)
        logging.info("main: completed install fish")

    if args.fuweb:
        logging.info("main: installing fuweb")
        run_process(rigs, Commands.install_fuweb)
        logging.info("main: completed install fuweb")

    logging.info("main: completed all")

    # run_process(rigs, Commands.install_fulib)

if __name__ == "__main__":
    # Define your global variables here
    global_variable1 = None
    global_variable2 = None
    SORES_HOST = "opensores.us.oracle.com"
    SORES_USERNAME = "bousborn"
    SORES_BUILD_SOURCE_COMMAND = "pwd && cd usr/src/ && pwd && pwd && build here -Cid && echo $?"
    SORES_BUILD_FISH_COMMAND = "pwd && cd usr/fish/ && pwd && build here -Cid && echo $?"
    SORES_HERE_LOG = "/export/ws/bousborn/on-gate/log.i386/here.log"
    SORES_KNOWN_KEYS = "/home/bousborn/.ssh/authorized_keys"

    LOCAL_LOGFILE_LOC = "/Users/bousborn/oracle/"
    AK_RIGS_INFO = [('nori', 'root', 'l1admin1'), ('chutoro', 'root', 'l1admin1')]
    AK_REBOOT_COMMAND = 'confirm maintenance system reboot'
    AK_PWD_COMMAND = 'confirm shell pwd'
    AK_MOUNT_COMMAND = 'confirm shell mkdir -p /tmp/on && mount -F nfs opensores.us.oracle.com:/export/ws/bousborn/on-gate /tmp/on/'
    KERNEL_INSTALL_PATH = "/export/ws/bousborn/on-gate/sbin"
    KERNEL_INSTALL_FILE = "install.ksh"
    AK_INSTALL_SOURCE_COMMAND = 'confirm shell /tmp/on/sbin/./install.ksh'
    AK_INSTALL_FISH_COMAND = 'confirm shell /usr/lib/ak/tools/fulib /tmp/on'
    AK_INSTALL_FUWEB_COMAND = 'confirm shell /usr/lib/ak/tools/fuweb -p /tmp/on/data/proto/fish-root_i386'
    AK_INSTALL_RESTART_SVCADM_COMAND = 'confirm shell svcadm restart -s akd'

    AK_TEST_ESTIMATE = 'shares select prj20 replication select action-000 sendestimate'
    AK_TEST_ESTIMATE2 = 'shares select prj20 replication select action-001 sendestimate'
    AK_TEST_ESTIMATE3 = 'shares select prj1 replication select action-002 sendestimate'

    KERNEL_INSTALL_CONTENT = """ROOT=
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
echo "Installation Complete. If kernel was installed, please restart machine...";"""
    main()
