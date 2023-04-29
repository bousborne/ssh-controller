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
AK_INSTALL_SOURCE_COMMAND = 'confirm shell /tmp/on/sbin/./install.ksh'
AK_INSTALL_FISH_COMAND = 'confirm shell /usr/lib/ak/tools/fulib /tmp/on'
AK_TEST_ESTIMATE = 'shares select prj20 replication select action-000 sendestimate'
AK_TEST_ESTIMATE2 = 'shares select prj20 replication select action-001 sendestimate'
AK_TEST_ESTIMATE3 = 'shares select prj1 replication select action-002 sendestimate'

class ForkedPdb(pdb.Pdb):
    """A Pdb subclass that may be used
    from a forked multiprocessing child

    Drop the following line somewhere
    inside of a class:

    ForkedPdb().set_trace()

    """
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = open('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin


class LogWriterProcess(multiprocessing.Process):
    def __init__(self, logfile_path, log_queue):
        super().__init__()
        self.logfile_path = logfile_path
        self.log_queue = log_queue

    def run(self):
        # Create a file handler for the log file
        file_handler = RotatingFileHandler(self.logfile_path, maxBytes=1024, backupCount=3)
        file_handler.setLevel(logging.DEBUG)

        # Create a formatter for the log messages
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        file_handler.setFormatter(formatter)

        # Create a logger and add the file handler
        logger = logging.getLogger('log_writer')
        logger.addHandler(file_handler)
        logger.setLevel(logging.DEBUG)

        while True:
            try:
                # Get a log message from the queue
                record = self.log_queue.get()
                if record is None:
                    break

                # Log the message
                logger.handle(record)
            except Exception:
                # Catch any exceptions and log them
                logger.exception('Error in log writer')


class Commands(multiprocessing.Process):
    def __init__(self, log_queue=None, log_writer=None, retry_time=10, host=None, username=None, password=None):
        super().__init__()
        self.log_queue = log_queue
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
        self.logger = logging.getLogger(f"Commands.{self.host}")
        self.logger.critical('init')
        self.logger.info('init')
        self.logger.setLevel(logging.DEBUG)
        self.logger.info("INFO init %s", self.host)
        self.log_writer = log_writer

    def reset_log(self, queue):
        self.log_queue = queue
        self.logger = logging.getLogger(f"Commands.{self.host}")
        self.logger.setLevel(logging.DEBUG)

    def connect(self):
        i = 0
        # logging.getLogger('log_writer')
        # self.logging.critical("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
        # print(f"logger: {self.logger}, host: {self.host}")
        # self.logger.info("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
        # self.logger.critical("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)

        print(f"Trying to connect to {self.host} ({i}/{self.retry_time})")
        while True:
            # self.logger.info("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
            try:
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh_client.connect(self.host, username=self.username, password=self.password)
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
            print(f"{self.host}: {command}")
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

    def reboot_rig(self):
        reboot_command = AK_REBOOT_COMMAND
        self.cmd_list = [reboot_command]
        self.run_cmd()

    def wait_for_rig_reboot(self):
        time.sleep(60)
        self.retry_time = 0
        while True:
            try:
                time.sleep(15)
                pwd_command = AK_PWD_COMMAND
                self.cmd_list = [pwd_command]
                self.run_cmd()
                break
            except:
                print("%s: Waiting for reboot" % self.host)
        self.retry_time = 10
        print("%s: Reboot complete" % self.host)

    def install_source(self):
        print("install source")
        # self.reset_log(log_queue)
        print("log reset")
        self.logger.critical("%s: INSTALL SOURCE" % self.host)
        print("logged")

        self.cmd_list = [AK_MOUNT_COMMAND]
        self.run_cmd()
        self.cmd_list = [AK_INSTALL_SOURCE_COMMAND]
        self.run_cmd()

    def install_fulib(self):
        self.cmd_list = [AK_MOUNT_COMMAND]
        self.run_cmd()
        self.cmd_list = [AK_INSTALL_FISH_COMAND]
        self.run_cmd()

    def build_source(self):
        self.host = SORES_HOST
        self.username = SORES_USERNAME
        self.cmd_list = [SORES_BUILD_SOURCE_COMMAND]
        ret = self.run_cmd()
        if ret.find("failed") != -1:
            return False
        else:
            return True

    def build_fish(self):
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


def get_rigs():
    processes = []
    # global LOGGER
    # logger = logging.getLogger('log_writer')
    logging.critical("get_rigs2")
    logging.info("get_rigs2")
    # connection = Commands(log_queue=log_queue)
    for rig in AK_RIGS_INFO:
        connect = Commands(host=rig[0], username=rig[1], password=rig[2])
        # connect.host = rig[0]
        # connect.username = rig[1]
        # connect.password = rig[2]
        processes.append(connect)

    return processes


def run_process(processlist, proc_target):
    # global LOGGER
    # logger = logging.getLogger('log_writer')
    logging.critical("run_process")
    processes = []
    for num, proc in enumerate(processlist):
        arg1 = tuple([proc])
        proc = multiprocessing.Process(target=proc_target, args=arg1,
            name="{host}.{target}".format(host=proc.host, target=proc_target.__name__))
        processes.append(proc)
    for num, proc in enumerate(processes):
        # LOGGER.info("Starting process %s", proc.name)
        proc.start()

    for proc in processes:
        # LOGGER.info("Waiting for process %s", proc.name)
        proc.join(300)  # wait for proc to finish, or timeout after 3 seconds
        if proc.is_alive():  # if proc is still alive, terminate it
            proc.terminate()
            proc.join()
            # LOGGER.info("Process %s timed out and was terminated", proc.name)

    # LOGGER.info("Complete!")


def install_all_rigs(log_queue=None, log_writer=None):
    # global LOGGER
    processlist = get_rigs()
    print("Kicking off Install Source Targets")
    run_process(processlist, Commands.install_source)
    print("Kicking off Reboot and Wait Targets")
    run_process(processlist, Commands.reboot_rig)
    print("Kicking off Reboot and Wait Targets")
    run_process(processlist, Commands.wait_for_rig_reboot)
    print("Kicking off Install Fulib Targets")
    run_process(processlist, Commands.install_fulib)
    # print("Kicking off Rig Test")
    # run_process(processlist, Commands.rig_test)
    print("Kicking off Close Clients")
    run_process(processlist, Commands.close_client)


def create_parser():
    # Create an argument parser
    desc = 'This program facilitates in helping build both fish and source, ' \
        'as well as installing it on developer rigs.'
    parser = argparse.ArgumentParser(description=desc,
                                     epilog='run "blastoff --setup" to set it up for the first time.')

    # Add boolean options
    parser.add_argument('-u', '--fulib', action='store_true',
                        help='enable fulib compile and install')

    parser.add_argument('-s', '--source_install', action='store_false',
        help='skip source compile')

    parser.add_argument('-f', '--fish_install', action='store_false',
        help='skip fish compile')

    return parser


def create_logger():
    # Create a multiprocessing queue for log messages
    log_queue = multiprocessing.Queue(-1)

    # Create a log writer process to write log messages to a file
    # logfile_path = os.path.join('/path/to/log', 'blastoff.log')
    logfile_path = 'blastoff.log'
    log_writer = LogWriterProcess(logfile_path, log_queue)
    log_writer.start()

    # Create a file handler for the log file
    file_handler = RotatingFileHandler(logfile_path, maxBytes=1024, backupCount=3)
    file_handler.setLevel(logging.DEBUG)

    # Create a formatter for the log messages
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    file_handler.setFormatter(formatter)

    # Create a logger and add the file handler
    logger = logging.getLogger('log_writer')
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)

    # Create a log handler for the queue and add it to the root logger
    queue_handler = logging.handlers.QueueHandler(log_queue)
    queue_handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(queue_handler)

    return log_queue, log_writer


def main():
    log_queue, log_writer = create_logger()

    # Log some messages
    logging.debug('Debug message')
    logging.info('Info message')
    logging.warning('Warning message')
    logging.error('Error message')
    logging.critical('Critical message')

    logging.critical("test")
    parser = create_parser()
    args = parser.parse_args()

    if args.source_install:
        print("Starting SOURCE\n")
        build_src = Commands(log_queue=log_queue, log_writer=log_writer)
        # LOGGER.info("LOG DADDy")
        src = build_src.build_source()
        build_src.close_client()
        if src is False:
            build_src.print_here_log()
            # LOGGER.info("Build Source Failed")
            sys.exit(1)

    if args.fish_install:
        print("Starting FISH\n")
        build_fish = Commands(log_queue=log_queue, log_writer=log_writer)
        fish = build_fish.build_fish()
        build_fish.close_client()
        if fish is False:
            build_fish.print_here_log()
            # LOGGER.info("Build Fish Failed")
            sys.exit(1)

    # Stop the log writer process

    install_all_rigs(log_queue=log_queue, log_writer=log_writer)
    # LOGGER.info("COMPLETED!")
    log_queue.put_nowait(None)
    log_writer.join()
    # return


if __name__ == "__main__":
    main()

# -------------------------------------------------------------------------------------
import argparse
import paramiko
import sys
import threading
import time
from queue import Queue


class SSHController:
    def __init__(self, host, user, key):
        self.host = host
        self.user = user
        self.key = key
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        self.client.connect(self.host, username=self.user, key_filename=self.key)

    def run_command(self, command):
        _, stdout, stderr = self.client.exec_command(command)
        return stdout.read().decode("utf-8"), stderr.read().decode("utf-8")

    def close(self):
        self.client.close()


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


def build_fish():
    host = SORES_HOST
    username = SORES_USERNAME
    cmd_list = [SORES_BUILD_FISH_COMMAND]
    ret = self.run_cmd()
    if ret.find("failed") != -1:
        return False
    else:
        return True


def build_bash():
    # Add your build_bash implementation here
    pass


def build_zsh():
    # Add your build_zsh implementation here
    pass


def threader(hosts, user, key, cmd, workers):
    host_queue = Queue()
    for host in hosts:
        host_queue.put(host)

    threads = []
    for _ in range(workers):
        t = threading.Thread(target=worker, args=(host_queue, user, key, cmd))
        t.start()
        threads.append(t)

    host_queue.join()

    for thread in threads:
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Execute commands on remote servers over SSH.")
    parser.add_argument("hosts", metavar="HOST", nargs="+", help="A list of hosts to connect to")
    parser.add_argument("-u", "--user", required=True, help="Username for the SSH connection")
    parser.add_argument("-k", "--key", required=True, help="SSH private key file")
    parser.add_argument("-c", "--cmd", required=True, help="Command to run on the remote server")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of worker threads to use (default: 5)")

    args = parser.parse_args()

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
    AK_INSTALL_SOURCE_COMMAND = 'confirm shell /tmp/on/sbin/./install.ksh'
    AK_INSTALL_FISH_COMAND = 'confirm shell /usr/lib/ak/tools/fulib /tmp/on'
    AK_TEST_ESTIMATE = 'shares select prj20 replication select action-000 sendestimate'
    AK_TEST_ESTIMATE2 = 'shares select prj20 replication select action-001 sendestimate'
    AK_TEST_ESTIMATE3 = 'shares select prj1 replication select action-002 sendestimate'

    threader(args.hosts, args.user, args.key, args.cmd, args.workers)

