#!/usr/bin/env python3

import os
import pdb
# import socket
import sys
import select
# import multiprocessing_logging
import paramiko
# import datetime
import logging
# from logging.handlers import RotatingFileHandler
# from logging.handlers import QueueHandler
# from logging.handlers import QueueListener
# from multiprocessing import Queue
from logging.handlers import QueueHandler, RotatingFileHandler
import time
# import atexit
import multiprocessing
import argparse
# import signal
# import posix_ipc
# import resource
# from multiprocessing_logging import install_mp_handler, MultiProcessingHandler
# import multiprocessing_logging

# # Set the maximum CPU time (in seconds) that the process can use
# cpu_time_limit = 5 # For example, 5 seconds
# resource.setrlimit(resource.RLIMIT_CPU, (cpu_time_limit, cpu_time_limit))
#
# # Set the maximum memory (in bytes) that the process can use
# memory_limit = 100000000000 # For example, 100 MB
# resource.setrlimit(resource.RLIMIT_DATA, (memory_limit, memory_limit))

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

# LOGGER = None

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


# class MultiprocessingLogger(logging.Logger):
#     def __init__(self, name, level=logging.DEBUG):
#         super().__init__(name, level)
#         self.queue = Queue()
#         handler = QueueHandler(self.queue)
#         self.addHandler(handler)
#         listener = QueueListener(self.queue, handler)
#         listener.start()
#
#     def stop(self):
#         for handler in self.handlers:
#             if isinstance(handler, QueueHandler):
#                 self.queue.put(None)
#         self.queue.close()
#         self.queue.join_thread()


class Commands():
    def __init__(self, logger=None, retry_time=10):
        self.retry_time = retry_time
        self.host = None
        self.connected = False
        self.username = None
        self.password = None
        self.cmd_list = None
        self.known_keys = SORES_KNOWN_KEYS
        self.ssh_client = paramiko.SSHClient()
        self.rigs = AK_RIGS_INFO
        self.build_loc = SORES_HOST
        # global LOGGER
        self.logger = logger
        # self.handler = logging.NullHandler()
        # self.logger = logging.Logger("test-logger")
        # self.logger.addHandler(self.handler)

    def connect(self):
        i = 0
        self.logger.info("Test")

        while True:
            self.logger.info("Trying to connect to %s (%i/%i)", self.host, i, self.retry_time)
            try:
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.ssh_client.connect(self.host, username=self.username, password=self.password)
                self.connected = True
                break
            except paramiko.AuthenticationException:
                self.logger.info("Authentication failed when connecting to %s" % self.host)
                self.connected = False
                sys.exit(1)
            except:
                self.logger.info("Could not SSH to %s, waiting for it to start" % self.host)
                self.connected = False
                i += 1
                time.sleep(2)

            # If we could not connect within time limit
            if i >= self.retry_time:
                logging.info("Could not connect to %s. Giving up" % self.host)
                self.connected = False
                sys.exit(1)

    def run_cmd(self):
        # ForkedPdb().set_trace()
        # if self.connected is False:
        output = None
        if not self.ssh_client.get_transport():
            logging.info("No transport available to %s." % self.host)
            self.connect()
        # if self.connected is False:
        if self.ssh_client.get_transport():
            if not self.ssh_client.get_transport().is_active():
                logging.info("Not connected to %s." % self.host)
                self.connect()

        if not self.ssh_client.get_transport().is_active():
            logging.info("There is no connection to %s." % self.host)
        # After connection is successful
        chan = self.ssh_client.get_transport().open_session()
        chan.get_pty()
        for command in self.cmd_list:
            # self.logger.info(self.host, ": ", command)
            logging.info(f"{self.host}: {command}")
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
                        logging.info(f"{self.host}: {output}")
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
                logging.info("%s: Waiting for reboot" % self.host)
        self.retry_time = 10
        logging.info("%s: Reboot complete" % self.host)

    def install_source(self):
        self.logger.info("%s: Reboot complete" % self.host)
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
            logging.info("No transport available to %s." % self.host)
            self.connect()
        # if self.connected is False:
        if self.ssh_client.get_transport():
            if not self.ssh_client.get_transport().is_active():
                logging.info("Not connected to %s." % self.host)
                self.connect()
        sftp = self.ssh_client.open_sftp()
        with sftp.open(SORES_HERE_LOG, "r") as f:
            contents = f.read()
            decoded_contents = contents.decode()
            logging.info(decoded_contents)


def get_rigs(logger=None):
    processes = []
    # global LOGGER
    connection = Commands(logger=logger)
    for rig in connection.rigs:
        connect = Commands()
        connect.host = rig[0]
        connect.username = rig[1]
        connect.password = rig[2]
        processes.append(connect)

    return processes


def run_process(processlist, proc_target):
    global LOGGER
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


def install_all_rigs(logger=None):
    # global LOGGER
    processlist = get_rigs(logger=logger)
    # LOGGER.info("Kicking off Install Source Targets")
    run_process(processlist, Commands.install_source)
    # LOGGER.info("Kicking off Reboot and Wait Targets")
    run_process(processlist, Commands.reboot_rig)
    # LOGGER.info("Kicking off Reboot and Wait Targets")
    run_process(processlist, Commands.wait_for_rig_reboot)
    # LOGGER.info("Kicking off Install Fulib Targets")
    run_process(processlist, Commands.install_fulib)
    # LOGGER.info("Kicking off Close Clients")
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


# def log_debug(*args):
#     debug = ' '.join(str(arg) for arg in args)
#     # global LOGGER
#     # LOGGER.debug(debug)
#
# def log_info(*args):
#     info = ' '.join(str(arg) for arg in args)
#     print(info)
#     # global LOGGER
#     # LOGGER.info(info)
#
# def log_warning(*args):
#     warning = ' '.join(str(arg) for arg in args)
#     # global LOGGER
#     # LOGGER.warning(warning)
#
# def log_error(*args):
#     error = ' '.join(str(arg) for arg in args)
#     # global LOGGER
#     # LOGGER.error(error)
#
# def log_critical(*args):
#     critical = ' '.join(str(arg) for arg in args)
#     # global LOGGER
#     # LOGGER.critical(critical)

# def create_logger(logfile):
#     # Create a logger instance
#     timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
#     logfile_location = "".join([LOCAL_LOGFILE_LOC, logfile, '_', timestamp, '.log'])
#     logger = logging.getLogger(logfile_location)
#     logger.setLevel(logging.DEBUG)
#
#     # Create a console handler
#     ch = logging.StreamHandler(sys.stdout)
#     ch.setLevel(logging.DEBUG)
#     ch.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
#     logger.addHandler(ch)
#
#     # Create a file handler
#     # fh = logging.FileHandler(logfile)
#     fh = RotatingFileHandler(logfile, maxBytes=1024, backupCount=3)
#     fh.setLevel(logging.DEBUG)
#     fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
#     logger.addHandler(fh)
#
#     return logger


# def create_logger(logfile):
#     # Create a logger instance
#     timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
#     logfile_location = "".join([LOCAL_LOGFILE_LOC, logfile, '_', timestamp, '.log'])
#     logger = logging.getLogger(logfile_location)
#     logger.setLevel(logging.DEBUG)
#
#     # Create a multiprocessing queue
#     queue = multiprocessing.Queue()
#
#     # Create a QueueHandler instance and set its target queue to the multiprocessing queue
#     queue_handler = QueueHandler(queue)
#
#     # Create a RotatingFileHandler instance and set its formatter
#     fh = RotatingFileHandler(logfile, maxBytes=1024, backupCount=3)
#     fh.setLevel(logging.DEBUG)
#     fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
#
#     # Create a QueueListener instance and set its handlers to the RotatingFileHandler and QueueHandler instances
#     queue_listener = QueueListener(queue, fh, queue_handler)
#     queue_listener.start()
#
#     # Add the QueueListener to the root logger
#     logging.getLogger().addHandler(queue_handler)
#
#     # Create a StreamHandler to print logs to console
#     console_handler = logging.StreamHandler(sys.stdout)
#     console_handler.setLevel(logging.DEBUG)
#     console_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
#
#     # Add the StreamHandler to the logger
#     logger.addHandler(console_handler)
#
#     return logger

# def create_logger(logfile):
#     # def worker(wid):
#     #     logger = logging.getLogger("child.%d" % (wid,))
#     #     for i in range(3):
#     #         logger.critical("Log %d.", i)
#     # Create a logger instance
#     timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
#     logfile_location = "".join([LOCAL_LOGFILE_LOC, logfile, '_', timestamp, '.log'])
#     # logger = MultiProcessingHandler(logfile_location)
#     logger = logging.getLogger(logfile_location)
#     logger.setLevel(logging.DEBUG)
#
#     # Create a RotatingFileHandler instance and set its formatter
#     fh = RotatingFileHandler(logfile, maxBytes=1024, backupCount=3)
#     fh.setLevel(logging.DEBUG)
#     fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
#
#     # Add the RotatingFileHandler to the logger
#     logger.addHandler(fh)
#
#     # Create a StreamHandler to print logs to console
#     console_handler = logging.StreamHandler(sys.stdout)
#     console_handler.setLevel(logging.DEBUG)
#     console_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
#
#     # Add the StreamHandler to the logger
#     logger.addHandler(console_handler)
#     return logger


class LogWriterProcess(multiprocessing.Process):
    def __init__(self, logfile_path, log_queue, level=logging.DEBUG):
        super().__init__()
        self.logfile_path = logfile_path
        self.log_queue = log_queue
        self.level = level

    def run(self):
        # Create a file handler for the log file
        file_handler = RotatingFileHandler(self.logfile_path, maxBytes=1024, backupCount=3)
        file_handler.setLevel(self.level)

        # Create a formatter for the log messages
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        file_handler.setFormatter(formatter)

        # Create a logger and add the file handler
        logger = logging.getLogger('log_writer')
        logger.addHandler(file_handler)

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


# class LogQueueHandler(logging.Handler):
#     def __init__(self, log_queue):
#         super().__init__()
#         self.log_queue = log_queue
#
#     def emit(self, record):
#         try:
#             # Send the log message to the queue
#             self.log_queue.put_nowait(record)
#         except Exception:
#             # Catch any exceptions and log them
#             self.handleError(record)


def create_logger():
    # Create a multiprocessing queue for log messages
    log_queue = multiprocessing.Queue(-1)

    # Create a log writer process to write log messages to a file
    # logfile_path = os.path.join('./', 'blastoff.log')
    logfile_path = 'blastoff.log'
    # log_writer = LogWriterProcess(logfile_path, log_queue)
    log_writer = LogWriterProcess(logfile_path, log_queue, level=logging.DEBUG)
    log_writer.start()

    # Create a log handler for the queue and add it to the root logger
    # queue_handler = LogQueueHandler(log_queue)
    queue_handler = logging.handlers.QueueHandler(log_queue)
    queue_handler.setLevel(logging.DEBUG)
    logging.getLogger().addHandler(queue_handler)

    # # Log some messages
    # logging.debug('Debug message')
    # logging.info('Info message')
    # logging.warning('Warning message')
    # logging.error('Error message')
    # logging.critical('Critical message')
    #
    # # Stop the log writer process
    # log_queue.put_nowait(None)
    # log_writer.join()
    return logging.getLogger(logfile_path)


def main(args=None):

    # global LOGGER
    print("fuck")

    logger = create_logger()
    print("fuck2")
    # multiprocessing_logging.install_mp_handler()
    logger.info('test')
    print("fuck3")
    parser = create_parser()
    args = parser.parse_args()
    logger.info('test')
    logger.info(args)
    logger.debug("test")
    print("fuck4")
    if args.fish_install:
        build_src = Commands()
        # LOGGER.info("LOG DADDy")
        src = build_src.build_source()
        build_src.close_client()
        if src is False:
            build_src.print_here_log()
            # LOGGER.info("Build Source Failed")
            sys.exit(1)

    if args.fish_install:
        build_fish = Commands()
        fish = build_fish.build_fish()
        build_fish.close_client()
        if fish is False:
            build_fish.print_here_log()
            # LOGGER.info("Build Fish Failed")
            sys.exit(1)
    print("fuck5")
    # install_all_rigs(logger=logger)
    # LOGGER.info("COMPLETED!")

    # return


# def sigint_handler(signum, frame):
#     print("Caught KeyboardInterrupt %d, quitting...", signum)
#     # clean up code here
#     # ...
#     # exit the program
#     # exit(1)
#     for p in multiprocessing.active_children():
#         p.terminate()
#     sys.exit(1)
#
#
# def sigterm_handler(signum, frame):
#     print("Caught SIGTERM %d, quitting...", signum)
#     for p in multiprocessing.active_children():
#         p.terminate()
#     sys.exit(1)
#
#
# def release_semaphores():
#     for semaphore_name in SEMAPHORE_NAMES:
#         try:
#             semaphore = posix_ipc.Semaphore(semaphore_name)
#             semaphore.unlink()
#         except Exception as e:
#             print(f"Error releasing semaphore {semaphore_name}: {e}")


if __name__ == "__main__":
    main()

    # atexit.register(release_semaphores)
    # signal.signal(signal.SIGINT, sigint_handler)  # ctrl-C
    # signal.signal(signal.SIGTERM, sigterm_handler)  # kill command or other signals
    # # check if the process had an exception
    # if p.exitcode != 0:
    #     # do some error handling here
    #     print("Process had an exception, handle it accordingly")
    #     signal.signal(signal.SIGTERM, sigterm_handler)

