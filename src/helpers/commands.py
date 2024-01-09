import time

from src.helpers.print_output import print_color


def wait_for_command_invocation(ssm_client, command_id, instance_id) -> (bool, dict):
    """

    :param ssm_client: The ssm (Systems manager) client associated with the required region and account.
    :param command_id: The id of the command to check invocation results for.
    :param instance_id: The id of the instance on which the command was run.
    :return: Returns a tuple of success state and AWS response json in full.
    """
    time.sleep(10)
    result = ssm_client.get_command_invocation(
        CommandId=command_id, InstanceId=instance_id)
    print_color('[..] Waiting for command to return.... This will take some time')
    while result['Status'] in {'InProgress', 'Pending', 'Waiting'}:
        time.sleep(10)
        result = ssm_client.get_command_invocation(
            CommandId=command_id, InstanceId=instance_id)
        if result['Status'] in {'Failed', 'TimedOut', 'Cancelling', 'Cancelled'}:
            print_color('[!] ERROR: %s' % result['StandardErrorContent'])
            return False, result
    print_color('[*] Status of the command is: %s' % result['Status'])
    if result['Status'] == 'Success':
        print_color('[+] Success! The command executed successfully. Output is:')
        print_color(result['StandardOutputContent'], 'blue')
    return True, result
