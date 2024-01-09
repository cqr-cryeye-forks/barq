from src.helpers.commands import wait_for_command_invocation


def run_linux_command(ssm_client, instance_id, action, payload) -> bool:
    """
    Run a Systems Manager command on a running Linux instance.
    :param ssm_client: Systems Manager client for the required region.
    :param instance_id: id of target instance
    :param action: Action to be run (AWS calls it DocumentName, here it's running a bash script)
    :param payload: The actual payload to be executed on the target instance.
    :return: returns status of execution.
    """
    response = ssm_client.send_command(InstanceIds=[instance_id, ],
                                       DocumentName=action,
                                       DocumentVersion='$DEFAULT',
                                       TimeoutSeconds=3600,
                                       Parameters={'commands': [payload]}
                                       )
    command_id = response['Command']['CommandId']
    success, result = wait_for_command_invocation(
        ssm_client, command_id, instance_id)
    return success
