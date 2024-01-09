ASSUME_ROLE_POLICY_DATA = {
    'Version': '2012-10-17',
    'Statement': {
        'Effect': 'Allow',
        'Principal': {
            'Service': 'ec2.amazonaws.com'},
        'Action': 'sts:AssumeRole'
    }
}

AMI_OPTIONS = [
    {'selector': '1', 'prompt': 'Linux', 'return': 'linux'},
    {'selector': '2', 'prompt': 'Windows', 'return': 'windows'}
]
