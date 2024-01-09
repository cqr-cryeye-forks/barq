import boto3
from botocore.exceptions import ClientError
from clint.textui import prompt
from prettytable import PrettyTable

from src.helpers.print_output import print_color, print_table
from src.scanner.records import findings
from src.scanner.records.aws_credentials import AWSCredentials
from src.scanner.records.command_invocations import CommandInvocation
from src.scanner.records.elastic_cloud import EC2Instance
from src.scanner.records.lambda_functions import LambdaFunction
from src.scanner.records.security_groups import SecurityGroup
from src.typing import T_TOKEN, T_ACCESS_KEY_ID, T_SECRET_KEY, T_REGION_NAME


class BarqScannerCore:
    def __init__(self,
                 access_key_id: T_ACCESS_KEY_ID,
                 secret_access_key: T_SECRET_KEY,
                 region_name: T_REGION_NAME,
                 session_token: T_TOKEN = None,
                 ):
        self.aws_creds: AWSCredentials = AWSCredentials(
            session_token=session_token,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            region_name=region_name,
        )
        self.session: boto3.session.Session | None = None
        self.findings: findings.Findings = findings.Findings()
        self.ec_2_instances: list[EC2Instance] = []
        self.lambda_functions: list[LambdaFunction] = []
        self.command_invocations: list[CommandInvocation] = []
        self.security_groups: list[SecurityGroup] = []
        self.ec2_instances: list[EC2Instance] = []

    def add_ec2_instance(self, instance: EC2Instance) -> None:
        self.ec2_instances.append(instance)

    def add_lamda_function(self, function: LambdaFunction) -> None:
        self.lambda_functions.append(function)

    def add_command_invocation(self, command: CommandInvocation) -> None:
        self.command_invocations.append(command)

    def add_security_group(self, group: SecurityGroup) -> None:
        self.security_groups.append(group)

    def add_findings(self, finding: findings.Secret | findings.Parameter) -> None:
        match type(finding):
            case findings.Secret:
                self.findings.secrets.append(finding)
            case findings.Parameter:
                self.findings.parameters.append(finding)
        raise ValueError(f"type '{type(finding)}' is not supported!")

    def set_aws_creds(self,
                      access_key_id: T_ACCESS_KEY_ID,
                      secret_access_key: T_SECRET_KEY,
                      region_name: T_REGION_NAME,
                      session_token: T_TOKEN = None, ) -> None:
        """
        Set the AWS credentials of the targeted AWS account.
        :return: None
        """
        self.aws_creds: AWSCredentials = AWSCredentials(
            session_token=session_token,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            region_name=region_name,
        )
        self.init_aws_session()

    def show_ec2_instances(self) -> None:
        """
        List EC2 instances.
        :return: None
        """
        self.show_selected_ec2_instances(instances=self.ec2_instances)

    @staticmethod
    def show_selected_ec2_instances(instances: list[EC2Instance]) -> None:
        """
        List of selected EC2 instances.
        :return: None
        """
        print_table(
            columns_names=[
                'Instance ID', 'Platform', 'Region', 'State', 'Public IP', 'Public DNS name', 'Profile'],
            table_data=instances,
            title='[*] Your collected EC2 instances, if you want an updated list, invoke attacksurface:'
        )

    def show_aws_creds(self) -> None:
        """
        List AWS credentials used to connect to this AWS account.
        :return: None
        """
        print_color(
            "[+] Your AWS credentials:"
            f"[*] Access key id: {self.aws_creds.access_key_id}"
            f"[*] Secret access key id: {self.aws_creds.secret_access_key}"
            f"[*] Session token: {self.aws_creds.session_token}"
            f"[*] Region: {self.aws_creds.region_name}"
        )

    def show_findings(self) -> None:
        """
        Show Secrets and Parameters looted from AWS Secrets Manager or Systems Manager Parameter store for each region.
        :return: None
        """
        if len(self.findings.secrets) < 1:
            print_color(
                '[!] You have no stored secrets. Run the command dumpsecrets to set them')
        if len(self.findings.parameters) < 1:
            print_color(
                '[!] You have no stored parameters. Run the command dumpsecrets to set them')

        print_color('[*] Your collected secrets and credentials:')
        for secret in self.findings.secrets:
            print_color("===========", 'blue')
            print_color(f"[+] Secret Name: {secret.name}\n"
                        f"[+] Secret Value: {secret.value}\n"
                        f"[+] Secret Description: {secret.description}\n")
        for parameter in self.findings.parameters:
            print_color("===========", 'blue')
            print_color(f"[+] Parameter Name: {parameter.name}\n"
                        f"[+] Parameter Value: {parameter.value}")

    def show_security_groups(self) -> None:
        """
        List security groups discovered.
        :return: None
        """
        if len(self.findings.secrets) < 1:
            print_color(
                '[!] You have no stored secrets. Run the command dumpsecrets to set them')
            return
        print_color(
            '[*] Your collected security groups, if you want an updated list, invoke attacksurface:')
        for group in self.security_groups:
            print_color(f"Group ID: {group.id}\n"
                        f"Group description: {group.description}"
                        f"Group Ingress IP permissions:\n",
                        'green')
            for rule in group.ip_permissions:
                print_color(f"[+] Ingress Rule: "
                            f"[+] From Port: {rule.from_port}, "
                            f"[+] To Port: {rule.to_port}, "
                            f"[+] Protocol: {rule.protocol}, "
                            f"[+] IP ranges: {rule.ranges}")
            print_color('Group Egress IP permissions:', 'green')
            for rule in group.ip_permissions_egress:
                print_color(f"[+] Egress Rule: "
                            f"[+] From Port: {rule.from_port}, "
                            f"[+] To Port: {rule.to_port}, "
                            f"[+] Protocol: {rule.protocol}, "
                            f"[+] IP ranges: {rule.ranges}")
            print_color("=======================================", 'magenta')

    def show_command_invocations(self) -> None:
        """
        Show stored results of previously executed attacks on EC2 instances.
        :return: None
        """
        if len(self.command_invocations) < 1:
            print_color(
                '[!] You don\'t have any commands run yet against EC2 targets. Run ec2attacks to launch commands.')
            return

        for command in self.command_invocations:
            print_color(
                f"Command instance id: {command.id}\n"
                f"Command state: {command.state}\n"
                f"Command platform: {command.platform}\n"
                f"Command region: {command.region}\n",
                'green')
            command.error = command.error[:min(len(command.error), 5000)]
            print_color(f"Command error: {command.error}", 'green')
            command.output = command.output[:min(len(command.output), 5000)]
            print_color(f"Command output: {command.output}", 'green')
            print_color("=======================================", 'magenta')

    def init_aws_session(self):
        """
        Set AWS credentials and initialize session.
        """
        self.session = boto3.session.Session(aws_access_key_id=self.aws_creds.access_key_id,
                                             aws_secret_access_key=self.aws_creds.secret_access_key,
                                             region_name=self.aws_creds.region_name,
                                             aws_session_token=self.aws_creds.session_token)
        self._set_account_regions()
        if self.aws_creds.region_name is None:
            self.set_session_region(region=self._get_account_region())

    def set_session_region(self, region: T_REGION_NAME) -> boto3.session.Session:
        try:
            self.session = boto3.session.Session(aws_access_key_id=self.aws_creds.access_key_id,
                                                 aws_secret_access_key=self.aws_creds.secret_access_key,
                                                 region_name=region,
                                                 aws_session_token=self.aws_creds.session_token)
            return self.session
        except Exception as e:
            print_color(e.__str__(), 'red')

    def _set_account_regions(self) -> None:
        try:
            response: dict = self.session.client('ec2').describe_regions()
            for region in response.get('Regions', []):
                self.aws_creds.possible_regions.append(region['RegionName'])
        except ClientError as e:
            if "OptInRequired" in str(e):
                print_color("[!] OptInRequired Error: The keys are valid but you have a problem in your AWS account."
                            "Your account may be under validation by AWS. Is it a new account?")
            else:
                print_color(
                    "[!] Error accessing AWS services. Double check your AWS keys, tokens, privileges and region.")
            raise e

    def _get_account_region(self) -> T_REGION_NAME:
        region_table = PrettyTable(['Region'])
        for region in self.aws_creds.possible_regions:
            region_table.add_row([region])
        print(region_table)
        chosen_region = prompt.query(
            'What is your preferred AWS region?', default='us-east-1')
        if chosen_region not in self.aws_creds.possible_regions:
            print_color("[!] Invalid AWS region! Exiting....")
            exit()
        return chosen_region
