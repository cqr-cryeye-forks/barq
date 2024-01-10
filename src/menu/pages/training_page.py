import json
import time

from clint.textui import prompt, indent

from src.constants.training import ASSUME_ROLE_POLICY_DATA, AMI_OPTIONS
from src.helpers.generators import id_generator
from src.helpers.linux_commands import run_linux_command
from src.helpers.print_output import print_color
from src.helpers.shell_options import shell_script_options
from src.helpers.windows_commands import run_windows_command
from src.menu.menu_commands import TRAINING_COMMANDS
from src.menu.pages.page_base import PageBase
from src.menu.typing import T_MENU_PAGE_NAME


class TrainingPage(PageBase):

    @property
    def name(self) -> T_MENU_PAGE_NAME:
        """Name of the page"""
        return "Training"

    @property
    def help_text(self) -> str:
        """Help text for specific page"""
        return """start           - Start training mode
            """

    @property
    def commands(self) -> list:
        """Ask before closing app if KeyboardInterrupt"""
        return TRAINING_COMMANDS

    def exit_handler(self) -> None:
        """function to handle KeyboardInterrupt"""
        print_color('Exit training.', "green")
        self.menu.show_root()

    def proceed_command(self, command: str) -> None:
        if command == 'start':
            self.start_training_mode()

    def start_training_mode(self):
        """
        Start the training mode.
        :return: None
        """
        if not self.is_session_set:
            return
        ec2_resource = self.scanner.session.resource('ec2')
        iam_resource = self.scanner.session.resource('iam')
        ssm_client = self.scanner.session.client('ssm')
        iam_client = self.scanner.session.client('iam')
        with indent(6, quote=">>>>"):
            print_color("[*] Training mode entered")
            print_color("[..] preparing environment.... \n[..] Creating Assume Role Policy...")
            role_name = f"role{id_generator()}"
            print_color(f"[..] Creating role with name: {role_name}")
            role = iam_resource.create_role(RoleName=role_name,
                                            AssumeRolePolicyDocument=json.dumps(ASSUME_ROLE_POLICY_DATA)
                                            )
            print_color("[+] Role created successfully.")
            print_color("[..] Attaching needed policies for role...")
            response_for_role = iam_client.attach_role_policy(
                RoleName=role.name, PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM')
            print_color(f"[+] Role attached successfully to policy AmazonEC2RoleforSSM. {response_for_role}")
            print_color("[..] Creating EC2 instance profile and adding it to role...")
            instance_profile = iam_resource.create_instance_profile(
                InstanceProfileName=role.name)
            instance_profile.add_role(RoleName=role.name)

            device_os, ami_name = self.choose_training_ami()
            print_color(f"[+] OS chosen is: {device_os}\n[+] Amazon AMI used is: {ami_name}")
            ami_images = list(ec2_resource.images.filter(Filters=[{'Name': 'name', 'Values': [ami_name, ]}]))
            ami_id = ami_images[0].image_id
            print_color('[..] Now creating EC2 instance of type t2.micro with this AMI....')
            time.sleep(10)
            new_instances = ec2_resource.create_instances(
                ImageId=ami_id,
                InstanceType='t2.micro',
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={'Name': role.name}
            )
            new_instance = new_instances[0]
            print_color('[+] EC2 instance id is: %s' % new_instance.id)
            print_color('[..] Waiting for EC2 instance to complete running..... This will take a while')
            new_instance.wait_until_running()
            new_instance.reload()
            print_color('[+] EC2 instance state is: %s' % new_instance.state)
            payload, action, disable_av = shell_script_options(device_os)

            print_color('[..] Sending the command "%s" to the running instance....' % payload)
            time.sleep(10)
            match device_os:
                case 'linux':
                    success = run_linux_command(ssm_client, new_instance.id, action, payload)
                case _:
                    print_color(
                        '[..] Waiting for Windows EC2 instance to be ready... waiting for 2 minutes...')
                    time.sleep(120)
                    success = run_windows_command(
                        ssm_client, new_instance.id, action, payload, disable_av)
            #########
            print_color(
                f"[+] Training mode done {'successfully' if success else 'with error'}... "
                "Now terminating EC2 instance and deleting IAM role...")
            new_instance.terminate()
            print_color('[..] Waiting for instance to be terminated...')
            new_instance.wait_until_terminated()
            print_color('[+] EC2 instance terminated. Now detaching policy and deleting role...')
            instance_profile.remove_role(RoleName=role.name)
            instance_profile.delete()
            role.detach_policy(PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM')
            role.delete()
            print_color('[+] Done!')
        self.menu.show_root()

    @staticmethod
    def choose_training_ami() -> (str, str):
        """
        Choose the AMI name for the training mode based on the OS choice.
        :return: Tuple of OS and AMI name.
        """
        print_color('[*] Choose your EC2 OS:')
        ami = prompt.options('Options:', AMI_OPTIONS)
        if ami == 'windows':
            return "windows", 'Windows_Server-2019-English-Full-Base-2019.01.10'
        return "linux", 'amzn2-ami-hvm-2.0.20190115-x86_64-gp2'
