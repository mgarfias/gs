#!/usr/bin/env python

import boto3
import yaml
from botocore.client import ClientError

class GlobeSherpa(object):
    def __init__(self,ami,instance_size,instance_count,iam_user,profile_name,bucket_name,keypair_name,user_data,ig_name,vpc_name,ingress_rules,sg_name):
        self.config = {
            'ami': ami,
            'instance_size': instance_size,
            'instance_count': instance_count,
            'iam_user': iam_user,
            'profile_name': profile_name,
            'bucket_name': bucket_name,
            'keypair_name': keypair_name,
            'user_data': user_data,
            'ig_name': ig_name,
            'vpc_name': vpc_name,
            'ingress_rules': ingress_rules,
            'sg_name': sg_name
        }

    @classmethod
    def load_config(cls,config_filepath):
        with open(config_filepath, 'r') as config:
            config_data = yaml.load(config)
            return GlobeSherpa(**config_data)

    def write_keypair(self,kp):
        ssh_filepath = os.path.abspath(
            os.path.expanduser(
                "~/.ssh/%s" % self.config['keypair_name']
            )
        )
        if not os.path.exists(ssh_filepath):
            ssh_key = open(ssh_filepath, 'w')
            ssh_key.write(kp['KeyMaterial'])
            ssh_key.close()
        else:
            print "Private key written"

    def ec2_keypair(self):
        ec2=self.session.client('ec2')
        try:
            kp = ec2.create_key_pair(
                DryRun=False,
                KeyName=self.config['keypair_name']
                )
            self.write_keypair(kp)
        except ClientError:
            pass

    def create_bucket(self):
        s3=self.session.resource('s3')
        return

    def create_vpc(self,ec2):
        client=self.session.client('ec2')
        try:
            vpc=ec2.create_vpc(
                CidrBlock='10.0.0.0/24'
            )
            tag=vpc.create_tags(Tags=[{'Key':'Name','Value': self.config['vpc_name']}])
            ig=ec2.create_internet_gateway()
            ig.attach_to_vpc(VpcId=vpc.id)
            route=list(vpc.route_tables.all())[0]
            client.create_route(RouteTableId=route.id,DestinationCidrBlock="0.0.0.0/0", GatewayId=ig.id)

        except ClientError as e:
            print "Unable to create vpc: %s" % e
            sys.exit(1)
        return vpc

    def create_subnet(self,vpc):
        try:
            subnet=vpc.create_subnet(CidrBlock='10.0.0.0/24')
            subnet.meta.client.modify_subnet_attribute(SubnetId=subnet.id, MapPublicIpOnLaunch={"Value": True})
        except ClientError:
            print "Unable to create subnet"
            sys.exit(1)
        return subnet

    def create_security_group(self,ec2,vpc):
        try:
            sg=vpc.create_security_group(GroupName=self.config['sg_name'],Description="GS Test")
            for rule in self.config['ingress_rules']:
                sg.authorize_ingress(
                  IpProtocol=rule['proto'],
                  CidrIp=rule['from_ip'],
                  FromPort=rule['from_port'],
                  ToPort=rule['to_port']
                )
        except ClientError:
            sys.exit(1)
        return sg

    def create_instance(self):
        ec2=self.session.resource('ec2')
        vpc=self.create_vpc(ec2)
        subnet=self.create_subnet(vpc)
        sg=self.create_security_group(ec2,vpc)
        try:
            instances=ec2.create_instances(
                DryRun=False,
                ImageId=self.config['ami'],
                InstanceType=self.config['instance_size'],
                KeyName=self.config['keypair_name'],
                MinCount=1,
                MaxCount=1,
                PrivateIpAddress = '10.0.0.30',
                SubnetId=subnet.id,
                SecurityGroupIds=[ sg.id ],
                UserData=self.config['user_data']
            )
            print "Instance Public ip: %s" % instances[0].public_ip_address
        except ClientError as e:
            print e
            print "Couldnt create instance"

    def ensure_aws_setup(self):
        """
        Create all the roles/profiles/etc needed to run this thing
        """
        self.ec2_keypair()

    def run(self,profile):
        try:
            self.session = boto3.session.Session(profile_name=profile)
        except:
            print "Could not create the aws session.  Please check credentials."
            sys.exit(1)

        self.ensure_aws_setup()
        self.create_instance()

if __name__ == '__main__':
    import argparse,sys,os,os.path

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--profile',default="default")
    args = parser.parse_args()

    # load our config
    config_filepath = os.path.abspath("./config.yaml")

    # if its not there, bail out
    if not os.path.exists(config_filepath):
        print("No configuration file at: %s.  Creating empty config file." % config_filepath)
        GlobeSherpa.create_config(config_filepath)
        sys.exit(1)

    # conf is there, start this thing up
    gs = GlobeSherpa.load_config(config_filepath)

    # execute run()
    try:
        gs.run(args.profile)
    except KeyboardInterrupt:
        sys.exit(0)
