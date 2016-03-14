import boto3
import yaml
import sys
import os




def load_config(yaml_file):
    stream = open(yaml_file,"r")
    return yaml.load(stream)

def write_access_key_pair(kp):
    # write this to ~/.aws/config
    print kp
    s = "\n[profile %s]\naws_access_key_id = %s\naws_secret_access_key = %s" % (kp.user_name,kp.id, kp.secret)
    aws_config=os.environ.get('HOME')
    aws_config += "/.aws/config"

    f = open(aws_config, 'a')
    f.write(s)
    f.close

def create_user(session,user_name):
    # note that we're still using the root creds here, so no session
    iam = boto3.resource("iam")
    user = iam.User(user_name)
    user.create()
    keypair = user.create_access_key_pair()
    write_access_key_pair(keypair)

def create_s3_bucket(session,config,bucket_name):
    s3 = session.resource('s3')
    print "Making s3 bucket: %s, %s" % (config, bucket_name)
    try:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
                'LocationConstraint': config['aws']['region']
            }
        )
    except:
        print "failed to create s3 bucket"

def create_instance(session,instance_data):
    ec2 = session.resource('ec2')

def create_role(session,role_data):
    iam = boto3.resource("iam")
    #role = iam.Role(role_data['name'])
    role = iam.create_role(
            RoleName=role_data['name'],
            AssumeRolePolicyDocument=json.dumps(self.basic_role_policy))
        self.iam.RolePolicy(self.role_name, 'more-permissions').put(
            PolicyDocument=json.dumps(self.more_permissions_policy))
        return role


def create_instance_profile(session,profile_name):
    iam = session.resource("iam")
    instance_profile = iam.InstanceProfile(profile_name)
