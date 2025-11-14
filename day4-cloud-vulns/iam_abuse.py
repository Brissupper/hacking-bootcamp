import boto3

sts = boto3.client('sts')
response = sts.assume_role(
    RoleArn='arn:aws:iam::123456789012:role/AssumeMeRole',
    RoleSessionName='AbuseSession'
)
creds = response['Credentials']
s3_abuse = boto3.client(
    's3',
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['SessionToken']
)
buckets = s3_abuse.list_buckets()
for b in buckets['Buckets']:
    print(f"Abused bucket: {b['Name']}")
