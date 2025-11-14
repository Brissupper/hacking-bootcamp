import boto3

s3 = boto3.client('s3', region_name='us-east-1')
bucket = 'misconfig-sim-abcd1234'  # Hypothetical
try:
    objects = s3.list_objects_v2(Bucket=bucket)
    for obj in objects.get('Contents', []):
        print(f"Leaked file: {obj['Key']}")
except Exception as e:
    print(f"Error: {e}")
