import json
import boto3
from botocore.config import Config
from urllib.parse import parse_qs

s3_config = Config(
    region_name='ap-northeast-2',
    signature_version='s3v4',
)

s3 = boto3.client('s3', config=s3_config)

def lambda_handler(event, context):
    file_name = event['Records'][0]['cf']['request']['querystring']
    file_name2=file_name.split('=')
    response = s3.list_buckets()
    s3_bucket = None
    
    for bucket in response['Buckets']:
        if 'wsi-cc-data-' in bucket['Name']:
            s3_bucket = bucket['Name']
            break
    
    presigned_url = s3.generate_presigned_url(
        ClientMethod='get_object',
        Params={
            'Bucket': s3_bucket,
            'Key': 'frontend/' + file_name2[1]
        },
        ExpiresIn=180
    )
    responses = {
        'status': '200',
        'statusDescription': 'OK',
        'headers': {
            'cache-control': [
                {
                    'key': 'Cache-Control',
                    'value': 'max-age=100'
                }
            ],
            "content-type": [
                {
                    'key': 'Content-Type',
                    'value': 'text/html'
                }
            ]
        },
        'body': json.dumps({"uri": presigned_url})
    }
    return responses