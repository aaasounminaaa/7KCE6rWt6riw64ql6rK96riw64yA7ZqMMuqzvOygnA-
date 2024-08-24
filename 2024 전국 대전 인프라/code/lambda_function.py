

import json
import boto3
import urllib3

def get_alb_endpoint(region_name):
    elb = boto3.client('elbv2', region_name=region_name)
    
    response = elb.describe_load_balancers()
    
    alb_dns_names = []
    for lb in response['LoadBalancers']:
        if lb['Type'] == 'application':
            alb_dns_names.append(lb['DNSName'])
    
    return alb_dns_names

def alb_healthcheck(dns_lists, uri_path):
    http = urllib3.PoolManager()
    uri = uri_path.split("/")[2]
    
    seoul_health = http.request('GET', f"http://{dns_lists[0]}/healthcheck?path={uri}").status
    us_health = http.request('GET', f"http://{dns_lists[1]}/healthcheck?path={uri}").status
    
    response = {
        "seoul": { 
            "state": "healthy" if int(seoul_health) == 200 else "unhealthy",
            "url": f"{dns_lists[0]}" if int(seoul_health) == 200 else ""
            
        },
        "us": { 
            "state": "healthy" if int(us_health) == 200 else "unhealthy",
            "url": f"{dns_lists[1]}" if int(us_health) == 200 else ""
            
        }
    }
    
    return response

def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']
    headers = request['headers']
    origin = request['origin']
    uri = request['uri']
    
    region_list = ['ap-northeast-2', 'us-east-1']
    region_alb_dns = []
    
    for region in region_list:
        alb_dns_name = get_alb_endpoint(region)
        region_alb_dns.extend(alb_dns_name)
    
    healthcheck_response = alb_healthcheck(region_alb_dns, uri)
    
    if healthcheck_response["seoul"]["state"] == "healthy":
        # headers["host"] = [{"key": "host", "value": healthcheck_response["seoul"]["url"]}]
        origin["custom"]["domainName"] = healthcheck_response["seoul"]["url"]
        origin["custom"]["port"] = 80
        origin["custom"]["protocol"] = "http"
        origin["custom"]["path"] = ""
        # del origin["custom"]["sslProtocols"]
    elif healthcheck_response["us"]["state"] == "healthy":
        # headers['host'] = [{"key": "host", "value": healthcheck_response["seoul"]["url"]}]
        origin["custom"]["domainName"] = healthcheck_response["us"]["url"]
        origin["custom"]["port"] = 80
        origin["custom"]["protocol"] = "http"
        origin["custom"]["path"] = ""
        # del origin["custom"]["sslProtocols"]
    
    
    return request