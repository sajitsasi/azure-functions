import logging

import azure.functions as func
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault import KeyVaultClient, KeyVaultId, KeyVaultAuthentication
from msrestazure.azure_cloud import AZURE_PUBLIC_CLOUD
from msrestazure.azure_active_directory import MSIAuthentication
from azure.eventhub import EventHubClient, Sender, EventData
import os
import json
import requests
import datetime
import adal


def get_azure_credentials():
    from msrestazure.azure_active_directory import MSIAuthentication
    logger = logging.getLogger(__name__)
    logger.debug("starting")
    credentials = MSIAuthentication()
    logger.debug("got credentials")
    # Issue with subscription_client.subscriptions.list() iteration hanging,
    # using this an APP_SETTING instead
    '''
    subscription_client = SubscriptionClient(credentials)
    logger.debug("got subscription_client")
    for x in subscription_client.subscriptions.list():
        logger.debug(x)
    logger.debug("done printing list")
    subscription = next(subscription_client.subscriptions.list())
    logger.debug("got subscription")
    subscription_id = subscription.subscription_id
    '''
    subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
    logger.debug(f"returning sub_id --> {subscription_id}")
    return credentials, subscription_id


def get_local_credentials(resource=None):
    from msrestazure.azure_active_directory import AdalAuthentication
    logger = logging.getLogger(__name__)
    data = json.load(open("./sp.json"))
    if not ('clientId' in data or 'clientSecret' in data or
            'subscriptionId' in data or 'tenantId' in data):
        logger.error(
            "did not find either clientId, clientSecret, subscriptionId of tenantId in file")
        return None, None
    else:
        logger.debug(
            f"found clientId={data['clientId']} in sub={data['subscriptionId']}")

    if not resource:
        resource = "https://management.core.windows.net"
    server = resource + '/' + data['tenantId']
    context = adal.AuthenticationContext(server)
    credentials = AdalAuthentication(
        context.acquire_token_with_client_credentials,
        AZURE_PUBLIC_CLOUD.endpoints.active_directory_resource_id,
        data['clientId'],
        data['clientSecret']
    )
    return credentials, data['subscriptionId']


def get_kv_secret(client=None, secret_key=None):
    logger = logging.getLogger(__name__)
    if not client or not secret_key:
        logger.error("no client or secret specified")
        return None

    vault_url = os.environ['KEY_VAULT_URI']
    secret = client.get_secret(vault_url, secret_key, KeyVaultId.version_none)
    return secret.value


def get_sas_token(namespace, event_hub, user, key):
    import urllib.parse
    import hmac
    import hashlib
    import base64
    import time

    if not (namespace or event_hub or user or key):
        return None
    uri = urllib.parse.quote_plus(
        "https://{}.servicebus.windows.net/{}".format(namespace, event_hub))
    sas = key.encode('utf-8')
    expiry = str(int(time.time() + 10000))
    string_to_sign = (uri + '\n' + expiry).encode('utf-8')
    signed_hmac_sha256 = hmac.HMAC(sas, string_to_sign, hashlib.sha256)
    signature = urllib.parse.quote(
        base64.b64encode(signed_hmac_sha256.digest()))
    return "SharedAccessSignature sr={}&sig={}&se={}&skn={}".format(uri, signature, expiry, user)


def get_http_header(namespace, event_hub, user, key):
    if not (namespace or event_hub or user or key):
        return None

    headers = {}
    headers['Content'] = "application/atom+xml;type=entry;charset=utf-8"
    headers['Authorization'] = get_sas_token(namespace, event_hub, user, key)
    headers['Host'] = "{}.servicebus.windows.net".format(namespace)
    return headers


def get_http_params():
    params = {}
    params['timeout'] = 60
    params['api-version'] = "2014-01"
    return params


def parse_webhook_data(webhook=None):
    logger = logging.getLogger(__name__)
    if not webhook:
        logger.debug("ERROR: no webhook data received!!!")
        return None

    start = webhook.find("RequestBody:")
    end = webhook.find("RequestHeader:")
    if start < 0 or end < 0:
        logger.debug(
            "ERROR: couldn't find markers in webhook {}".format(webhook))
        return None
    data = webhook[(start+12):(end-1)]
    return (json.loads(data))


def check_keys(d, *keys):
    if not isinstance(d, dict) or len(keys) == 0:
        return False
    
    dt = d
    for key in keys:
        try:
            dt = dt[key]
        except KeyError:
            return False
    return True


def main(req: func.HttpRequest) -> func.HttpResponse:
    logger = logging.getLogger(__name__)
    formatter = logging.Formatter(
        '%(asctime)s %(name)s %(levelname)s: %(message)s')
    func_context = os.environ['FUNCTION_CONTEXT']
    logger.debug(f"Function context --> {func_context}")

    credentials = None
    subscription_id = None
    kv_credentials = None
    kv_subscription_id = None
    if func_context == 'local':
        filehandler = logging.FileHandler('func.log')
        filehandler.setFormatter(formatter)
        logger.addHandler(filehandler)
        logger.setLevel(logging.DEBUG)
        credentials, subscription_id = get_local_credentials()
    else:
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(formatter)
        credentials, subscription_id = get_azure_credentials()

    logger.debug('Python HTTP trigger function processed a request.')
    logger.debug(f"method={req.method}, url={req.url}, params={req.params}")
    logger.debug(f"body={req.get_json()}")

    # Handle WebHook
    webhook = req.get_json()
    # Get resource information specifically tags if this is an alert
    resource_id = None
    if check_keys(webhook, 'data', 'context', 'resourceId'):
        resource_id = webhook['data']['context']['resourceId']
    elif check_keys('data', 'context', 'activityLog', 'resourceId'):
        resource_id = webhook['data']['context']['activityLog']['resourceId']
    elif check_keys('data', 'context', 'scope'):
        resource_id = webhook['data']['context']['scope']

    if resource_id:
        resource_client = ResourceManagementClient(credentials, subscription_id)
        resource = resource_client.resources.get_by_id(resource_id, api_version='2018-06-01')
        if resource.tags:
            webhook['tags'] = resource.tags
            logger.info(f"adding tags {resource.tags}")
        else:
            logger.info(f"no tags found in resource {resource_id}")
    else:
        logger.info("no resource_id found in webhook")

    # Key Vault stuff
    kv_mgmt_client = KeyVaultManagementClient(credentials, subscription_id)
    kv_client = KeyVaultClient(credentials)
    namespace = get_kv_secret(kv_client, 'EventHubNamespace')
    event_hub = get_kv_secret(kv_client, 'EventHub')
    user = get_kv_secret(kv_client, 'EventHubKeyName')
    key = get_kv_secret(kv_client, 'EventHubKey')

    amqp_uri = f"https://{namespace}.servicebus.windows.net/{event_hub}"
    eh_client = EventHubClient(
        amqp_uri, debug=False, username=user, password=key)
    eh_sender = eh_client.add_sender(partition="0")
    eh_client.run()
    eh_sender.send(EventData(json.dumps(webhook)))
    logger.info(f"sending event to {amqp_uri}, {json.dumps(webhook)}")
    date = datetime.datetime.now()
    return func.HttpResponse(
        json.dumps({
            'status': 'SUCCESS'
        })
    )