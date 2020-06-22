############################################################################
# This is demo code and not intended for use in production.  As such this
# code demonstrates how to send events from an Azure Function to an
# Event Hub.
#
# USE AT YOUR OWN RISK!!!
#
# Author: Sajit Sasi
# Author Email: sajit.sasi@microsoft.com
############################################################################
import logging

import azure.functions as func
from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
from azure.mgmt.keyvault import KeyVaultManagementClient
#from azure.keyvault import KeyVaultClient, KeyVaultId, KeyVaultAuthentication
from msrestazure.azure_cloud import AZURE_PUBLIC_CLOUD
from msrestazure.azure_active_directory import MSIAuthentication
from azure.eventhub import EventHubProducerClient, EventData
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os
import json
import requests
import datetime
import adal


def get_azure_credentials():
    from msrestazure.azure_active_directory import MSIAuthentication
    logger = logging.getLogger(__name__)
    credentials = MSIAuthentication()
    '''
    subscription_client = SubscriptionClient(credentials)
    subscription = next(subscription_client.subscriptions.list())
    subscription_id = subscription.subscription_id
    '''
    subscription_id = os.environ['AZURE_SUBSCRIPTION_ID']
    kv_credential = DefaultAzureCredential()
    logger.debug(f"returning sub_id --> {subscription_id}")
    return credentials, kv_credential, subscription_id


def get_local_credentials(resource=None):
    from azure.common.credentials import ServicePrincipalCredentials
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

    os.environ['AZURE_TENANT_ID'] = data['tenantId']
    os.environ['AZURE_CLIENT_ID'] = data['clientId']
    os.environ['AZURE_CLIENT_SECRET'] = data['clientSecret']
    os.environ['AZURE_SUBSCRIPTION_ID'] = data['subscriptionId']
    tenant_id = data['tenantId']
    client_id = data['clientId']
    client_secret = data['clientSecret']
    credential = ServicePrincipalCredentials(
        tenant=tenant_id,
        client_id=client_id,
        secret=client_secret)
    kv_credential = DefaultAzureCredential(
        exclude_managed_identity_credential=True)
    return credential, kv_credential, data['subscriptionId']


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
        credentials, kv_credentials, subscription_id = get_local_credentials()
    else:
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(formatter)
        credentials, kv_credentials, subscription_id = get_azure_credentials()

    logger.debug('Python HTTP trigger function processed a request.')
    logger.debug(f"method={req.method}, url={req.url}, params={req.params}")
    logger.debug(f"body={req.get_json()}")

    # Handle WebHook
    webhook = req.get_json()
    # Get resource information specifically tags if this is an alert
    resource_id = None
    if "azureMonitorCommonAlertSchema" in webhook["schemaId"]:
        if check_keys(webhook, 'data', 'essentials', 'alertTargetIDs'):
            resource_id = webhook["data"]["essentials"]["alertTargetIDs"]

    if resource_id:
        resource_client = ResourceManagementClient(
            credentials, subscription_id)
        try:
            resource = resource_client.resources.get_by_id(
                resource_id[0], api_version='2018-06-01')
            if resource.tags:
                #                webhook['resource_tags'] = resource.tags
                logger.info(f"found resource tags {resource.tags}")
            else:
                logger.info(f"no tags found in resource {resource_id}")
        except:
            logger.error(
                f"received exception from ResourceManagementClient for {resource_id}")
    else:
        logger.info("no resource_id found in webhook")

    subscription_client = SubscriptionClient(credentials)
    subscription = next(subscription_client.subscriptions.list())
    webhook['additionalData'] = {}
    if 'motsID' in subscription.tags.keys():
        webhook['additionalData']['motsID'] = subscription.tags['motsID']

    logger.info(f"added subscription tags={subscription.tags}")

    # Key Vault stuff
    kv_mgmt_client = KeyVaultManagementClient(credentials, subscription_id)
#    kv_client = KeyVaultClient(credentials)
    kv_client = SecretClient(
        vault_url=os.environ['KEY_VAULT_URI'], credential=kv_credentials)
    namespace = kv_client.get_secret('EventHubNamespace').value
    event_hub = kv_client.get_secret('EventHub').value
    user = kv_client.get_secret('EventHubKeyName').value
    key = kv_client.get_secret('EventHubKey').value
    # Check whether connection string exists in Key Vault
    kv_prop = kv_client.list_properties_of_secrets()
    if 'EventHubConnectionString' in [prop.name for prop in kv_prop]:
        conn_string = get_kv_secret(
            kv_client, 'EventHubConnectionString').value
    else:
        conn_string = f"Endpoint=sb://{namespace}.servicebus.windows.net/;SharedAccessKeyName={user};SharedAccessKey={key}"

    eh_prod_client = EventHubProducerClient.from_connection_string(
        conn_string, eventhub_name=event_hub)
    event_data_batch = eh_prod_client.create_batch()
    event_data_batch.add(EventData(json.dumps(webhook)))
    eh_prod_client.send_batch(event_data_batch)
    logger.info(f"sending event to {namespace}, {json.dumps(webhook)}")
    date = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")
    return func.HttpResponse(
        json.dumps({
            'date': date,
            'status': 'SUCCESS'
        })
    )
