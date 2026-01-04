import requests
import json
import sys
import base64
import os

# -----------------------------
# CONFIGURATION - EDIT THESE
# -----------------------------
TENANT_ID = "cab1718c-4f3f-432f-9ed9-03aaac4908a7"   # Azure tenant ID
CLIENT_ID = "7719b107-6de8-4ebb-a239-3f3bfaad8fea"   # Azure App Registration (Application ID)
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")     # Read securely from environment variable
PROJECT_NUMBER = "238647468466"                      # Numeric GCP project number
PROJECT_ID = "prefab-bounty-480110-d2"           # String GCP project ID
SERVICE_ACCOUNT_EMAIL = "azure-wif-sa@prefab-bounty-480110-d2.iam.gserviceaccount.com"
WORKLOAD_POOL_ID = "azure-pool1"
PROVIDER_ID = "azure-provider"


# -----------------------------
# STEP 1: Get Azure JWT
# -----------------------------
def get_azure_jwt():
    if not CLIENT_SECRET:
        print("[ERROR] AZURE_CLIENT_SECRET environment variable not set")
        sys.exit(1)

    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": f"{CLIENT_ID}/.default",
        "grant_type": "client_credentials"
    }
    print(f"[INFO] Requesting Azure token from: {token_url}")
    resp = requests.post(token_url, data=data)
    print(f"[INFO] Azure response code: {resp.status_code}")
    if resp.status_code != 200:
        print("[ERROR] Azure token request failed:", resp.text)
        sys.exit(1)
    print("[OK] Azure JWT obtained")
    return resp.json()["access_token"]

# -----------------------------
# Helper: Decode JWT claims
# -----------------------------
def decode_jwt(jwt_token):
    parts = jwt_token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1] + "=" * (-len(parts[1]) % 4)  # pad base64
    decoded = base64.urlsafe_b64decode(payload)
    return json.loads(decoded)

# -----------------------------
# STEP 2: Exchange with GCP STS
# -----------------------------
def exchange_with_gcp_sts(azure_jwt):
    sts_url = "https://sts.googleapis.com/v1/token"
    audience = f"//iam.googleapis.com/projects/{PROJECT_NUMBER}/locations/global/workloadIdentityPools/{WORKLOAD_POOL_ID}/providers/{PROVIDER_ID}"
    payload = {
        "audience": audience,
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
        "subjectToken": azure_jwt,
        "scope": "https://www.googleapis.com/auth/cloud-platform"
    }
    print(f"[INFO] Exchanging token with GCP STS (audience={audience})")
    resp = requests.post(sts_url, json=payload)
    print(f"[INFO] STS response code: {resp.status_code}")
    if resp.status_code != 200:
        print("[ERROR] STS exchange failed:", resp.text)
        sys.exit(1)
    print("[OK] STS exchange succeeded")
    return resp.json()["access_token"]

# -----------------------------
# STEP 3: Impersonate Service Account
# -----------------------------
def impersonate_service_account(gcp_token):
    url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{SERVICE_ACCOUNT_EMAIL}:generateAccessToken"
    headers = {"Authorization": f"Bearer {gcp_token}"}
    body = {
        "scope": ["https://www.googleapis.com/auth/cloud-platform"]
    }
    print(f"[INFO] Impersonating service account: {SERVICE_ACCOUNT_EMAIL}")
    resp = requests.post(url, headers=headers, json=body)
    print(f"[INFO] IAM impersonation response code: {resp.status_code}")
    if resp.status_code != 200:
        print("[ERROR] Impersonation failed:", resp.text)
        sys.exit(1)
    print("[OK] Impersonation succeeded")
    return resp.json()["accessToken"]

# -----------------------------
# STEP 4: Call GCP Secret Manager API
# -----------------------------
def call_gcp_secret_manager(sa_token, secret_name):
    headers = {"Authorization": f"Bearer {sa_token}"}
    url = f"https://secretmanager.googleapis.com/v1/projects/{PROJECT_ID}/secrets/{secret_name}/versions/latest:access"
    print(f"[INFO] Calling Secret Manager for secret: {secret_name}")
    resp = requests.get(url, headers=headers)
    print(f"[INFO] Secret Manager response code: {resp.status_code}")
    if resp.status_code != 200:
        print("[ERROR] Secret Manager API call failed:", resp.text)
        sys.exit(1)
    secret_data = resp.json()["payload"]["data"]
    print("[OK] Secret retrieved successfully")
    print("[INFO] Secret value (base64 decoded):", base64.b64decode(secret_data).decode("utf-8"))

# -----------------------------
# MAIN FLOW
# -----------------------------
if __name__ == "__main__":
    print("[INFO] Starting Azure -> GCP WIF flow")

    print("[INFO] Getting Azure JWT...")
    azure_jwt = get_azure_jwt()
    print("[INFO] Decoded Azure JWT claims:")
    print(json.dumps(decode_jwt(azure_jwt), indent=2))

    print("[INFO] Exchanging with GCP STS...")
    gcp_token = exchange_with_gcp_sts(azure_jwt)

    print("[INFO] Impersonating Service Account...")
    sa_token = impersonate_service_account(gcp_token)

    print("[INFO] Calling GCP Secret Manager API...")
    call_gcp_secret_manager(sa_token, SECRET_NAME)
