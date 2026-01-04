import requests
import json
import sys
import os

# -----------------------------
# CONFIGURATION
# -----------------------------
TENANT_ID = "cab1718c-4f3f-432f-9ed9-03aaac4908a7"
CLIENT_ID = "7719b107-6de8-4ebb-a239-3f3bfaad8fea"
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")

PROJECT_NUMBER = "238647468466"
PROJECT_ID = "prefab-bounty-480110-d2"

SERVICE_ACCOUNT_EMAIL = "azure-wif-sa@prefab-bounty-480110-d2.iam.gserviceaccount.com"
WORKLOAD_POOL_ID = "azure-pool1"
PROVIDER_ID = "azure-provider"

REGION = "us-central1"
MODEL = "gemini-2.5-flash"  # ✅ FIXED MODEL

# -----------------------------
# STEP 1: Azure JWT
# -----------------------------
def get_azure_jwt():
    if not CLIENT_SECRET:
        print("[ERROR] AZURE_CLIENT_SECRET not set")
        sys.exit(1)

    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": f"{CLIENT_ID}/.default"
    }

    resp = requests.post(url, data=data)
    if resp.status_code != 200:
        print("[ERROR] Azure token failed:", resp.text)
        sys.exit(1)

    print("[OK] Azure JWT obtained")
    return resp.json()["access_token"]

# -----------------------------
# STEP 2: STS Exchange
# -----------------------------
def exchange_with_gcp_sts(azure_jwt):
    url = "https://sts.googleapis.com/v1/token"
    audience = (
        f"//iam.googleapis.com/projects/{PROJECT_NUMBER}"
        f"/locations/global/workloadIdentityPools/{WORKLOAD_POOL_ID}"
        f"/providers/{PROVIDER_ID}"
    )

    payload = {
        "audience": audience,
        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
        "subjectToken": azure_jwt,
        "scope": "https://www.googleapis.com/auth/cloud-platform"
    }

    resp = requests.post(url, json=payload)
    if resp.status_code != 200:
        print("[ERROR] STS exchange failed:", resp.text)
        sys.exit(1)

    print("[OK] GCP STS token obtained")
    return resp.json()["access_token"]

# -----------------------------
# STEP 3: Impersonate SA
# -----------------------------
def impersonate_service_account(gcp_token):
    url = (
        f"https://iamcredentials.googleapis.com/v1/projects/-/"
        f"serviceAccounts/{SERVICE_ACCOUNT_EMAIL}:generateAccessToken"
    )

    headers = {"Authorization": f"Bearer {gcp_token}"}
    body = {"scope": ["https://www.googleapis.com/auth/cloud-platform"]}

    resp = requests.post(url, headers=headers, json=body)
    if resp.status_code != 200:
        print("[ERROR] SA impersonation failed:", resp.text)
        sys.exit(1)

    print("[OK] Service Account impersonated")
    return resp.json()["accessToken"]

# -----------------------------
# STEP 4: Vertex AI Gemini
# -----------------------------
def call_vertex_ai(sa_token):
    url = (
        f"https://{REGION}-aiplatform.googleapis.com/v1/"
        f"projects/{PROJECT_ID}/locations/{REGION}/"
        f"publishers/google/models/{MODEL}:generateContent"
    )

    headers = {
        "Authorization": f"Bearer {sa_token}",
        "Content-Type": "application/json"
    }

    body = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": "Explain Workload Identity Federation in GCP in simple terms"}
                ]
            }
        ]
    }

    resp = requests.post(url, headers=headers, json=body)
    if resp.status_code != 200:
        print("[ERROR] Vertex AI call failed:", resp.text)
        sys.exit(1)

    print("[OK] Vertex AI response:")
    print(resp.json()["candidates"][0]["content"]["parts"][0]["text"])

# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    print("=== Azure → GCP → Vertex AI GenAI Test ===")

    azure_jwt = get_azure_jwt()
    gcp_token = exchange_with_gcp_sts(azure_jwt)
    sa_token = impersonate_service_account(gcp_token)
    call_vertex_ai(sa_token)
