import requests
import json
import sys
import os
import base64
import time
import webbrowser

# ============================================================
# CONFIGURATION
# ============================================================
TENANT_ID             = "cab1718c-4f3f-432f-9ed9-03aaac4908a7"
CLIENT_ID             = "7719b107-6de8-4ebb-a239-3f3bfaad8fea"
# ✅ NO CLIENT SECRET — user authenticates interactively via browser

PROJECT_NUMBER        = "238647468466"
PROJECT_ID            = "prefab-bounty-480110-d2"
SERVICE_ACCOUNT_EMAIL = "azure-wif-sa@prefab-bounty-480110-d2.iam.gserviceaccount.com"
WORKLOAD_POOL_ID      = "azure-pool1"
PROVIDER_ID           = "azure-provider"

REGION = "us-central1"
MODEL  = "gemini-2.5-flash"

# Scope: openid + profile = standard OIDC claims (iss, sub, aud, email)
# api://<CLIENT_ID>/.default = your app's own scope (sets correct 'aud' for GCP STS)
SCOPES = f"openid profile api://{CLIENT_ID}/.default"


# ============================================================
# HELPER: Decode JWT payload without signature verification
# ============================================================
def decode_jwt_payload(token: str) -> dict:
    try:
        payload_b64 = token.split(".")[1]
        padding = 4 - len(payload_b64) % 4
        payload_b64 += "=" * (padding % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception as e:
        return {"error": str(e)}


# ============================================================
# STEP 1: Device Code Flow — user logs in via browser
#
# How it works:
#   1. Script requests a device_code from Entra
#   2. Entra returns a short code + verification URL
#   3. Script prints the code and opens the browser
#   4. User visits the URL, enters the code, and signs in
#   5. Script polls Entra until login is complete
#   6. Entra returns a JWT bound to the USER's identity
#
# ✅ No client secret needed anywhere
# ✅ Token is tied to the individual user's Entra account
# ✅ Full audit trail in Entra sign-in logs per user
# ✅ Only users assigned to the app can log in
#    (enforced by Assignment Required = Yes on the app)
# ============================================================
def get_azure_jwt_device_code() -> str:

    # --- 1a. Request a device code from Entra ---
    device_code_url = (
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"
    )
    resp = requests.post(device_code_url, data={
        "client_id": CLIENT_ID,
        "scope":     SCOPES,
    })

    if resp.status_code != 200:
        print(f"[ERROR] Failed to get device code  (HTTP {resp.status_code})")
        print(resp.text)
        print()
        print("  Checklist:")
        print("  - Is 'Allow public client flows' ENABLED in Entra app registration?")
        print("    Portal → App Registrations → your app → Authentication → ")
        print("    Advanced settings → Allow public client flows → YES")
        print("  - Is the CLIENT_ID correct?")
        sys.exit(1)

    device_data      = resp.json()
    device_code      = device_data["device_code"]
    user_code        = device_data["user_code"]
    verification_url = device_data["verification_uri"]
    expires_in       = device_data.get("expires_in", 900)
    poll_interval    = device_data.get("interval", 5)

    # --- 1b. Show login instructions ---
    print()
    print("=" * 60)
    print("  ACTION REQUIRED — Sign in to continue")
    print("=" * 60)
    print(f"  1. Open this URL in your browser:")
    print(f"     {verification_url}")
    print()
    print(f"  2. Enter this one-time code when prompted:")
    print(f"     >>> {user_code} <<<")
    print()
    print(f"  (Code expires in {expires_in // 60} minutes)")
    print("=" * 60)

    # Auto-open browser if possible
    try:
        webbrowser.open(verification_url)
        print("  [INFO] Browser opened automatically.")
    except Exception:
        print("  [INFO] Could not open browser — please open the URL manually.")

    print()
    print("[...] Waiting for you to complete sign-in in the browser ...")
    print()

    # --- 1c. Poll Entra until user completes login ---
    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    elapsed   = 0

    while elapsed < expires_in:
        time.sleep(poll_interval)
        elapsed += poll_interval

        poll_resp = requests.post(token_url, data={
            "client_id":   CLIENT_ID,
            "grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
        })

        poll_data = poll_resp.json()

        if "access_token" in poll_data:
            token  = poll_data["access_token"]
            claims = decode_jwt_payload(token)

            print("[OK]  Sign-in successful!")
            print(f"      User : {claims.get('upn') or claims.get('preferred_username') or claims.get('email', 'n/a')}")
            print(f"      iss  : {claims.get('iss', 'n/a')}")
            print(f"      aud  : {claims.get('aud', 'n/a')}   <-- GCP STS validates this")
            print(f"      sub  : {claims.get('sub', 'n/a')}   <-- WIF identity principal")
            return token

        error = poll_data.get("error", "")

        if error == "authorization_pending":
            print(f"      ... waiting for sign-in  ({elapsed}s elapsed)")
            continue
        elif error == "slow_down":
            poll_interval += 5
            continue
        elif error == "authorization_declined":
            print("[ERROR] User declined the sign-in request.")
            sys.exit(1)
        elif error == "expired_token":
            print("[ERROR] Code expired. Please re-run the script.")
            sys.exit(1)
        else:
            print(f"[ERROR] Unexpected polling error: {poll_data}")
            sys.exit(1)

    print("[ERROR] Sign-in timed out. Please re-run the script.")
    sys.exit(1)


# ============================================================
# STEP 2: Exchange Azure JWT → GCP federated token via STS
# ============================================================
def exchange_with_gcp_sts(azure_jwt: str) -> str:
    audience = (
        f"//iam.googleapis.com/projects/{PROJECT_NUMBER}"
        f"/locations/global/workloadIdentityPools/{WORKLOAD_POOL_ID}"
        f"/providers/{PROVIDER_ID}"
    )

    payload = {
        "audience":           audience,
        "grantType":          "urn:ietf:params:oauth:grant-type:token-exchange",
        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
        "subjectTokenType":   "urn:ietf:params:oauth:token-type:jwt",
        "subjectToken":       azure_jwt,
        "scope":              "https://www.googleapis.com/auth/cloud-platform",
    }

    print("\n[2/4] Exchanging Azure JWT with GCP STS ...")
    resp = requests.post("https://sts.googleapis.com/v1/token", json=payload)

    if resp.status_code != 200:
        print(f"[ERROR] GCP STS exchange failed  (HTTP {resp.status_code})")
        print(resp.text)
        print()
        print("  Checklist:")
        print("  - Application ID URI set to  api://<CLIENT_ID>  in Entra?")
        print("  - 'aud' in JWT matches  allowedAudiences  in GCP WIF provider?")
        print("  - 'iss' in JWT matches  issuerUri  in GCP WIF provider?")
        print("  - Pool ID and Provider ID spelling correct above?")
        sys.exit(1)

    print("[OK]  GCP federated (STS) token obtained")
    return resp.json()["access_token"]


# ============================================================
# STEP 3: Impersonate Service Account
# ============================================================
def impersonate_service_account(gcp_sts_token: str) -> str:
    url = (
        f"https://iamcredentials.googleapis.com/v1/projects/-/"
        f"serviceAccounts/{SERVICE_ACCOUNT_EMAIL}:generateAccessToken"
    )

    headers = {"Authorization": f"Bearer {gcp_sts_token}"}
    body    = {"scope": ["https://www.googleapis.com/auth/cloud-platform"]}

    print("\n[3/4] Impersonating Service Account ...")
    resp = requests.post(url, headers=headers, json=body)

    if resp.status_code != 200:
        print(f"[ERROR] SA impersonation failed  (HTTP {resp.status_code})")
        print(resp.text)
        print()
        print("  Checklist:")
        print("  - WIF principal granted  roles/iam.workloadIdentityUser  on the SA?")
        print("  - Use pool-level binding so ALL assigned users can impersonate:")
        print("    principalSet://iam.googleapis.com/projects/<NUM>/locations/global/")
        print("    workloadIdentityPools/<POOL_ID>/*")
        sys.exit(1)

    print(f"[OK]  Impersonated SA: {SERVICE_ACCOUNT_EMAIL}")
    return resp.json()["accessToken"]


# ============================================================
# STEP 4: Call Vertex AI Gemini
# ============================================================
def call_vertex_ai(sa_token: str):
    url = (
        f"https://{REGION}-aiplatform.googleapis.com/v1/"
        f"projects/{PROJECT_ID}/locations/{REGION}/"
        f"publishers/google/models/{MODEL}:generateContent"
    )

    headers = {
        "Authorization": f"Bearer {sa_token}",
        "Content-Type":  "application/json",
    }

    body = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": "Explain Workload Identity Federation in GCP in simple terms"}],
            }
        ]
    }

    print(f"\n[4/4] Calling Vertex AI  model={MODEL}  region={REGION} ...")
    resp = requests.post(url, headers=headers, json=body)

    if resp.status_code != 200:
        print(f"[ERROR] Vertex AI call failed  (HTTP {resp.status_code})")
        print(resp.text)
        print()
        print("  Checklist:")
        print("  - SA has  roles/aiplatform.user  on the project?")
        print("  - Vertex AI API enabled in the project?")
        print("  - Correct model name and region?")
        sys.exit(1)

    answer = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    print("\n[OK]  Vertex AI response:")
    print("=" * 60)
    print(answer)
    print("=" * 60)


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  Azure Entra ID  →  GCP WIF  →  Vertex AI Gemini")
    print("  Auth: Device Code Flow  (no client secret)")
    print("=" * 60)

    print("\n[1/4] Starting interactive sign-in (Device Code Flow) ...")
    azure_jwt = get_azure_jwt_device_code()
    gcp_token = exchange_with_gcp_sts(azure_jwt)
    sa_token  = impersonate_service_account(gcp_token)
    call_vertex_ai(sa_token)
