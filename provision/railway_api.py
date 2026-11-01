"""Minimal Railway GraphQL client. Token comes from RAILWAY_API_TOKEN, never from a file."""
import json, os, time, urllib.error, urllib.request

ENDPOINT = "https://backboard.railway.com/graphql/v2"


class RailwayError(RuntimeError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("; ".join(e.get("message", "?") for e in errors))


def gql(query, variables=None, retries=3):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    headers = {
        "Authorization": "Bearer " + os.environ["RAILWAY_API_TOKEN"],
        "Content-Type": "application/json",
        "User-Agent": "railway-nocodb-client-env/1",
    }
    for attempt in range(retries):
        try:
            req = urllib.request.Request(ENDPOINT, body, headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.load(resp)
            break
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode("utf-8", "replace")
            try:
                data = json.loads(payload)
                break
            except ValueError:
                if attempt == retries - 1:
                    raise RuntimeError(f"HTTP {exc.code}: {payload[:200]}") from exc
        except urllib.error.URLError:
            if attempt == retries - 1:
                raise
        time.sleep(2 ** attempt)
    if data.get("errors"):
        raise RailwayError(data["errors"])
    return data["data"]


def usage(workspace_id):
    q = """query($id:String!){ workspace(workspaceId:$id){ customer{
        creditBalance remainingUsageCreditBalance currentUsage appliedCredits state
        billingPeriod{start end} } } }"""
    return gql(q, {"id": workspace_id})["workspace"]["customer"]
