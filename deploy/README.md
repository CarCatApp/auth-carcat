# Auth on DOKS

Shared chart: [`CarCatApp/charts`](https://github.com/CarCatApp/charts) (`carcat-app`).  
Values in this repo under `deploy/`.

## Safety

- **preprod only** via `deploy/install-preprod.sh` and workflow `deploy-doks-preprod.yml`
- Existing `cicd.yml` still deploys the **droplet** — unchanged
- Does not change DNS / nginx / production traffic

## Bootstrap (once)

```bash
# 1) chart tag 0.1.1 pushed on CarCatApp/charts
# 2) secret in cluster
chmod +x deploy/install-secret-preprod.sh deploy/install-preprod.sh
./deploy/install-secret-preprod.sh

# 3) install (uses local charts checkout if present)
./deploy/install-preprod.sh
```

Repo secrets for GitHub Actions (`deploy-doks-preprod.yml`):

| Secret | Purpose |
|--------|---------|
| `DOCKER_USERNAME` / `DOCKER_PASSWORD` | already used by cicd.yml |
| `KUBE_CONFIG` | base64 DOKS kubeconfig |
| `CHARTS_READ_TOKEN` | optional PAT if private charts + GITHUB_TOKEN can't read |

GitHub Environment **`preprod`** (optional protection rules).
