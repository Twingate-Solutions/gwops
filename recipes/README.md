# Recipes

A recipe is a complete deployment for one environment and use case: the seed, the `.env`, the
container runtime setup, what must exist on your Twingate tenant first, and how to verify the
result. Each recipe combines several [guides](../guides/README.md), which explain one capability
in depth, and links to them rather than repeating them. Running and maintaining a deployment
once it is up is covered in [Operations](../operations/README.md).

If you have never deployed the image, the [quickstart](../quickstart/README.md) is the shortest
path to a working gateway. Recipes assume you have read it.

## Choose your recipe

Find the row closest to your environment and requirements. Columns: where the container runs,
what it fronts, where its certificates come from, and how changes reach it.

| Recipe | Host | Fronts | Certificates | Operating model |
| --- | --- | --- | --- | --- |
| [Privileged SSH to a server fleet](ssh-fleet-generated-ca.md) | Docker host | SSH | Generated CAs | Seed, admin API |
| [SSH fleet that already trusts your SSH CA](ssh-fleet-existing-ssh-ca.md) | Docker host | SSH | Your SSH CA from files | Seed, admin API |
| [Kubernetes and web apps with your CA from Vault or a secret store](k8s-and-web-apps-ca-from-secret-store.md) | Docker host | Kubernetes, web apps | Your X.509 and SSH CAs, written by a secrets agent | Seed, admin API |
| [Developer kubectl access to a cluster](developer-kubectl-access.md) | Docker host | Kubernetes | Generated CAs | Seed, admin API |
| [Internal web apps for managed devices](internal-web-apps-managed-devices.md) | Docker host | Web apps | Generated or your X.509 CA, installed on devices | Seed, admin API |
| [Browser-trusted web apps with Let's Encrypt on Cloudflare](public-web-apps-acme-cloudflare.md) | Docker host | Web apps (SSH, Kubernetes optional) | ACME, Cloudflare DNS-01 | Seed |
| [Browser-trusted web apps with certificates you renew](public-web-apps-own-acme-client.md) | Docker host | Web apps (SSH, Kubernetes optional) | Let's Encrypt files from your own ACME client | Seed |
| [SSH, Kubernetes and web apps on one gateway](all-in-one-gateway.md) | Docker host | SSH, Kubernetes, web apps | Generated CAs | Seed, admin API |
| [Private and public gateways on one host](private-and-public-gateways-one-host.md) | Docker host, two containers | Any | Private CA in one, public certificates in the other | Seed |
| [One gateway per remote network or cluster](multiple-remote-networks.md) | Several hosts or containers | Any | Any | One seed per gateway |
| [Adopt a Gateway object that already exists](adopt-existing-gateway.md) | Docker host | Any | Generated or your own | Seed |
| [Seed managed in Git and deployed by CI](gitops-seed.md) | Docker host | Any | Any | GitOps |
| [Upstreams that register themselves](self-registering-upstreams.md) | Docker host | SSH, web apps | Private CA | Automation token |
| [Session recording into your SIEM or log pipeline](recording-to-siem.md) | Docker host | SSH, Kubernetes, web apps | Any | Seed |
| [Restricted egress and outbound proxies](restricted-egress.md) | Docker host behind a proxy | Any | Private CA | Seed |
| [Contractor and vendor access on a separate gateway](third-party-access.md) | Docker host | SSH, web apps | Generated CAs | Seed, admin API |
| [Homelab or small office](homelab-small-office.md) | One small amd64 machine | SSH, web apps | Generated CAs or ACME | Seed |
| [On a cloud VM (AWS, Azure, Google Cloud)](cloud-vm.md) | AWS, Azure or Google Cloud VM | Any | Any | Seed |
| [Inside a Kubernetes cluster (untested)](kubernetes-hosted.md) | Kubernetes pod | Its own cluster API, in-cluster web apps | Private CA | Seed in a ConfigMap |

## Constraints that shape the choice

These hold for every recipe. Each comes from the gateway binary or the seed schema, so no recipe
can work around them.

- **One certificate mode per gateway.** Private CA mode (`ca.x509`) and public certificate mode
  (`public_tls`) are mutually exclusive. To serve both, run two containers.
- **One Kubernetes cluster per gateway.** For a second cluster, run a second container.
- **A bring-your-own X.509 CA needs pinned-gateway mode.** gwops never registers a CA you bring,
  so it cannot create the Gateway object for you. See [Gateway modes](../guides/gateway-modes.md).
- **Public certificate mode serves DNS names only** and only certificates that chain to ISRG
  Root X1. See [Public certificates from files](../guides/public-certs-files.md).
- **`linux/amd64` only.** ARM hosts cannot run the published image.
- **The container needs outbound HTTPS to your tenant.** There is no offline mode. See
  [Image reference: network egress](../reference/image.md#network-egress).
- **No built-in secret-store integration.** CA keys, Kubernetes credentials and DNS tokens are
  files gwops reads from mounts; a secrets agent can write them there.

## Recipe format

Each recipe uses the same sections:

- **Environment**: what the recipe assumes about your hosts, network and tenant.
- **What you get**: the resources, certificates and access model at the end.
- **Architecture**: one diagram of the deployment.
- **Twingate prerequisites**: objects to create on the tenant first, and the API key's scope.
- **Files**: the complete `seed.yaml`, `.env` and `compose.yaml` (or other runtime manifest) for
  the deployment, plus any mounted files.
- **Deploy**: the steps, in order.
- **Verify**: how to confirm each part works.
- **Day 2**: what changes later and which operations pages apply.
- **Variations**: small changes to the recipe and the guide that covers each.
- **Related**: the guides, operations pages and reference sections the recipe uses.

Unlike guides, recipe seeds are complete files, not fragments.
