# Google Cloud: least privilege for keycensus

`keycensus-kms-viewer-role.yaml` is a custom role with the seven permissions the `gcp-kms` collector
uses. Bind it at the organization or a folder so `discover: true` sees every project under it.

The built-in alternative is `roles/browser` (for project discovery) plus `roles/cloudkms.viewer` on the
same scope. `roles/cloudkms.viewer` also includes a few permissions keycensus does not use, such as
listing import jobs and EKM connections.

On GKE, run keycensus with Workload Identity and give the Kubernetes service account
`roles/iam.workloadIdentityUser` on the Google service account that holds this role.
