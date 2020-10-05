# Concourse dex

A fork of dexidp/dex with changes necessary for Concourse.

Use the pipeline [update-dex](https://ci.concourse-ci.org/teams/main/pipelines/update-dex) on ci.concourse-ci.org to update concourse/dex fork with upstream dexidp/dex.

The pipeline will rebase upstream/master into each pr branch and then merge all rebased pr branches into a newly created master that on top of upstream/master. Then it will generate release with version `v0.x.0` that allows Dependabot to pick the new version and create PR in `concourse/concourse`. And to work with go modules, the release version has to be `< v2.0.0`.
