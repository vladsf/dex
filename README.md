# Concourse dex

A fork of coreos/dex with changes necessary for Concourse.

Work is done from the `maintenance` branch.

If you have push access:

    git checkout maintenance
    ./update-merged-branch

If you don't have push access:

You can still run the above command and let it fail at the very end when it tries to push.
Your local HEAD will be the newly merged (but un-pushed) master.
