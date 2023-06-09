This repository contains demo code for my talk at fwd:cloudsec 2023.

To start, add this directory to your `PYTHONPATH` and install the dependencies
listed in `requirements.txt`.

To enable the awscli plugin, put this in your `.aws/config`:

    [plugins]
    external_signers = fwdcloudsec_signers.awscli_plugin

You'll need to have the signer running on port 8000 with suitable credentials to access S3:

    python3 -m fwdcloudsec_signers.example_homedirs

The contents of this repository are copyrighted by Josh Snyder, and offered
under the Apache 2.0 license. See the LICENSE file for details.
