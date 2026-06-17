# PacketDesk MSIX Store Build

Run `build_msix_store.bat` from the project root after editing these values inside the batch file:

```bat
set "STORE_IDENTITY_NAME=PUT-PARTNER-CENTER-PACKAGE-IDENTITY-NAME-HERE"
set "STORE_PUBLISHER=CN=PUT-PARTNER-CENTER-PUBLISHER-ID-HERE"
```

Use the exact package identity values shown in Microsoft Partner Center after reserving the app name.

The script builds:

```text
msix_out\PacketDesk_1.0.0.0_x64_StoreUpload.msix
```

Upload that unsigned `.msix` in the Store submission's **Packages** step. Microsoft signs Store MSIX packages after certification.

For local testing only, set:

```bat
set "CREATE_LOCAL_TEST_SIGNED_COPY=1"
```

Do not upload the local self-signed test package to Partner Center.

## Requirements

- Windows 10/11
- Python 3.11+
- Windows 10/11 SDK with `MakeAppx.exe`
- Existing project files, including `pingpath_gui.py` and `requirements.txt`

Optional:

- Put the app logo at `assets\packetdesk_logo.png`. If absent, the script generates placeholder MSIX visual assets.
