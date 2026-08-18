# EntraDpapiDecrypt

`EntraDpapiDecrypt` is a C# implementation of the on-disk DPAPI recovery chain for Entra ID-joined Windows devices. Given a password and sufficient local file access, it derives the CloudAP credential key, unwraps matching DPAPI master keys, and decrypts matching Windows Credential Manager blobs.

The tool operates entirely on disk: it does not read LSASS memory or impersonate users.

## What it covers

The current implementation:

- enumerates provisioned local user profiles.
- locates CloudAP `CacheData`, DPAPI master-key and Credential Manager files.
- derives a password-based CloudAP key from a supplied password.
- decrypts supported Entra ID CloudAP and DPAPI data layouts.
- reports successfully decrypted credential records to standard output.

Tested on Windows 11 Entra ID-joined lab builds

## Compile

Build with a .NET compiler.

## Usage

Run the compiled executable with the target account password. It must run with access to the required protected profile files.

```powershell
# Standard run
.\EntraDpapiDecrypt.exe '<password>'

# Include diagnostic details
.\EntraDpapiDecrypt.exe '<password>' -v

# Try multiple passwords (one per line in the file)
.\EntraDpapiDecrypt.exe -f passwords.txt
.\EntraDpapiDecrypt.exe -f passwords.txt -v

# Target one local profile only (faster — skips other users)
.\EntraDpapiDecrypt.exe '<password>' -u kerbme
.\EntraDpapiDecrypt.exe -f passwords.txt -u kerbme -v
```

Supported flags:

- `-v`, `--verbose` — print per-file parsing and decryption diagnostics.
- `-f`, `--password-file` — path to a text file with one password per line. each password is tried in order for every user profile.
- `-u`, `--username` — local profile folder name (e.g. `kerbme` from `C:\Users\kerbme`). only that user's master keys and credentials are processed. CacheData scanning is limited to that profile plus the SYSTEM CloudAP cache.

The password is accepted as a command-line argument, or via `-f` for multiple candidates. Verbose mode includes file paths and cryptographic diagnostic information.

## Performance

Runs can take noticeably longer in some cases. That is expected.

The slow step is **unlocking CloudAP `CacheData`**. Microsoft does not publish a fixed on-disk layout for this file, and it has changed between Windows builds. Rather than hard-code one structure, the tool performs a **decrypt-and-recognise sweep**:

- for every 4-byte-aligned offset in each `CacheData` file
- for many candidate ciphertext lengths (640 bytes down to 32 bytes)
- for two AES-CBC variants (embedded IV and zero IV)

Each attempt decrypts and checks whether the result contains a valid CredKey. This is intentional: it keeps the tool working across layout changes, but it is computationally expensive.

A run is usually **fast** when:

- the password is correct
- few `CacheData` files exist on the machine
- the matching blob is found early in the file

A run is usually **slow** when:

- the password is wrong: the tool must exhaust the full scan before moving on
- `-f` is used with many passwords: each candidate pays the full `CacheData` scan cost
- many Entra users have logged in on the same host: more `CacheData` files to scan
- several user profiles have master keys: each user/password pair scans all `CacheData` files

Use `-u <profile>` to target one local profile and skip other users. this also narrows the `CacheData` scan to that profile plus the SYSTEM CloudAP cache.

Master-key and credential decryption are comparatively quick once `CacheData` unlocks. K1 (the password-derived key) is cached per unique password so PBKDF2 is not repeated for every user profile.

Use `-v` to see which `CacheData` files are scanned and where a match is found.

## Known limitations

- By default the tool attempts a single supplied password. Use `-f` to try multiple candidates.
- To work, the user must have used password based login at least once.

## Acknowledgements

This tool and research builds on publicly documented DPAPI and CloudAP work, including:

- [Synacktiv CacheData_decrypt](https://github.com/synacktiv/CacheData_decrypt)
- [Fortra Impacket](https://github.com/fortra/impacket)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [dpapick3](https://github.com/fortra/dpapick)

## License

Licensed under the MIT License. See [LICENSE](LICENSE).
