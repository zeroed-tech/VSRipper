# VSRipper

VSRipper is a tool I wrote to make decrypting view states trivial.
Released along side [Decrypting View State Messages](https://zeroed.tech/blog/decrypting-viewstate-messages/)

## Usage

### Bruteforce

Given one or more autogen keys, attempt to decrypt the target view state using every combination of validation algorithm and decryption algorithm for legacy and modern configurations.

This can be handy for situation where you have an encrypted view state and an autogen key (typically dumped from the Windows registry) but cant run code on the server to dump the actual keys.


```bash
VSRipper.exe bruteforce --autogenkeys "KEY1,KEY2" --webapp "/owa" --appid "/LM/W3SVC/1/ROOT" --page "/login.aspx" --viewstate "./payload.txt"

```

| Argument | Requirement | Default | Description |
| --- | --- | --- | --- |
| `--autogenkeys` | **Required** | - | The path to a file containing a comma separated list of autogen keys. |
| `--webapp` | **Required** | - | The path to the targeted web application. |
| `--appid` | **Required** | - | The ID of the targeted application. |
| `--page` | **Required** | - | The specific page the view state was generated for. |
| `--viewstate` | **Required** | - | Path to the file containing the view state string. |
| `--generatelegacy` | Optional | `true` | Should legacy machine keys be generated? |
| `--generatemodern` | Optional | `true` | Should modern machine keys be generated? |
| `--userkey` | Optional | - | The view state user key for the target application. |
| `--urlencoded` | Optional | `false` | Set to true if the input view state is url encoded. |
| `--outputfile` | Optional | - | File to write the decrypted view state to. |
| `--verbose` | Optional | `false` | Print all combinations tested. |

---

### Decrypt

Decrypt a view state given the correct keys and algorithms

```bash
VSRipper.exe decrypt --decryptionkey "AABBCCDD" --validationkey "EEFFGGHH" --webapp "/owa" --page "/login.aspx" --viewstate "./payload.txt" --decryptor AES --validator HMACSHA256

```

| Argument | Requirement | Default | Description |
| --- | --- | --- | --- |
| `--decryptionkey` | **Required** | - | The decryption key from the target server. |
| `--validationkey` | **Required** | - | The validation key from the target server. |
| `--webapp` | **Required** | - | The path to the targeted web application. |
| `--page` | **Required** | - | The page the target view state was generated for. |
| `--viewstate` | **Required** | - | Path to the file containing the view state message. |
| `--decryptor` | **Required** | `Auto` | The decryption algorithm: `AES`, `DES`, `TripleDES`, `Auto`. |
| `--validator` | **Required** | `HMACSHA256` | The validation algorithm: `HMACSHA1`, `HMACSHA256`, `HMACSHA384`, `HMACSHA512`, `MD5`, `SHA1`. |
| `--islegacy` | Optional | `false` | Use legacy cryptography logic. |
| `--skipvalidation` | Optional | `false` | Set to skip payload validation. |
| `--userkey` | Optional | - | The view state user key for the target application. |
| `--urlencoded` | Optional | `false` | Set to true if your view state message is url encoded. |

---

## Requirements

VSRipper needs to be run on a host with .NET Framework 4.x (built using 4.8).