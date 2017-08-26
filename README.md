# acme-wf

Use `acme-wf` to securely transfer [acme.sh][] certificates to your [WebFaction][] account.

WebFaction is a web host who support customer managed SSL/TLS certificates but WebFaction do not directly support LetsEncrypt. This tool bridges the gap between the excellent `acme.sh` project and WebFaction's lack of LetsEncrypt support.

## Overview

`acme-wf` transfers SSL certificates from your WebFaction server into the WebFaction control panel. This is done without needing to store your credentials on the server.

From the trusted private computer, `acme-wf` connects via `ssh` to your WebFaction server which has `acme.sh` installed. The certificates required for your secure web site are collected over this secure connection.

With the certificates, `acme-wf` then connects via the `XML-RPC` interface to WebFaction's control panel. Once connected to WebFaction, `acme-wf` creates or updates the appropriate certificate entry.

## Why use `acme-wf`?

`acme-wf` exists because other solutions for using LetsEncrypt certificates on WebFaction required too many error prone steps, and automated approaches required embedding confidential credentials on the shared server.

With `acme-wf` a secure certificate can be updated with one command and without storing your WebFaction control panel password on your server.

`acme-wf` is written in [Go](https://golang.org). This means running `acme-wf` requires only the compiled executable and no supporting files. Compiling `acme-wf` on multiple platforms is also easy thanks to being written in Go.

Ideally, WebFaction will add automatic LetsEncrypt support. Until then, we have `acme.sh` and `acme-wf`.

# Build

Assuming `go` is installed on your computer, get and build `acme-wf` using the commands:

```
git clone https://github.com/grahammiln/acme-wf.git
cd acme-wf
go get
go build
```

[Cross compile from macOS](https://stackoverflow.com/questions/12168873) to other platforms using:

```
GOOS=linux GOARCH=386 CGO_ENABLED=0 go build -o acme-wf.linux main.go
GOOS=windows GOARCH=386 go build -o acme-wf.exe main.go
```

# Getting Started

1. Install [acme.sh][] on your [WebFaction][] server.
2. On your trusted computer, set up [passwordless ssh access](https://www.dssw.co.uk/blog/2013-09-20-avoiding-password-prompts-with-ssh-and-rsync/) to your WebFaction server.
3. On your trusted computer, run the appropriate `acme-wf …` command; see below for examples.

```
./acme-wf -u wfuser [-p wfpassword] [-s wfserver] [domains ...]
```

# Example Output

## Listing Certificates

Below is an example of output returned from the command:

`./acme-wf -u wfuser`

The command does not provide any domains, so the output lists known certificates returned by WebFaction's API:

```
WebFaction control panel password: 
2017/08/26 11:21:29 [INFO] Logging into WebFaction as: 'wfuser'
2017/08/26 11:21:34 [INFO] Established WebFaction session as user 'wfuser' for server 'Web123'
2017/08/26 11:21:34 [INFO] Requesting WebFaction certificate list
2017/08/26 11:21:36 [INFO] Found WebFaction certificate: 'example_com' expires 2017-09-18, for domains 'example.com,www.example.com'
2017/08/26 11:21:36 [INFO] Found WebFaction certificate: 'anotherdomain_com' expires 2019-11-01, for domains 'anotherdomain.com'
```

## Updating a Certificate

Below is an example of output returned from the command:

`./acme-wf -u wfuser example.com`

The output shows `acme-wf` connecting the WebFaction to determine what certificates already exist. A `ssh` connection then fetches the three certificate files from the server. Finally, the certificate entry is updated using the collected certificate files.

```
WebFaction control panel password: 
2017/08/26 11:32:38 [INFO] Logging into WebFaction as: 'wfuser'
2017/08/26 11:32:40 [INFO] Established WebFaction session as user 'wfuser' for server 'Web123'
2017/08/26 11:32:40 [INFO] Requesting WebFaction certificate list
2017/08/26 11:32:41 [INFO] ssh to 'wfuser@web123.webfaction.com' to read certificates
2017/08/26 11:32:41 [INFO] Working on domain: 'example.com'
2017/08/26 11:32:41 [INFO] Reading '/home/wfuser/.acme.sh/example.com/example.com.cer' via ssh
2017/08/26 11:32:42 [INFO] Reading '/home/wfuser/.acme.sh/example.com/example.com.key' via ssh
2017/08/26 11:32:42 [INFO] Reading '/home/wfuser/.acme.sh/example.com/ca.cer' via ssh
2017/08/26 11:32:42 [INFO] Requesting WebFaction `update_certificate` for example_com (example.com)
2017/08/26 11:32:44 [INFO] Successfully called WebFaction `update_certificate` for example_com (example.com)
```

## Examples

### List Certificates with Expiry Dates

Run `acme-wf` without domains to return a list of existing WebFaction certificates.

### Single Server

Assuming you have one WebFaction server and the domain `example.com`, the command is:

    acme-wf -u <webfaction-username> 'example.com'

For `-u` provide your WebFaction user name. The final argument is the domain name, as listed with `acme.sh`.

With this command, `acme-wf` will connect to WebFaction and be told the name of your server. `acme-wf` will then connect to the server and fetch the `acme.sh` certificates associated with the domain `example.com`.

Using Terminal.app on macOS, the final command might look like:

    ./acme-wf -u myuser 'example.com'

### Multiple Servers

If you have multiple WebFaction servers, then the command needs to include which server you want to fetch the certificates from:

    acme-wf -u <webfaction-username> -s <webfaction-servername> 'example.com'

Using Terminal.app on macOS, the final command might look like:

    acme-wf -u myuser -s Web123 'example.com'

## Assumptions

`acme-wf` assumes a fair bit about its environment. This keeps the code simple but means the implementation is fragile. In time, additional checks and flexibility can be added. For now the focus is on a minimal working tool.

- `acme-wf` assumes you have an account with WebFaction and at least one server.
- `acme-wf` assumes you have passwordless secure shell (ssh) access to your WebFaction server.
- `acme-wf` assumes you have `acme.sh` set up on your WebFaction server.
- `acme-wf` assumes `acme.sh` stores three files for certificates at known paths:
   1. `~/.acme.sh/<domain>/<domain>.cer`
   2. `~/.acme.sh/<domain>/<domain>.key`
   3. `~/.acme.sh/<domain>/ca.cer`

## Scripting

To avoid needing to enter your WebFaction control panel password, use the `-p` option:

    -p <webfaction-control-panel-password>

# Improvements

Today `acme-wf` works well enough to be useful. There are numerous improvements that could be implemented. In no particular order these include:

- [ ] Only update certificates that have changed; compare WebFaction PEM versus `acme.sh` files before calling `update_certificate`.
- [ ] Check replacement certificate covers the same domains as existing WebFaction entry.
- [ ] Check replacement certificates have not expired.
- [ ] Check replacement certificates are valid.
- [ ] Allow replacement certificates to come from a user specified server.
- [ ] Allow replacement certificates to come from a user specified path.
- [ ] Add option to download WebFaction certificates for back up purposes.
- [ ] Add option to list existing certificates in expiry date order; possible warning of near expiry entries.

## Contributions and Improvements Welcome

Help improve `acme-wf`! Pull requests are welcomed.

# Licence and Legal

`acme-wf` was created by Graham Miln / https://miln.eu / @grahammiln and is licensed under the Apache License, Version 2.0.

`acme-wf` has not affiliation or associations with `acme.sh` or WebFaction.

[acme.sh]: https://github.com/Neilpang/acme.sh
[WebFaction]: https://www.webfaction.com/?aid=50311
