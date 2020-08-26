# `tunneldns`

This module contains the DoH `proxy-dns` implementation which is used
as the system DNS stub resolver running on port 53.

### Changes for ODoH

The code in this branch introduces support for Oblivious DoH and 
implements `--protocol` default to DOH with the alternate possibility of ODOH.

Invoking the `proxy-dns` with `--protocol ODOH` results in the proxy DNS bootstrapping
itself by querying the `--discovery` endpoint from which the list of oblivious proxies 
and targets are obtained and chosen to be used.

The `Upstream` interface is modified to include the `protocol` and every `Exchange`
request has an additional `protocol` message attached to it. The `proxy-dns` stub
when using ODOH, creates a one time key and encapsulates it in the encrypted query
to the oblivious target through the proxy. A new `proxyServerInstance` maintains the
state of the public keys and their corresponding mapping to the targets after `bootstrap`.

The ODOH implementation of the `proxy-dns` with default parameters can be run as follows:

```
sudo cloudflared proxy-dns --protocol ODOH
```