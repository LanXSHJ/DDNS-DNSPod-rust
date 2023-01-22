# DDNS-DNSPod-rust

A simple rust program which change DNS resolution of one domain to current ip of the machine by DNSPod API.

## Usage
```
Usage: ddns-dnspod-rust [OPTIONS]

Options:
  -c, --config <CONFIG>  The path of configuration, you can find an example in config/configuration-example.yaml [default: config/configuration.yaml]
  -h, --help             Print help
  -V, --version          Print version
```

### Configuration

Please check [`config/configuration-example.yaml`](config/configuration-example.yaml) for example.

## Reference document
1. DNS resolution: https://cloud.tencent.com/document/product/1427/56180
2. Signature v3: https://cloud.tencent.com/document/api/1427/56189
