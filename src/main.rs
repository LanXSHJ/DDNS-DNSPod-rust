use http::HeaderValue;
use http::header;
use http::HeaderMap;
use serde::{Serialize, Deserialize};
use reqwest;
use anyhow::Result;
use clap::Parser;
use serde_json::json;
use tokio::fs;
use chrono::Utc;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use hex;

/// A simple rust program which change DNS resolution of one domain to current ip of the machine by DNSPod API.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
   /// The path of configuration, you can find an example in config/configuration-example.yaml
   #[arg(short, long, default_value = "config/configuration.yaml")]
   config: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct DNSPodConfig {
    #[serde(rename = "SecretId")]
    pub secret_id: String,
    #[serde(rename = "SecretKey")]
    pub secret_key: String
}
#[derive(Serialize, Deserialize, Debug)]
struct DomainConfig {
    #[serde(rename = "Domain")]
    pub domain: String,
    #[serde(rename = "SubDomain")]
    pub sub_domain: String,
    #[serde(rename = "RecordType")]
    pub record_type: String,
    #[serde(rename = "RecordLine")]
    pub record_line: String
}
#[derive(Serialize, Deserialize, Debug)]
struct GlobalConfig {
    #[serde(rename = "DNSPod")]
    pub dnspod_cfg: DNSPodConfig,
    #[serde(rename = "Domain")]
    pub domain_cfg: DomainConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = load_config(&args.config).await?;
    // println!("get cfg : {:?}", cfg);
    let ip = get_current_ip().await?;
    println!("get current ip = {:?}", ip);
    do_ddns(cfg, ip).await?;
    Ok(())
}

async fn load_config(path: &str) -> Result<GlobalConfig> {
    let yaml_file = fs::read_to_string(path).await?;
    let cfg = serde_yaml::from_str::<GlobalConfig>(&yaml_file)?;
    Ok(cfg)
}

async fn get_current_ip() -> Result<String> {
    let resp = reqwest::get("https://ifconfig.me")
        .await?;
    let ip = resp.text().await?;
    Ok(ip)
}

// https://cloud.tencent.com/document/product/1427/56180
async fn do_ddns(cfg: GlobalConfig, ip: String) -> Result<()> {
    let post_json = json!({
            "Domain": &cfg.domain_cfg.domain,
            "SubDomain": &cfg.domain_cfg.sub_domain,
            "RecordType": &cfg.domain_cfg.record_type,
            "RecordLine": &cfg.domain_cfg.record_line,
            "Value": &ip
        }
    );

    let post_json_str = serde_json::to_string(&post_json)?;
    println!("json to post: {}\n", post_json_str);
    let post_json_sha256 = sha256::digest(post_json_str);

    let mut hdr = HeaderMap::new();
    hdr.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    hdr.insert(header::HOST, HeaderValue::from_static("dnspod.tencentcloudapi.com"));
    let now = Utc::now();
    let timestamp = now.timestamp();
    hdr.insert("X-TC-Timestamp", HeaderValue::from_str(&timestamp.to_string())?);
    hdr.insert("X-TC-Action", HeaderValue::from_static("CreateRecord"));
    hdr.insert("X-TC-Version", HeaderValue::from_static("2021-03-23"));

    let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}",
        "POST", "/", "",
        format!("{}:{}\n{}:{}\n", 
            header::CONTENT_TYPE.to_string().to_lowercase(),
            "application/json",
            header::HOST.to_string().to_lowercase(),
            "dnspod.tencentcloudapi.com"
        ),
        format!("{};{}",
            header::CONTENT_TYPE.to_string().to_lowercase(),
            header::HOST.to_string().to_lowercase()
        ),
        post_json_sha256.to_lowercase()
    );
    println!("canonical_request: {canonical_request}\n");

    let canonical_request_sha256 = sha256::digest(canonical_request).to_lowercase();
    let str_to_sign = format!("{}\n{}\n{}\n{}",
        "TC3-HMAC-SHA256",
        timestamp,
        format!("{}/dnspod/tc3_request", now.date_naive()),
        canonical_request_sha256
    );
    println!("str_to_sign: {str_to_sign}\n");

    let sec_date = hmacsha256(format!("TC3{}", cfg.dnspod_cfg.secret_key).as_bytes(), now.date_naive().to_string().as_bytes())?;
    let sec_service = hmacsha256(sec_date.as_slice(), b"dnspod")?;
    let sec_signing = hmacsha256(sec_service.as_slice(), b"tc3_request")?;

    let signature = hmacsha256(sec_signing.as_slice(), str_to_sign.as_bytes())?;
    let sign_hex = hex::encode(signature);
    
    let authorization = format!("{} Credential={}/{}, SignedHeaders={}, Signature={}",
        "TC3-HMAC-SHA256",
        &cfg.dnspod_cfg.secret_id,
        format!("{}/dnspod/tc3_request", now.date_naive()),
        format!("{};{}",
            header::CONTENT_TYPE.to_string().to_lowercase(),
            header::HOST.to_string().to_lowercase()
        ),
        sign_hex
    );
    println!("authorization: {authorization}\n");

    hdr.insert(header::AUTHORIZATION, HeaderValue::from_str(&authorization)?);


    let client = reqwest::Client::new();
    let rep = client.post("https://dnspod.tencentcloudapi.com")
        .headers(hdr)
        .json(&post_json)
        .send()
        .await?;
    
    println!("response: {}", rep.text().await?);
    
    Ok(())
}

fn hmacsha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(msg);
    let result = mac.finalize();
    
    Ok(result.into_bytes().to_vec())
}