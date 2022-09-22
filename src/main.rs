use fastly::error::anyhow;
use fastly::http::{header, Method, StatusCode};
use fastly::{object_store::ObjectStore, panic_with_status, Body, Error, Request, Response};
use ipnet::Ipv4Net;
use serde_json::Value;
use std::net::IpAddr;

#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // Filter request methods...
    match req.get_method() {
        // Allow GET, PUT and HEAD requests.
        &Method::GET | &Method::PUT | &Method::HEAD => (),

        // Deny anything else.
        _ => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, HEAD")
                .with_body_text_plain("This method is not allowed\n"))
        }
    };

    // Pattern match on the path...
    match (req.get_method(), req.get_path()) {
        (&Method::PUT, "/acl_upload") => {
            //TODO: Authentication is required
            let body = req.take_body_str();
            let i = check_body(&body)?;
            let mut object_store = ObjectStore::open("ip-acl")
                .unwrap_or_else(|_| {
                    panic_with_status!(501, "objectstore API not available on this host");
                })
                .unwrap_or_else(|| {
                    panic_with_status!(501, "Object Store: chat is not available");
                });
            object_store.insert("ipacl", Body::from(body))?;
            Ok(Response::from_status(StatusCode::OK)
               .with_body_text_plain(&format!("The number of IPNet is {} updated", i)))
        }
        (&Method::GET, "/acl_check") => {
            //TODO: Authentication is required
            let client_ip = req
                .get_client_ip_addr()
                .ok_or_else(|| anyhow!("could not get client ip"))?;
            let client_ip_v4 = match client_ip {
                IpAddr::V4(ip4) => ip4,
                IpAddr::V6(ip6) => {
                    return Ok(Response::from_status(StatusCode::OK)
                        .with_body_text_plain(&client_ip.to_string()))
                }
            };
            let ip_list = get_ip_list()?;
            for block_ip_value in &ip_list {
                let block_ip: Ipv4Net = block_ip_value.as_str().unwrap().parse::<Ipv4Net>()?;
                if block_ip.contains(&client_ip_v4) {
                    return Ok(Response::from_status(StatusCode::FORBIDDEN)
                        .with_body_text_plain(&client_ip.to_string()));
                }
            }
            Ok(Response::from_status(StatusCode::OK).with_body_text_plain(&client_ip.to_string()))
        }

        // Catch all other requests and return a 404.
        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)
            .with_body_text_plain("The page you requested could not be found\n")),
    }
}

fn get_ip_list() -> Result<Vec<Value>, Error> {
   let mut object_store = ObjectStore::open("ip-acl")
      .unwrap_or_else(|_| {
          panic_with_status!(501, "objectstore API not available on this host");
      })
      .unwrap_or_else(|| {
          panic_with_status!(501, "Object Store: chat is not available");
      });
    // This can replace to request to ObjectStore;
    //let block_list_value: Value = serde_json::from_str(include_str!("ip_list.json"))?;
    let ip_list = object_store.lookup_str("ipacl")?;
    let block_list_value: Value = serde_json::from_str(&ip_list.unwrap())?;
    let block_list = block_list_value.as_array().unwrap().to_vec();
    Ok(block_list)
}

fn check_body(body: &str) -> Result<i64, Error> {
    let body_value: Value = serde_json::from_str(body)?;
    let ip_list = body_value.as_array().ok_or_else(|| anyhow!("Upload format is incorrect. It should be Array."))?;
    let mut i: i64 = 0;
    for ipnet in ip_list {
        let net = ipnet.as_str().unwrap().parse::<Ipv4Net>();
        if net.is_err() {
            return Err(anyhow!("{:?} doesn't match Ipv4Net format.", ipnet));
        }
        i+=1;
    }
    Ok(i)
}
