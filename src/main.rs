use fastly::error::anyhow;
use fastly::http::{header, Method, StatusCode};
use fastly::{object_store::ObjectStore, panic_with_status, Body, Error, Request, Response};
use ipnet::Ipv4Net;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};

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
            let (upload_count, ip_list) = check_body(&body)?;
            let ip_list_str: Vec<String> = ip_list.iter().map(|x| x.to_string()).collect::<Vec<_>>();
            let ip_str = format!("{:?}", ip_list_str);
            println!("{}", ip_str);
            let mut object_store = ObjectStore::open("ip-acl")
                .unwrap_or_else(|_| {
                    panic_with_status!(501, "objectstore API not available on this host");
                })
                .unwrap_or_else(|| {
                    panic_with_status!(501, "Object Store: ip-acl is not available");
                });
            object_store.insert("ipacl", ip_str)?;
            Ok(Response::from_status(StatusCode::OK)
               .with_body_text_plain(&format!("The number of IPNet is {} updated", upload_count)))
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
            if block_client_ip(client_ip_v4, ip_list) {
                return Ok(Response::from_status(StatusCode::FORBIDDEN)
                       .with_body_text_plain(&client_ip.to_string()));
            }
            /*
            for block_ip_value in &ip_list {
                let block_ip: Ipv4Net = block_ip_value.as_str().unwrap().parse::<Ipv4Net>()?;
                if block_ip.contains(&client_ip_v4) {
                    return Ok(Response::from_status(StatusCode::FORBIDDEN)
                        .with_body_text_plain(&client_ip.to_string()));
                }
            }
            */
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
    let ip_list = object_store.lookup_str("ipacl")?;
    let block_list_value: Value = serde_json::from_str(&ip_list.unwrap())?;
    let block_list: Vec<Value> = block_list_value.as_array().unwrap().to_vec();

    Ok(block_list)
}

fn check_body(body: &str) -> Result<(i64, Vec<Ipv4Net>), Error> {
    let body_value: Value = serde_json::from_str(body)?;
    let ip_list = body_value.as_array().ok_or_else(|| anyhow!("Upload format is incorrect. It should be Array."))?;
    let mut i: i64 = 0;
    let mut ip_aggregated_list: Vec<Ipv4Net> = Vec::new();
    for ipnet in ip_list {
        let net = ipnet.as_str().unwrap().parse::<Ipv4Net>();
        if net.is_err() {
            return Err(anyhow!("{:?} doesn't match Ipv4Net format.", ipnet));
        }
        ip_aggregated_list.push(net.unwrap());
        i+=1;
    }
    ip_aggregated_list = Ipv4Net::aggregate(&ip_aggregated_list);
    ip_aggregated_list.sort_by(|x, y| x.cmp(&y));
    Ok((i, ip_aggregated_list))
}

fn block_client_ip(client_ip: Ipv4Addr, ip_list: Vec<Value>) -> bool {
    let len = ip_list.len();
    let mut low = 0;
    let mut high = len - 1;

    while low <= high {
        let mid = (low + high) / 2;
        match &ip_list[mid] {
            x if ip_list[mid].as_str().unwrap().parse::<Ipv4Net>().unwrap().contains(&client_ip) => return true,
            _ => {
                    let mid_network: u32 = ip_list[mid].as_str().unwrap().parse::<Ipv4Net>().unwrap().network().into();
                    let client_ip_u32: u32 = client_ip.into();
                    if mid_network < client_ip_u32 {
                        low = mid + 1;
                        high = high;
                    } else {
                        low = low;
                        high = mid - 1;
                    }
                },
        }
    }

    false
}
