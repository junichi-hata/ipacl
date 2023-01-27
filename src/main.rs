use fastly::error::anyhow;
use fastly::http::{header, Method, StatusCode};
use fastly::{object_store::ObjectStore, panic_with_status, Error, Request, Response};
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
            let (upload_count, ip_list_count, ip_lists) = check_body(&body)?;
            let mut object_store = ObjectStore::open("ip-acl")
                .unwrap_or_else(|x| {
                    panic_with_status!(501, "objectstore API not available on this host: {}", x);
                })
                .unwrap_or_else(|| {
                    panic_with_status!(501, "objectstore ip-acl is not found");
                });
            let binary_ipnet_vec: Vec<u8> = bincode::serialize(&ip_lists)?;
            let object = object_store.lookup_bytes("ipacl");
            if object.is_err() {
                return Err(anyhow!("Failed to read object store: ipacl"));
            }
            let binary_ipnet_pre = object.unwrap();
            if binary_ipnet_vec == binary_ipnet_pre.unwrap() {
                return Ok(
                    Response::from_status(StatusCode::OK).with_body_text_plain(&format!(
                        "No updated because of no change! Uploaded: {} Aggregated: {}",
                        upload_count, ip_list_count
                    )),
                );
            }
            let obs_insert = object_store.insert("ipacl", binary_ipnet_vec);
            if obs_insert.is_err() {
                return Err(anyhow!("Failed to upload: ipacl"));
            }
            Ok(
                Response::from_status(StatusCode::OK).with_body_text_plain(&format!(
                    "The number of IPNet is {} updated. Aggergated to {}",
                    upload_count, ip_list_count
                )),
            )
        }
        (&Method::GET, "/acl_check") => {
            //TODO: Authentication is required
            let client_ip = req
                .get_client_ip_addr()
                .ok_or_else(|| anyhow!("could not get client ip"))?;
            let client_ip_v4 = match client_ip {
                IpAddr::V4(ip4) => ip4,
                IpAddr::V6(_ip6) => {
                    return Ok(Response::from_status(StatusCode::OK)
                        .with_body_text_plain(&client_ip.to_string()))
                }
            };
            let ip_list = get_ip_list(&client_ip_v4);
            if ip_list.is_err() {
                return Ok(Response::from_status(StatusCode::OK)
                    .with_body_text_plain(&client_ip.to_string()));
            }
            if block_client_ip(client_ip_v4, ip_list.unwrap()) {
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

fn get_ip_list(client_ip: &Ipv4Addr) -> Result<Vec<Ipv4Net>, Error> {
    let object_store = ObjectStore::open("ip-acl")
        .unwrap_or_else(|x| {
            panic_with_status!(501, "objectstore API not available on this host: {}", x);
        })
        .unwrap_or_else(|| {
            panic_with_status!(501, "Object Store: chat is not available");
        });
    let first_octet = client_ip.octets()[0];
    let object = object_store.lookup_bytes("ipacl");
    if object.is_err() {
        return Err(anyhow!("No ACL objects"));
    }
    let ip_list = object.unwrap();
    let block_lists: Vec<Vec<Ipv4Net>> = if ip_list.is_some() {
        bincode::deserialize(&ip_list.unwrap()).unwrap()
    } else {
        return Err(anyhow!("No ACL objects"));
    };
    let mut i = 0;
    for block_list in block_lists {
        if i != first_octet {
            i += 1;
            continue;
        }
        return Ok(block_list);
    }
    return Err(anyhow!("No ACL objects"));
}

fn check_body(body: &str) -> Result<(usize, usize, Vec<Vec<Ipv4Net>>), Error> {
    let body_result = serde_json::from_str(body);
    if body_result.is_err() {
        return Err(anyhow!("Upload format should be JSON format."));
    }
    let body_value: Value = body_result?;
    let ip_list_array = body_value
        .as_array()
        .ok_or_else(|| anyhow!("Upload format is incorrect. It should be Array."))?;
    let mut i = 0;
    let mut j = 0;
    let mut ip_lists: Vec<Vec<Ipv4Net>> = Vec::new();
    unsafe {
        ip_lists.set_len(255);
    }
    for ipnet in ip_list_array {
        let net = ipnet.as_str().unwrap().parse::<Ipv4Net>();
        if net.is_err() {
            return Err(anyhow!("{:?} doesn't match Ipv4Net format.", ipnet));
        }
        let ipv4net = net.unwrap();
        let first_octet: usize = ipv4net.addr().octets()[0].into();
        ip_lists[first_octet].push(ipv4net);
        i += 1;
    }
    for ip_list_num in 0..ip_lists.len() {
        if ip_lists[ip_list_num].len() != 0 {
            let mut ip_aggregated_list = Ipv4Net::aggregate(&ip_lists[ip_list_num]);
            ip_aggregated_list.sort_by(|x, y| x.cmp(&y));
            j += ip_aggregated_list.len();
            ip_lists[ip_list_num] = ip_aggregated_list;
        }
    }
    Ok((i, j, ip_lists))
}

fn block_client_ip(client_ip: Ipv4Addr, ip_list: Vec<Ipv4Net>) -> bool {
    let len = ip_list.len();
    if len == 0 {
        return false;
    }
    let mut low = 0;
    let mut high = len - 1;

    while low <= high {
        let mid = (low + high) / 2;
        match &ip_list[mid] {
            _x if ip_list[mid].contains(&client_ip) => return true,
            _ => {
                let mid_network: u32 = ip_list[mid].network().into();
                let client_ip_u32: u32 = client_ip.into();
                if mid_network < client_ip_u32 {
                    low = mid + 1;
                    high = high;
                } else {
                    low = low;
                    high = mid - 1;
                }
            }
        }
    }

    false
}
