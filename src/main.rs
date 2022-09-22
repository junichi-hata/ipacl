use fastly::error::anyhow;
use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};
use serde_json::Value;

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    // Filter request methods...
    match req.get_method() {
        // Allow GET and HEAD requests.
        &Method::GET | &Method::HEAD => (),

        // Deny anything else.
        _ => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, HEAD")
                .with_body_text_plain("This method is not allowed\n"))
        }
    };

    // Pattern match on the path...
    match req.get_path() {
        "/acl_check" => {
            let client_ip = req
                .get_client_ip_addr()
                .ok_or_else(|| anyhow!("could not get client ip"))?;
            let client_ip_v4 = match client_ip {
                IpAddr::V4(ip4) => ip4,
                IpAddr::V6(ip6) => return Ok(Response::from_status(StatusCode::OK)
                                          .with_body_text_plain(&client_ip.to_string())),
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
    // This can replace to request to ObjectStore;
    let block_list_value: Value = serde_json::from_str(include_str!("ip_list.json"))?;
    let block_list = block_list_value.as_array().unwrap().to_vec();
    Ok(block_list)
}
