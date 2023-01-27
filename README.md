# IP ACL at Compute@Edge Fastly

## Upload ACL list
/acl_upload is the endpoint. To update the IP ACL list, you need to upload the array format file to the endpoint. The IP should comply with Ipv4Net format. https://docs.rs/ipnet/2.5.0/ipnet/struct.Ipv4Net.html Sample file is `src/ip_list.json`

e.g.

```
curl -sv -X PUT https://ipacl.edgecompute.app/acl_upload -T src/ip_list.json
```

## IP ACL endpoint
/acl_check is the endpoint to check your client IP is in the ACL list.

e.g.

```
curl -sv -X GET https://ipacl.edgecompute.app/acl_check -4
```

### Caveats
Only IPv4 is supported now.
