# JWT token Parser for grpc request


## From grpc(tonic) metadata

```rust 
let parser = JWTUserTokenParser::new(PUBLIC_KEY.to_string());        
let user_uuid = parser.get_user_uuid_from_grpc(&metadata);        
```
