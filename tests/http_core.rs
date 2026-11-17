use octetrail::http::{body_allowed, message, Error, Request, Response};

#[test]
fn request_fields_headers_and_chunked_body() {
    let raw = b"PUT /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX: 1\r\nx: 2\r\n\r\n3\r\nabc\r\n0\r\n\r\nnext";
    let r = Request::parse(raw).unwrap();
    assert_eq!(
        (r.method.as_str(), r.uri.as_str(), r.version.as_str()),
        ("PUT", "/u", "1.1")
    );
    assert_eq!(
        r.message.headers,
        [
            ("transfer-encoding".to_string(), vec!["chunked".to_string()]),
            ("x".to_string(), vec!["1".to_string(), "2".to_string()]),
        ]
    );
    assert_eq!(
        (&r.message.body[..], r.message.data),
        (&b"abc"[..], &b"next"[..])
    );
}

#[test]
fn errors_follow_dpkt() {
    assert!(matches!(
        Request::parse(b"PATCH / HTTP/1.1\r\n"),
        Err(Error::Unpack(_))
    ));
    assert!(matches!(
        message(b"Content-Length: 5\r\n\r\nabc", true),
        Err(Error::NeedData(_))
    ));
    assert!(matches!(
        message(b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n", true),
        Err(Error::Unpack(_))
    ));
    assert!(matches!(
        message(b"Content-Length: x\r\n\r\n", true),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn responses_without_a_body_keep_the_rest_as_data() {
    let r = Response::parse(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 2\r\n\r\nok").unwrap();
    assert_eq!(
        (r.status.as_str(), r.reason.as_str()),
        ("304", "Not Modified")
    );
    assert_eq!(
        (&r.message.body[..], r.message.data),
        (&b""[..], &b"ok"[..])
    );
    assert!(body_allowed("200") && body_allowed("1000") && !body_allowed("0204"));
}
