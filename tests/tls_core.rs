use octetrail::tls::{
    certificates, extensions, multi_factory, ssl2, tls_records, variable_array, Error, Hello,
};

fn var(lenbytes: usize, data: &[u8]) -> Vec<u8> {
    let mut out = data.len().to_be_bytes()[8 - lenbytes..].to_vec();
    out.extend_from_slice(data);
    out
}

#[test]
fn client_hello_fields() {
    let mut body = var(1, b"sess");
    body.extend(var(2, &[0xc0, 0x2b, 0x00, 0x2f]));
    body.extend(var(1, &[0]));
    body.extend(var(2, &[0x00, 0x0a, 0x00, 0x01, 0x07]));
    let h = Hello::client(&body);
    assert_eq!(h.session_id, Some((1, 5)));
    assert_eq!(h.ciphersuites, Some(vec![0xc02b, 0x002f]));
    assert_eq!(h.compression, Some((12, 13)));
    assert_eq!(h.extensions, Some(vec![(10, (19, 20))]));
    assert_eq!(h.error, None);
}

#[test]
fn client_hello_errors_keep_earlier_fields() {
    let mut body = var(1, b"");
    body.extend(var(2, &[0, 1, 2]));
    let h = Hello::client(&body);
    assert_eq!(
        (h.session_id, h.ciphersuites, h.error),
        (Some((1, 1)), None, Some(Error::Struct))
    );
    // Fewer than six bytes after the compression methods: no extensions.
    let mut body = var(1, b"");
    body.extend(var(2, &[0, 1]));
    body.extend(var(1, &[0]));
    body.extend([0, 0, 0, 0, 0]);
    let h = Hello::client(&body);
    assert_eq!((h.extensions, h.error), (None, None));
}

#[test]
fn server_hello_fields() {
    let mut body = var(1, &[9; 32]);
    body.extend([0x12, 0x34, 0x00]);
    let h = Hello::server(&body);
    assert_eq!(
        (h.ciphersuites, h.compression),
        (Some(vec![0x1234]), Some((35, 36)))
    );
    assert_eq!(Hello::server(&body[..34]).error, Some(Error::Struct));
}

#[test]
fn certificate_lists() {
    let mut list = var(3, b"one");
    list.extend(var(3, b"two"));
    let body = var(3, &list);
    assert_eq!(certificates(&body), Ok((vec![(6, 9), (12, 15)], None)));
    assert_eq!(certificates(&body[..10]).unwrap().1, Some(Error::Struct));
    assert_eq!(certificates(&[0, 0]), Err(Error::Struct));
}

#[test]
fn records_factory_and_ssl2() {
    let raw = b"\x17\x03\x01\x00\x02ab\x17\x03\x01\x00\x09cd";
    assert_eq!(multi_factory(raw), Ok((vec![(0, 7)], 7)));
    assert_eq!(tls_records(raw), (vec![(0, 7)], Some(Error::ShortRecord)));
    assert_eq!(ssl2(0x8002, b"ab").unwrap().rest, (2, 2));
    assert_eq!(variable_array(b"\x02", 0, 1), Ok(((1, 1), 3)));
    assert_eq!(extensions(b"\x00", 0).1, Some(Error::Struct));
}

#[test]
fn long_inputs_parse_in_one_pass() {
    // Many empty extensions and certificates parse in a single linear pass.
    let ext: Vec<u8> = std::iter::repeat([0u8, 1, 0, 0])
        .take(16_383)
        .flatten()
        .collect();
    let block = var(2, &ext);
    assert_eq!(extensions(&block, 0).0.len(), 16_383);
    let certs: Vec<u8> = std::iter::repeat([0u8, 0, 0])
        .take(20_000)
        .flatten()
        .collect();
    assert_eq!(certificates(&var(3, &certs)).unwrap().0.len(), 20_000);
}
