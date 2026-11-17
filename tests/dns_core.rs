use octetrail::dns::{encode, unpack_name, Entry, Error, Message, Question, Rdata};

fn question() -> Vec<u8> {
    let mut out = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(b"\x04note\x07example\0\0\x01\0\x01");
    out
}

fn answer(kind: u16, rdata: &[u8]) -> Vec<u8> {
    let mut wire = question();
    wire[7] = 1;
    wire.extend_from_slice(&[0xc0, 12]);
    wire.extend_from_slice(&kind.to_be_bytes());
    wire.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    wire.extend_from_slice(rdata);
    wire
}

fn entries(message: &Message<'_>) -> [Vec<Entry<'static>>; 3] {
    // Parsed records pack their raw RDATA, as dpkt packs a nonempty `rdata`.
    std::array::from_fn(|i| {
        message.sections[i]
            .iter()
            .map(|r| Entry {
                name: r.name.clone(),
                kind: r.kind,
                class: r.class,
                ttl: r.ttl,
                rdata: Rdata::Raw(r.raw.to_vec().leak()),
            })
            .collect()
    })
}

#[test]
fn short_headers_need_data() {
    for n in 0..12 {
        assert_eq!(Message::parse(&vec![0; n]).unwrap_err(), Error::NeedData)
    }
    assert!(Message::parse(&[0; 12]).is_ok());
}

#[test]
fn question_fields_and_bytes() {
    let wire = question();
    let parsed = Message::parse(&wire).unwrap();
    assert_eq!((parsed.id, parsed.flags), (0x1234, 256));
    assert_eq!(
        parsed.questions,
        [Question {
            name: "note.example".into(),
            kind: 1,
            class: 1
        }]
    );
    assert_eq!(
        encode(parsed.id, parsed.flags, &parsed.questions, [&[], &[], &[]]).unwrap(),
        wire
    );
}

#[test]
fn truncation_follows_dpkt_error_classes() {
    let wire = question();
    // Inside the name a missing byte is NeedData; inside type and class it is a
    // short fixed field, which dpkt reports as UnpackError.
    for n in 12..26 {
        assert_eq!(
            Message::parse(&wire[..n]).unwrap_err(),
            Error::NeedData,
            "{n}"
        );
    }
    for n in 26..wire.len() {
        assert_eq!(
            Message::parse(&wire[..n]).unwrap_err(),
            Error::ShortField,
            "{n}"
        );
    }
    let rr = answer(1, &[192, 0, 2, 9]);
    assert_eq!(Message::parse(&rr[..35]).unwrap_err(), Error::ShortField);
}

#[test]
fn rdata_is_sliced_from_the_bytes_present() {
    let wire = answer(1, &[192, 0, 2, 9]);
    let parsed = Message::parse(&wire[..wire.len() - 2]).unwrap();
    let rr = &parsed.sections[0][0];
    assert_eq!((rr.rlen, rr.raw), (4, &[192, 0][..]));
}

#[test]
fn pointers_must_point_before_the_current_name() {
    let mut wire = question();
    wire[5] = 3;
    wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0xc0, 30, 0, 1, 0, 1]);
    let parsed = Message::parse(&wire).unwrap();
    assert!(parsed.questions.iter().all(|q| q.name == "note.example"));
    assert_eq!(unpack_name(&[0xc0, 0], 0).unwrap_err(), Error::Pointer);
    assert_eq!(unpack_name(&[0, 0xc0, 1], 1).unwrap_err(), Error::Pointer);
    assert_eq!(unpack_name(&[0, 0xc0], 1).unwrap_err(), Error::ShortField);
    assert_eq!(unpack_name(&[0x40], 0).unwrap_err(), Error::LabelType(0x40));
}

#[test]
fn names_keep_dots_inside_labels_and_count_255_label_bytes() {
    assert_eq!(unpack_name(b"\x03a.b\0", 0).unwrap(), ("a.b".into(), 5));
    let mut long = Vec::new();
    for n in [63, 63, 63, 62] {
        long.push(n);
        long.extend_from_slice(&vec![b'a'; usize::from(n)]);
    }
    long.push(0);
    assert_eq!(unpack_name(&long, 0).unwrap().0.len(), 3 * 63 + 62 + 3);
    long.insert(0, 0);
    long[1] = 64;
    assert_eq!(unpack_name(&long, 1).unwrap_err(), Error::LabelType(64));
    let mut over = vec![63];
    over.extend_from_slice(&[b'a'; 63]);
    let over = over.repeat(5);
    assert_eq!(unpack_name(&over, 0).unwrap_err(), Error::NameLength);
    assert_eq!(
        unpack_name(b"\x02\xff\xfe\0", 0).unwrap_err(),
        Error::Encoding
    );
}

#[test]
fn typed_rdata_decodes_like_dpkt() {
    let mx_wire = answer(15, b"\x00\x0a\x04mail\xc0\x11");
    let mx = Message::parse(&mx_wire).unwrap();
    let rr = &mx.sections[0][0];
    assert_eq!(
        (rr.numbers.as_slice(), rr.names.as_slice()),
        (&[10][..], &["mail.example".to_string()][..])
    );
    let txt_wire = answer(16, b"\x05first\x09sec");
    let txt = Message::parse(&txt_wire).unwrap();
    assert_eq!(txt.sections[0][0].text, ["first", "sec"]);
    assert_eq!(
        Message::parse(&answer(15, b"\x00")).unwrap_err(),
        Error::ShortField
    );
    assert_eq!(
        Message::parse(&answer(33, b"\x00\x01")).unwrap_err(),
        Error::ShortField
    );
    assert_eq!(
        Message::parse(&answer(65280, b"note")).unwrap_err(),
        Error::UnsupportedType(65280)
    );
    for kind in [1, 10, 28, 41] {
        assert_eq!(
            Message::parse(&answer(kind, b"xyz")).unwrap().sections[0][0].raw,
            b"xyz"
        );
    }
}

#[test]
fn trailing_bytes_are_dropped_and_raw_rdata_repacks() {
    let mut wire = answer(5, b"\x05alias\xc0\x11");
    let original = wire.clone();
    wire.extend_from_slice(b"tail");
    let parsed = Message::parse(&wire).unwrap();
    assert_eq!(parsed.sections[0][0].names, ["alias.example"]);
    let sections = entries(&parsed);
    let packed = encode(
        parsed.id,
        parsed.flags,
        &parsed.questions,
        [&sections[0], &sections[1], &sections[2]],
    )
    .unwrap();
    assert_eq!(packed, original);
}

#[test]
fn structured_rdata_rebuilds_compression() {
    let questions = [Question {
        name: "note.example".into(),
        kind: 5,
        class: 1,
    }];
    let rr = Entry {
        name: "note.example".into(),
        kind: 5,
        class: 1,
        ttl: 60,
        rdata: Rdata::Name("alias.example".into()),
    };
    let packed = encode(0x1234, 0x0100, &questions, [&[rr], &[], &[]]).unwrap();
    let mut want = answer(5, b"\x05alias\xc0\x11");
    want[2..4].copy_from_slice(&[1, 0]);
    want[27] = 5;
    assert_eq!(packed, want);
}

#[test]
fn names_split_on_dots_without_validation() {
    let q = |name: &str| Question {
        name: name.into(),
        kind: 1,
        class: 1,
    };
    let packed = encode(0, 0, &[q("a..b"), q(".")], [&[], &[], &[]]).unwrap();
    assert_eq!(
        &packed[12..],
        b"\x01a\x00\x01b\x00\x00\x01\x00\x01\x00\x00\x00\x00\x01\x00\x01"
    );
    assert_eq!(
        encode(0, 0, &[q(&"x".repeat(256))], [&[], &[], &[]]).unwrap_err(),
        Error::Pack("DNS label exceeds 255 bytes")
    );
}

#[test]
fn many_compressed_names_parse() {
    let questions = vec![
        Question {
            name: "one.two.three.four.five.six.seven.example".into(),
            kind: 1,
            class: 1
        };
        2000
    ];
    let wire = encode(7, 0x8180, &questions, [&[], &[], &[]]).unwrap();
    assert_eq!(Message::parse(&wire).unwrap().questions, questions);
}
