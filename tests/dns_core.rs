use octetrail::dns::{encode, Error, Message, Question, Record, MAX_MESSAGE, MAX_RECORDS};

fn question() -> Vec<u8> {
    let mut out = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    out.extend_from_slice(b"\x04note\x07example\0\0\x01\0\x01");
    out
}

#[test]
fn all_short_fixed_headers_are_need_data() {
    for n in 0..12 {
        assert!(matches!(Message::parse(&vec![0; n]), Err(Error::Truncated)))
    }
}

#[test]
fn literal_question_fields_and_serialized_bytes() {
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
        encode(
            parsed.id,
            parsed.flags,
            &parsed.questions,
            [&[], &[], &[]],
            parsed.trailing
        )
        .unwrap(),
        wire
    );
}

#[test]
fn ordinary_backward_pointer_chain_resolves_questions() {
    let mut wire = question();
    wire[5] = 3;
    wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0xc0, 30, 0, 1, 0, 1]);
    let parsed = Message::parse(&wire).unwrap();
    assert_eq!(parsed.questions.len(), 3);
    assert!(parsed.questions.iter().all(|q| q.name == "note.example"));
}

#[test]
fn compressed_owner_and_name_rdata_are_bounded_and_rebased() {
    let mut wire = question();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[7] = 1;
    wire.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 8]);
    wire.extend_from_slice(b"\x05alias\xc0\x11");
    let parsed = Message::parse(&wire).unwrap();
    let rr = &parsed.sections[0][0];
    assert_eq!(rr.names, ["alias.example"]);
    assert_eq!(rr.raw.as_ptr(), wire[42..].as_ptr());
    assert_eq!(
        encode(
            parsed.id,
            parsed.flags,
            &parsed.questions,
            [&parsed.sections[0], &[], &[]],
            &[]
        )
        .unwrap(),
        wire
    );
    let mut questions = parsed.questions.clone();
    questions[0].name = "another.example".into();
    let changed = encode(
        parsed.id,
        parsed.flags,
        &questions,
        [&parsed.sections[0], &[], &[]],
        &[],
    )
    .unwrap();
    assert_eq!(
        Message::parse(&changed).unwrap().sections[0][0].names,
        ["alias.example"]
    );
}

#[test]
fn positive_name_and_record_boundaries() {
    let name = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    let q = Question {
        name: name.clone(),
        kind: 1,
        class: 1,
    };
    let wire = encode(0, 0, &[q], [&[], &[], &[]], &[]).unwrap();
    assert_eq!(Message::parse(&wire).unwrap().questions[0].name, name);
    let q = Question {
        name: "".into(),
        kind: 1,
        class: 1,
    };
    let qs = vec![q; MAX_RECORDS];
    assert_eq!(
        Message::parse(&encode(0, 0, &qs, [&[], &[], &[]], &[]).unwrap())
            .unwrap()
            .questions
            .len(),
        MAX_RECORDS
    );
    let mut over = vec![0; 12];
    over[4..6].copy_from_slice(&((MAX_RECORDS + 1) as u16).to_be_bytes());
    assert!(matches!(Message::parse(&over), Err(Error::Truncated)));
    over.extend_from_slice(&[0, 0, 1, 0, 1].repeat(MAX_RECORDS + 1));
    assert!(matches!(Message::parse(&over), Err(Error::Limit)));
}

#[test]
fn unknown_resource_and_trailing_bytes_are_preserved() {
    let mut wire = vec![
        0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0xff, 0, 0, 1, 0, 0, 0, 0, 0, 4,
    ];
    wire.extend_from_slice(b"note");
    wire.extend_from_slice(b"tail");
    let parsed = Message::parse(&wire).unwrap();
    assert_eq!(parsed.sections[0][0].raw, b"note");
    assert_eq!(parsed.trailing, b"tail");
    assert_eq!(
        encode(
            parsed.id,
            parsed.flags,
            &[],
            [&parsed.sections[0], &[], &[]],
            parsed.trailing
        )
        .unwrap(),
        wire
    );
}

#[test]
fn maximum_message_size_and_generic_output_limits() {
    let raw = vec![b'x'; MAX_MESSAGE - 23];
    let record = Record {
        name: "".into(),
        kind: 65280,
        class: 1,
        ttl: 0,
        raw: &raw,
        names: vec![],
        numbers: vec![],
        text: vec![],
    };
    let wire = encode(0, 0, &[], [&[record], &[], &[]], &[]).unwrap();
    assert_eq!(wire.len(), MAX_MESSAGE);
    assert!(Message::parse(&wire).is_ok());
    let mut over = wire;
    over.push(0);
    assert!(matches!(Message::parse(&over), Err(Error::Limit)));
    assert_eq!(
        encode(0, 0, &[], [&[], &[], &[]], &vec![0; MAX_MESSAGE]).unwrap_err(),
        Error::Limit
    );
}

#[test]
fn ordinary_field_truncation_stops_cleanly() {
    let wire = question();
    for n in 12..wire.len() {
        assert!(matches!(Message::parse(&wire[..n]), Err(Error::Truncated)))
    }
    let mut wire = question();
    wire[7] = 1;
    wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0]);
    assert!(matches!(Message::parse(&wire), Err(Error::Truncated)));
}

#[test]
fn minimum_section_bytes_precede_count_limits() {
    let mut wire = vec![0; 12];
    wire[6..8].copy_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&[0; 10]);
    assert!(matches!(Message::parse(&wire), Err(Error::Truncated)));
}

#[test]
fn many_valid_compressed_names_fit_the_declared_budget() {
    let questions = vec![
        Question {
            name: "one.two.three.four.five.six.seven.example".into(),
            kind: 1,
            class: 1
        };
        1000
    ];
    let wire = encode(7, 0x8180, &questions, [&[], &[], &[]], &[]).unwrap();
    let message = Message::parse(&wire).unwrap();
    assert_eq!(message.questions, questions);
}
