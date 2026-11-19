#![cfg(feature = "protocols")]
use octetrail::vrrp::{layout, Layout};

#[test]
fn addresses_then_auth() {
    let found = layout(2, b"\x0a\0\0\x01\x0a\0\0\x02auth");
    assert_eq!(
        found,
        Layout {
            addrs: vec![(0, 4), (4, 8)],
            auth: (8, 12)
        }
    );
}

#[test]
fn zero_count_and_empty_data() {
    assert_eq!(
        layout(0, b""),
        Layout {
            addrs: vec![],
            auth: (0, 0)
        }
    );
    assert_eq!(layout(255, b"").addrs.len(), 255);
}
