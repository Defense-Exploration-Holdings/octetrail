//! NetFlow v1 to v7 record boundaries as dpkt 1.9.8 walks them.

/// How many whole records of `size` bytes fit in `len` bytes, and where the
/// bytes of a cut-off record start, if any. dpkt fails on a cut-off record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Records {
    pub count: usize,
    pub tail: Option<usize>,
}

/// Split `len` bytes into fixed records of `size` bytes. `size` must not be 0.
pub fn records(len: usize, size: usize) -> Records {
    assert!(size > 0, "record size must not be 0");
    let count = len / size;
    let used = count * size;
    Records {
        count,
        tail: (used < len).then_some(used),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_and_cut() {
        assert_eq!(
            records(96, 48),
            Records {
                count: 2,
                tail: None
            }
        );
        assert_eq!(
            records(100, 48),
            Records {
                count: 2,
                tail: Some(96)
            }
        );
        assert_eq!(
            records(0, 48),
            Records {
                count: 0,
                tail: None
            }
        );
        assert_eq!(
            records(5, 48),
            Records {
                count: 0,
                tail: Some(0)
            }
        );
    }
}
