//! Conversion for the SCTP core. Offsets index the bytes that were passed in.
use octetrail::sctp;
use pyo3::prelude::*;

pyo3::create_exception!(_native, SctpShortChunkError, pyo3::exceptions::PyException);

type ChunkRow = (u8, u8, u16, usize, usize, usize, usize);

/// `(chunks, stopped)` for the chunks from `start`. Each chunk is
/// `(type, flags, len, data_start, data_end, padding_start, padding_end)`.
/// A cut-off chunk header raises `SctpShortChunkError(have)`.
#[pyfunction]
fn _sctp_chunks(buf: &[u8], start: usize) -> PyResult<(Vec<ChunkRow>, bool)> {
    let found =
        sctp::chunks(buf, start).map_err(|short| SctpShortChunkError::new_err(short.have))?;
    let rows = found
        .chunks
        .iter()
        .map(|c| {
            (
                c.kind,
                c.flags,
                c.len,
                c.data.0,
                c.data.1,
                c.padding.0,
                c.padding.1,
            )
        })
        .collect();
    Ok((rows, found.stopped))
}

#[pyfunction]
fn _crc32c_add(crc: u32, buf: &[u8]) -> u32 {
    sctp::crc32c_add(crc, buf)
}

#[pyfunction]
fn _crc32c_done(crc: u32) -> u32 {
    sctp::crc32c_done(crc)
}

#[pyfunction]
fn _crc32c_table() -> Vec<u32> {
    sctp::CRC32C_TABLE.to_vec()
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_sctp_chunks, module)?)?;
    module.add_function(wrap_pyfunction!(_crc32c_add, module)?)?;
    module.add_function(wrap_pyfunction!(_crc32c_done, module)?)?;
    module.add_function(wrap_pyfunction!(_crc32c_table, module)?)?;
    module.add(
        "SctpShortChunkError",
        module.py().get_type::<SctpShortChunkError>(),
    )?;
    Ok(())
}
