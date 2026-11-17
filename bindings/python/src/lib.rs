//! A synchronous Python binary-stream adapter around the independent Rust core.

mod dns;
mod ethernet;
mod http;
mod ipv4;
mod ipv6;
mod tls;

use octetrail::{ByteOrder, Error, Header, Limits, Reader, Resolution};
use pyo3::exceptions::{
    PyBlockingIOError, PyMemoryError, PyNotImplementedError, PyOSError, PyTypeError, PyValueError,
};
use pyo3::gc::{PyTraverseError, PyVisit};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::io::{self, Read, Write};

pyo3::create_exception!(_native, TruncatedError, pyo3::exceptions::PyException);
pyo3::create_exception!(_native, PacketLimitError, PyValueError);

struct PythonInput {
    object: Py<PyAny>,
}

impl Read for PythonInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Python::attach(|py| {
            let result = self.object.bind(py).call_method1("read", (buf.len(),))?;
            let bytes = result
                .cast::<PyBytes>()
                .map_err(|_| PyTypeError::new_err("binary read(size) must return bytes"))?;
            let data = bytes.as_bytes();
            if data.len() > buf.len() {
                return Err(PyValueError::new_err(
                    "binary read(size) returned too many bytes",
                ));
            }
            buf[..data.len()].copy_from_slice(data);
            Ok(data.len())
        })
        // Preserve Python exceptions, including InterruptedError, by identity.
        // Rust read_exact must not retry a Python callback exception silently.
        .map_err(io::Error::other)
    }
}

fn python_error(error: Error) -> PyErr {
    match error {
        Error::Io(error) => {
            let message = error.to_string();
            // Preserve Python callback exceptions. Native WriteZero and other
            // standard I/O failures instead become OSError with their message.
            match error
                .into_inner()
                .and_then(|inner| inner.downcast::<PyErr>().ok())
            {
                Some(error) => *error,
                None => PyOSError::new_err(message),
            }
        }
        Error::Truncated(part) => TruncatedError::new_err(format!("truncated {part}")),
        Error::UnsupportedMagic(_) => PyValueError::new_err("invalid tcpdump header"),
        Error::Allocation => PyMemoryError::new_err("cannot allocate packet buffer"),
        error @ (Error::PacketLimit { .. }
        | Error::BlockLimit { .. }
        | Error::ResourceLimit { .. }) => PacketLimitError::new_err(error.to_string()),
        error @ Error::UnsupportedBlock(_) => PyNotImplementedError::new_err(error.to_string()),
        error => PyValueError::new_err(error.to_string()),
    }
}

#[pyclass(name = "_Reader", module = "octetrail._native")]
struct RawReader {
    reader: Option<Reader<PythonInput>>,
    header: Header,
}

#[pymethods]
impl RawReader {
    #[new]
    fn new(fileobj: Py<PyAny>, max_packet_bytes: u32) -> PyResult<Self> {
        let reader = Reader::new(PythonInput { object: fileobj }, Limits { max_packet_bytes })
            .map_err(python_error)?;
        let header = reader.header();
        Ok(Self {
            reader: Some(reader),
            header,
        })
    }

    fn metadata(&self) -> (u32, u32, bool) {
        (
            self.header.snaplen,
            self.header.linktype,
            self.header.resolution == Resolution::Nanoseconds,
        )
    }

    fn read_packet<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<Option<(u32, u32, Bound<'py, PyBytes>)>> {
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("capture reader is closed"))?;
        match reader.next() {
            None => Ok(None),
            Some(Err(error)) => Err(python_error(error)),
            Some(Ok(packet)) => Ok(Some((
                packet.timestamp.seconds,
                packet.timestamp.fraction,
                PyBytes::new(py, &packet.data),
            ))),
        }
    }

    fn close(&mut self) {
        self.reader = None;
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        if let Some(reader) = &self.reader {
            visit.call(&reader.get_ref().object)?;
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.close();
    }

    #[getter]
    fn closed(&self) -> bool {
        self.reader.is_none()
    }
}

struct PythonOutput {
    object: Py<PyAny>,
}

impl Write for PythonOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Python::attach(|py| {
            // Limit the temporary Python copy even when a sink makes short writes.
            let chunk = &bytes[..bytes.len().min(64 * 1024)];
            let result = self
                .object
                .bind(py)
                .call_method1("write", (PyBytes::new(py, chunk),))?;
            if result.is_none() {
                return Err(PyBlockingIOError::new_err("binary write returned None"));
            }
            let count = result.extract::<usize>()?;
            if count > chunk.len() {
                return Err(PyValueError::new_err(
                    "binary write returned too many bytes",
                ));
            }
            Ok(count)
        })
        .map_err(io::Error::other)
    }

    fn flush(&mut self) -> io::Result<()> {
        Python::attach(|py| self.object.bind(py).call_method0("flush").map(|_| ()))
            .map_err(io::Error::other)
    }
}

#[pyclass(name = "_Writer", module = "octetrail._native")]
struct RawWriter {
    writer: Option<octetrail::Writer<PythonOutput>>,
    resolution: Resolution,
}

#[pymethods]
impl RawWriter {
    #[new]
    fn new(
        fileobj: Py<PyAny>,
        snaplen: u32,
        linktype: u32,
        nano: bool,
        little: bool,
        max_packet_bytes: u32,
    ) -> PyResult<Self> {
        let resolution = if nano {
            Resolution::Nanoseconds
        } else {
            Resolution::Microseconds
        };
        let options = octetrail::writer::Options {
            byte_order: if little {
                ByteOrder::Little
            } else {
                ByteOrder::Big
            },
            resolution,
            snaplen,
            linktype,
        };
        let writer = octetrail::Writer::new(
            PythonOutput { object: fileobj },
            options,
            Limits { max_packet_bytes },
        )
        .map_err(python_error)?;
        Ok(Self {
            writer: Some(writer),
            resolution,
        })
    }

    fn write_packet(
        &mut self,
        seconds: u32,
        fraction: u32,
        data: &Bound<'_, PyBytes>,
    ) -> PyResult<()> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("capture writer is closed"))?;
        let bytes = data.as_bytes();
        let length = u32::try_from(bytes.len())
            .map_err(|_| PyValueError::new_err("captured length exceeds 32 bits"))?;
        writer
            .write_packet(
                octetrail::Timestamp {
                    seconds,
                    fraction,
                    resolution: self.resolution,
                },
                length,
                bytes,
            )
            .map_err(python_error)
    }

    fn flush(&mut self) -> PyResult<()> {
        self.writer
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("capture writer is closed"))?
            .flush()
            .map_err(python_error)
    }

    fn close(&mut self) {
        self.writer = None;
    }

    #[getter]
    fn closed(&self) -> bool {
        self.writer.is_none()
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        if let Some(writer) = &self.writer {
            visit.call(&writer.get_ref().object)?;
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.close();
    }
}

type NgWriteConfig = (u32, u16, bool, u32, u32);
type NgWriteClock = (Option<u8>, Option<i64>);
type NgWriteText<'py> = (Option<Bound<'py, PyBytes>>, Option<Bound<'py, PyBytes>>);

#[pyclass(name = "_PcapngWriter", module = "octetrail._native")]
struct RawNgWriter {
    writer: Option<octetrail::pcapng_writer::Writer<PythonOutput>>,
}

#[pymethods]
impl RawNgWriter {
    #[new]
    fn new(
        fileobj: Py<PyAny>,
        config: NgWriteConfig,
        clock: NgWriteClock,
        text: NgWriteText<'_>,
    ) -> PyResult<Self> {
        let (snaplen, linktype, little, max_packet_bytes, max_block_bytes) = config;
        let options = octetrail::pcapng_writer::Options {
            byte_order: if little {
                ByteOrder::Little
            } else {
                ByteOrder::Big
            },
            snaplen,
            linktype,
            timestamp_resolution: clock.0.map(|encoded| {
                if encoded & 0x80 == 0 {
                    octetrail::pcapng::Resolution::Decimal(encoded)
                } else {
                    octetrail::pcapng::Resolution::Binary(encoded & 0x7f)
                }
            }),
            timestamp_offset: clock.1,
            section_comment: text.0.as_ref().map(|value| value.as_bytes()),
            interface_name: text.1.as_ref().map(|value| value.as_bytes()),
        };
        let limits = octetrail::pcapng_writer::Limits {
            max_packet_bytes,
            max_block_bytes,
        };
        let writer = octetrail::pcapng_writer::Writer::new(
            PythonOutput { object: fileobj },
            options,
            limits,
        )
        .map_err(python_error)?;
        Ok(Self {
            writer: Some(writer),
        })
    }

    fn write_packet(&mut self, ticks: u64, data: &Bound<'_, PyBytes>) -> PyResult<()> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("capture writer is closed"))?;
        let bytes = data.as_bytes();
        let original = u32::try_from(bytes.len())
            .map_err(|_| PyValueError::new_err("captured length exceeds 32 bits"))?;
        writer
            .write_packet(ticks, original, bytes)
            .map_err(python_error)
    }

    fn flush(&mut self) -> PyResult<()> {
        self.writer
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("capture writer is closed"))?
            .flush()
            .map_err(python_error)
    }

    fn close(&mut self) {
        self.writer = None;
    }

    #[getter]
    fn closed(&self) -> bool {
        self.writer.is_none()
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        if let Some(writer) = &self.writer {
            visit.call(&writer.get_ref().object)?;
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.close();
    }
}

type NgRecord<'py> = (u64, u32, u8, i64, Bound<'py, PyBytes>);

#[pyclass(name = "_PcapngReader", module = "octetrail._native")]
struct RawNgReader {
    reader: Option<octetrail::pcapng::Reader<PythonInput>>,
    interface: octetrail::pcapng::Interface,
}

#[pymethods]
impl RawNgReader {
    #[new]
    fn new(
        fileobj: Py<PyAny>,
        max_packet_bytes: u32,
        max_block_bytes: u32,
        max_interfaces: u32,
        max_blocks_per_read: u32,
    ) -> PyResult<Self> {
        let limits = octetrail::pcapng::Limits {
            max_packet_bytes,
            max_block_bytes,
            max_interfaces,
            max_blocks_per_read,
        };
        let reader = octetrail::pcapng::Reader::new(PythonInput { object: fileobj }, limits)
            .map_err(python_error)?;
        let interface = reader.first_interface();
        Ok(Self {
            reader: Some(reader),
            interface,
        })
    }

    fn metadata(&self) -> (u32, u16) {
        (self.interface.snaplen, self.interface.linktype)
    }

    fn read_packet<'py>(&mut self, py: Python<'py>) -> PyResult<Option<NgRecord<'py>>> {
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("capture reader is closed"))?;
        match reader.next() {
            None => Ok(None),
            Some(Err(error)) => Err(python_error(error)),
            Some(Ok(packet)) => {
                let (base, exponent) = packet.timestamp.resolution.components();
                Ok(Some((
                    packet.timestamp.ticks,
                    base,
                    exponent,
                    packet.timestamp.offset_seconds,
                    PyBytes::new(py, &packet.data),
                )))
            }
        }
    }

    fn close(&mut self) {
        self.reader = None;
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        if let Some(reader) = &self.reader {
            visit.call(&reader.get_ref().object)?;
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.close();
    }

    #[getter]
    fn closed(&self) -> bool {
        self.reader.is_none()
    }
}

#[pymodule(gil_used = true)]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    ethernet::register(module)?;
    ipv4::register(module)?;
    ipv6::register(module)?;
    dns::register(module)?;
    http::register(module)?;
    tls::register(module)?;
    vrrp::register(module)?;
    module.add_class::<RawReader>()?;
    module.add_class::<RawNgReader>()?;
    module.add_class::<RawWriter>()?;
    module.add_class::<RawNgWriter>()?;
    module.add("TruncatedError", module.py().get_type::<TruncatedError>())?;
    module.add(
        "PacketLimitError",
        module.py().get_type::<PacketLimitError>(),
    )?;
    tcp::register(module)?;
    Ok(())
}

mod tcp;
mod vrrp;
