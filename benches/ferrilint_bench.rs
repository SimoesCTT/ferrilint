use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ferrilint::{MacroContext, CpioReader};

fn bench_macro_expansion(c: &mut Criterion) {
    let spec = r#"
Name: %{name}
Version: %{version}
Release: %{release}%{?dist}
Summary: High-performance RPM linter

%if 0%{?fedora} >= 40
BuildRequires: rustc cargo
%endif

%global optflags %{optflags} -fPIE
"#;

    c.bench_function("macro_expansion_complex", |b| {
        b.iter(|| {
            let mut ctx = MacroContext::new();
            ctx.define("name", "ferrilint");
            ctx.define("version", "0.1.0");
            ctx.define("release", "1");
            let _ = black_box(ctx.expand(black_box(spec)));
        })
    });
}

fn make_cpio_header(ino: u32, mode: u32, filesize: u32, namesize: u32) -> String {
    format!(
        "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        ino, mode, 0, 0, 1, 0, filesize, 0, 0, 0, 0, namesize, 0
    )
}

fn bench_cpio_parsing(c: &mut Criterion) {
    let mut cpio_data = Vec::new();
    let filename = "./usr/bin/ferrilint\0";
    let file_content = b"ELF64_MOCK_BINARY_PAYLOAD_DATA";
    
    let header_and_name_len = 110 + filename.len();
    let name_padding = (4 - (header_and_name_len % 4)) % 4;

    let header = make_cpio_header(1, 0o100755, file_content.len() as u32, filename.len() as u32);
    assert_eq!(header.len(), 110);

    cpio_data.extend_from_slice(header.as_bytes());
    cpio_data.extend_from_slice(filename.as_bytes());
    cpio_data.extend(std::iter::repeat(b'\0').take(name_padding));

    let data_padding = (4 - (file_content.len() % 4)) % 4;
    cpio_data.extend_from_slice(file_content);
    cpio_data.extend(std::iter::repeat(b'\0').take(data_padding));

    // Trailer
    let trailer_name = "TRAILER!!!\0";
    let trailer_header = make_cpio_header(0, 0, 0, trailer_name.len() as u32);
    assert_eq!(trailer_header.len(), 110);

    cpio_data.extend_from_slice(trailer_header.as_bytes());
    cpio_data.extend_from_slice(trailer_name.as_bytes());
    let trailer_header_and_name = 110 + trailer_name.len();
    let trailer_padding = (4 - (trailer_header_and_name % 4)) % 4;
    cpio_data.extend(std::iter::repeat(b'\0').take(trailer_padding));

    c.bench_function("cpio_payload_walk", |b| {
        b.iter(|| {
            let reader = CpioReader::new(black_box(&cpio_data));
            let count = reader.filter_map(|entry| entry.ok()).count();
            assert_eq!(black_box(count), 1);
        })
    });
}

criterion_group!(benches, bench_macro_expansion, bench_cpio_parsing);
criterion_main!(benches);
