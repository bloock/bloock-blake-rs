use bloock_blake_rs::Blake512;
use criterion::{criterion_group, criterion_main, Criterion};

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut blake = Blake512::default();
    let buf: Vec<u8> = vec![0; 8 << 10];
    let tmp: Vec<u8> = vec![0; 32];

    c.bench_function("blake hash", |b| {
        b.iter(|| {
            blake.reset();
            blake.write(&buf[..64]);
            blake.sum(&tmp);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
