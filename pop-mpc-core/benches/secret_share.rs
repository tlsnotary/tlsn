use criterion::{black_box, criterion_group, criterion_main, Criterion};
use elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use pop_mpc_core::secret_share::*;
use rand::thread_rng;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("secret_share", move |bench| {
        let mut rng = thread_rng();

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key().to_projective();

        let master_secret = SecretKey::random(&mut rng);
        let master_point =
            (&server_pk * &master_secret.to_nonzero_scalar()).to_encoded_point(false);

        let slave_secret = SecretKey::random(&mut rng);
        let slave_point = (&server_pk * &slave_secret.to_nonzero_scalar()).to_encoded_point(false);

        bench.iter(|| {
            let master = SecretShareMaster::new(master_point);
            let slave = SecretShareSlave::new(slave_point);

            let (message, master) = master.next();
            let (message, slave) = slave.next(message);
            let (message, master) = master.next(message);
            let (message, slave) = slave.next(message);
            let (message, master) = master.next(message);
            let (message, _) = slave.next(message);
            let master = master.next(message);
            black_box(master.secret());
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
