use criterion::{black_box, criterion_group, criterion_main, Criterion};
use elliptic_curve::sec1::ToEncodedPoint;
use mpc_core::point_addition::{master, slave, MasterCore, SlaveCore};
use p256::SecretKey;
use rand::thread_rng;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("point_addition", move |bench| {
        let mut rng = thread_rng();

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key().to_projective();

        let master_secret = SecretKey::random(&mut rng);
        let master_point =
            (&server_pk * &master_secret.to_nonzero_scalar()).to_encoded_point(false);

        let slave_secret = SecretKey::random(&mut rng);
        let slave_point = (&server_pk * &slave_secret.to_nonzero_scalar()).to_encoded_point(false);

        bench.iter(|| {
            let mut master = master::PointAdditionMaster::new(&master_point);
            let mut slave = slave::PointAdditionSlave::new(&slave_point);

            let message = master.next(None).unwrap().unwrap();
            let message = slave.next(message).unwrap();
            let message = master.next(Some(message)).unwrap().unwrap();
            let message = slave.next(message).unwrap();
            let message = master.next(Some(message)).unwrap().unwrap();
            let message = slave.next(message).unwrap();
            master.next(Some(message)).unwrap();
            black_box(master.get_secret());
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
