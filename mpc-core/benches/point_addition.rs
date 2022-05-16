use criterion::{black_box, criterion_group, criterion_main, Criterion};
use elliptic_curve::sec1::ToEncodedPoint;
use mpc_core::point_addition::{
    MasterCore, PointAdditionMaster, PointAdditionMessage, PointAdditionSlave, SlaveCore,
};
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
            let mut master = PointAdditionMaster::new(&master_point);
            let mut slave = PointAdditionSlave::new(&slave_point);

            let mut master_message;
            let mut slave_message: Option<PointAdditionMessage> = None;
            loop {
                if !master.is_complete() {
                    master_message = master.next(slave_message).unwrap();
                } else {
                    master_message = None;
                }
                if !slave.is_complete() {
                    slave_message = slave.next(master_message).unwrap();
                } else {
                    slave_message = None;
                }
                if master.is_complete() && slave.is_complete() {
                    break;
                }
            }
            black_box(master.get_secret().unwrap());
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
