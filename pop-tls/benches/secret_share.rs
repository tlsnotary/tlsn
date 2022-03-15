use criterion::{black_box, criterion_group, criterion_main, Criterion};
use elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use pop_tls::secret_share::*;
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
            let mut master = SecretShareMaster::new(master_point);
            let mut slave = SecretShareSlave::new(slave_point);

            let master_step_one = master.step_one();
            let slave_step_one = slave.step_one(master_step_one);
            let master_step_two = master.step_two(slave_step_one);
            let slave_step_two = slave.step_two(master_step_two);
            let master_step_three = master.step_three(slave_step_two);
            let slave_step_three = slave.step_three(master_step_three);
            let master_share = master.step_four(slave_step_three);
            black_box(master_share);
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
