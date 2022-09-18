use criterion::{black_box, criterion_group, criterion_main, Criterion};
use elliptic_curve::sec1::ToEncodedPoint;
use mpc_core::point_addition::{PointAdditionFollower, PointAdditionLeader};
use p256::SecretKey;
use rand::thread_rng;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("point_addition", move |bench| {
        let mut rng = thread_rng();

        let server_secret = SecretKey::random(&mut rng);
        let server_pk = server_secret.public_key().to_projective();

        let leader_secret = SecretKey::random(&mut rng);
        let leader_point =
            (&server_pk * &leader_secret.to_nonzero_scalar()).to_encoded_point(false);

        let follower_secret = SecretKey::random(&mut rng);
        let follower_point =
            (&server_pk * &follower_secret.to_nonzero_scalar()).to_encoded_point(false);

        bench.iter(|| {
            let leader = PointAdditionLeader::new(&leader_point);
            let follower = PointAdditionFollower::new(&follower_point);

            let (leader_msg, leader) = leader.next();
            let (follower_msg, follower) = follower.next(leader_msg);

            let (leader_msg, leader) = leader.next(follower_msg);
            let (follower_msg, follower) = follower.next(leader_msg);

            let (leader_msg, leader) = leader.next(follower_msg);
            let (follower_msg, follower) = follower.next(leader_msg);

            let leader_share = leader.finalize(follower_msg).unwrap();
            let follower_share = follower.finalize().unwrap();

            black_box((leader_share, follower_share));
        });
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
