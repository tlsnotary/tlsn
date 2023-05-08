use std::pin::Pin;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use futures::Future;
use mpc_circuits::circuits::AES128;
use mpc_garble::{
    protocol::deap::mock::create_mock_deap_vm, Decode, Execute, Memory, Thread, Vm, VmError,
};

async fn bench_deap() {
    let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("mock").await;
    let mut leader_thread = leader_vm.new_thread("mock_thread").await.unwrap();
    let mut follower_thread = follower_vm.new_thread("mock_thread").await.unwrap();

    let key = [0u8; 16];
    let msg = [0u8; 16];

    let leader_fut = {
        let key_ref = leader_thread
            .new_private_input::<[u8; 16]>("key", Some(key))
            .unwrap();
        let msg_ref = leader_thread
            .new_private_input::<[u8; 16]>("msg", None)
            .unwrap();
        let ciphertext_ref = leader_thread.new_output::<[u8; 16]>("ciphertext").unwrap();

        async {
            leader_thread
                .execute(
                    AES128.clone(),
                    &[key_ref, msg_ref],
                    &[ciphertext_ref.clone()],
                )
                .await
                .unwrap();

            leader_thread.decode(&[ciphertext_ref]).await.unwrap();

            leader_vm.finalize().await.unwrap();
        }
    };

    let follower_fut = {
        let key_ref = follower_thread
            .new_private_input::<[u8; 16]>("key", None)
            .unwrap();
        let msg_ref = follower_thread
            .new_private_input::<[u8; 16]>("msg", Some(msg))
            .unwrap();
        let ciphertext_ref = follower_thread
            .new_output::<[u8; 16]>("ciphertext")
            .unwrap();

        async {
            follower_thread
                .execute(
                    AES128.clone(),
                    &[key_ref, msg_ref],
                    &[ciphertext_ref.clone()],
                )
                .await
                .unwrap();

            follower_thread.decode(&[ciphertext_ref]).await.unwrap();

            follower_vm.finalize().await.unwrap();
        }
    };

    _ = futures::join!(leader_fut, follower_fut)
}

fn bench_aes_leader<T: Thread + Execute + Decode>(
    thread: &mut T,
    block: usize,
) -> Pin<Box<dyn Future<Output = Result<[u8; 16], VmError>> + '_>> {
    Box::pin(async move {
        let key = thread.new_private_input(&format!("key/{block}"), Some([0u8; 16]))?;
        let msg = thread.new_private_input(&format!("msg/{block}"), Some([0u8; 16]))?;
        let ciphertext = thread.new_output::<[u8; 16]>(&format!("ciphertext/{block}"))?;

        thread
            .execute(AES128.clone(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut values = thread.decode(&[ciphertext]).await?;

        Ok(values.pop().unwrap().try_into().unwrap())
    })
}

fn bench_aes_follower<T: Thread + Execute + Decode>(
    thread: &mut T,
    block: usize,
) -> Pin<Box<dyn Future<Output = Result<[u8; 16], VmError>> + '_>> {
    Box::pin(async move {
        let key = thread.new_private_input::<[u8; 16]>(&format!("key/{block}"), None)?;
        let msg = thread.new_private_input::<[u8; 16]>(&format!("msg/{block}"), None)?;
        let ciphertext = thread.new_output::<[u8; 16]>(&format!("ciphertext/{block}"))?;

        thread
            .execute(AES128.clone(), &[key, msg], &[ciphertext.clone()])
            .await?;

        let mut values = thread.decode(&[ciphertext]).await?;

        Ok(values.pop().unwrap().try_into().unwrap())
    })
}

async fn bench_aes_threadpool(thread_count: usize, block_count: usize) {
    let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("bench_vm").await;

    let (mut leader_pool, mut follower_pool) = futures::try_join!(
        leader_vm.new_thread_pool("bench_pool", thread_count),
        follower_vm.new_thread_pool("bench_pool", thread_count),
    )
    .unwrap();

    let mut leader_scope = leader_pool.new_scope();
    let mut follower_scope = follower_pool.new_scope();

    for block in 0..block_count {
        leader_scope.push(move |thread| bench_aes_leader(thread, block));
        follower_scope.push(move |thread| bench_aes_follower(thread, block));
    }

    _ = futures::join!(leader_scope.wait(), follower_scope.wait());

    futures::try_join!(leader_vm.finalize(), follower_vm.finalize()).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("deap");
    let thread_count = 4;
    let block_count = 128;

    let rt = tokio::runtime::Runtime::new().unwrap();
    group.bench_function("aes", |b| {
        b.to_async(&rt).iter(|| async {
            bench_deap().await;
            black_box(())
        })
    });

    group.throughput(criterion::Throughput::Bytes(block_count as u64 * 16));
    group.bench_function("aes_mt", |b| {
        b.to_async(&rt).iter(|| async {
            bench_aes_threadpool(thread_count, block_count).await;
            black_box(())
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
