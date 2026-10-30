use std::task::Context;

use futures::{AsyncWriteExt, task::waker};

use super::harness::{PartialWriter, WakeCounter};
use crate::prover::poll_write_to_server;

#[test]
fn drains_buffered_records_across_polls() {
    const FRAME_SIZE: usize = 16 * 1024;
    const FRAMES: usize = 4;

    let (mut sender, receiver) = futures_plex::duplex(FRAME_SIZE * FRAMES);
    futures::executor::block_on(sender.write_all(&[0; FRAME_SIZE * FRAMES])).unwrap();

    let wake_counter = WakeCounter::new();
    let waker = waker(wake_counter.clone());
    let mut cx = Context::from_waker(&waker);
    let mut writer = PartialWriter {
        max_write: FRAME_SIZE,
        written: 0,
    };

    // Model the executor's poll loop: poll, and only poll again if the
    // helper re-armed the waker. A helper that makes progress without
    // re-arming would leave the remaining records queued forever.
    let mut polls = 0;
    loop {
        let before = writer.written;
        poll_write_to_server(&mut cx, &receiver, &mut writer).unwrap();
        polls += 1;

        if writer.written == before {
            // No progress: `Pending`/EOF, so a real executor parks the
            // task on the wakers registered elsewhere.
            break;
        }

        assert!(
            wake_counter.take() > 0,
            "made progress without re-arming the waker"
        );

        if writer.written == FRAME_SIZE * FRAMES {
            break;
        }
        assert!(polls <= FRAMES, "not draining one frame per poll");
    }

    assert_eq!(writer.written, FRAME_SIZE * FRAMES);
}
