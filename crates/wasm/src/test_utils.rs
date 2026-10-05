//! Test-only support types for the wasm unit tests.
//!
//! This lives in the crate under test rather than being shared with the
//! harness: a real `IoChannel` needs a live WebSocket relay and a browser.

#![allow(dead_code)]

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

/// A JavaScript mock of the `IoChannel` interface.
///
/// Behaviour is scripted from Rust:
///
/// * [`push`](MockIoChannel::push) queues a chunk for the next `read()`.
/// * [`push_eof`](MockIoChannel::push_eof) queues an EOF (`null`).
/// * [`fail_unread`](MockIoChannel::fail_unread) makes `unread()` throw, to
///   exercise the missing-method error path.
/// * `unread()` records its payload and pushes it back onto the read queue,
///   mirroring the real channel's queue semantics.
///
/// Introspection methods (`unread_count`, `unread_at`, `write_count`,
/// `is_closed`) let tests assert on what the adapter did.
#[wasm_bindgen(inline_js = r#"
    export class MockIoChannel {
        constructor() {
            this._reads = [];
            this._unreads = [];
            this._writes = [];
            this._failUnread = false;
            this._closed = false;
        }

        push(bytes) { this._reads.push(bytes); }
        pushEof() { this._reads.push(null); }
        failUnread(flag) { this._failUnread = flag; }

        read() {
            if (this._reads.length) return Promise.resolve(this._reads.shift());
            // No EOF by default: keep the read pending.
            return new Promise(() => {});
        }

        write(data) {
            this._writes.push(new Uint8Array(data));
            return Promise.resolve();
        }

        close() {
            this._closed = true;
            return Promise.resolve();
        }

        unread(data) {
            if (this._failUnread) throw new Error("unread unsupported");
            const bytes = new Uint8Array(data);
            this._unreads.push(bytes);
            this._reads.unshift(bytes);
        }

        unreadCount() { return this._unreads.length; }
        unreadAt(index) { return this._unreads[index]; }
        writeCount() { return this._writes.length; }
        isClosed() { return this._closed; }
    }
"#)]
extern "C" {
    #[wasm_bindgen(js_name = MockIoChannel)]
    pub(crate) type MockIoChannel;

    #[wasm_bindgen(constructor)]
    pub(crate) fn new() -> MockIoChannel;

    #[wasm_bindgen(method)]
    pub(crate) fn push(this: &MockIoChannel, bytes: &Uint8Array);

    #[wasm_bindgen(method, js_name = pushEof)]
    pub(crate) fn push_eof(this: &MockIoChannel);

    #[wasm_bindgen(method, js_name = failUnread)]
    pub(crate) fn fail_unread(this: &MockIoChannel, flag: bool);

    #[wasm_bindgen(method, js_name = unreadCount)]
    pub(crate) fn unread_count(this: &MockIoChannel) -> u32;

    #[wasm_bindgen(method, js_name = unreadAt)]
    pub(crate) fn unread_at(this: &MockIoChannel, index: u32) -> Uint8Array;

    #[wasm_bindgen(method, js_name = writeCount)]
    pub(crate) fn write_count(this: &MockIoChannel) -> u32;

    #[wasm_bindgen(method, js_name = isClosed)]
    pub(crate) fn is_closed(this: &MockIoChannel) -> bool;
}

impl MockIoChannel {
    /// Returns the mock as a [`JsValue`], ready to be cast to `JsIo`.
    pub(crate) fn as_js_value(&self) -> JsValue {
        let value: &JsValue = self.as_ref();
        value.clone()
    }

    /// Returns the payload passed to the `index`-th `unread()` call.
    pub(crate) fn unread_bytes(&self, index: u32) -> Vec<u8> {
        self.unread_at(index).to_vec()
    }
}
