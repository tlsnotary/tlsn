# Run the TLSN benches with Docker

In the root folder of this repository, run:
```
# Change to BENCH_TYPE=browser if you want benchmarks to run in the browser.
docker build -t tlsn-bench . -f ./crates/benches/binary/benches.Dockerfile --build-arg BENCH_TYPE=native
```

Next run the benches with:
```
docker run -it --privileged -v ./crates/benches/binary:/benches tlsn-bench
```
The `--privileged` parameter is required because this test bench needs permission to create networks with certain parameters