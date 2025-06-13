# Run the TLSN benches with Docker

In the root folder of this repository, run:
```
docker build -t tlsn-bench . -f ./crates/harness/harness.Dockerfile
```

Next run the benches with:
```
docker run -it --privileged -v ./crates/harness/:/benches tlsn-bench bash -c "runner setup; runner test"
```
The `--privileged` parameter is required because this test bench needs permission to create networks with certain parameters

To run the benches in a browser run:
```
+docker run -it --privileged -v ./crates/harness/:/benches tlsn-bench bash -c "cd /; runner setup; runner --target browser test"
```