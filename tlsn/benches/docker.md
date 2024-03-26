# Run the TLSN benches with Docker

In the root folder of this repository, run:
```
docker build -t tlsn-bench . -f ./tlsn/benches/benches.Dockerfile
```

Next run the benches with:
```
docker run -it --privileged -v ./tlsn/benches/:/benches tlsn-bench
```
The `--privileged` parameter is required because this test bench needs permission to create networks with certain parameters