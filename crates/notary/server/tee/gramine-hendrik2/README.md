Start the container:
```
docker run -it --platform linux/amd64 --rm $(docker build -q .) bash
```

Calculate mr_enclave


  HINT: if you have installed the library, try setting PKG_CONFIG_PATH to the directory containing `openssl.pc`. 