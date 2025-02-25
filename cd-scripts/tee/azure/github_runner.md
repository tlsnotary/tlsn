
* https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/adding-self-hosted-runners
* https://github.com/Umair-Gillani/self-hosted_runner


## Basic setup
```
sudo apt update
sudo apt upgrade -y
sudo apt install -y git
```

## Install and configure the Runner

1. Navigate to your [GitHub repository > Settings > Actions > Runners](https://github.com/tlsnotary/tlsn/settings/actions/runners).
2. Click "New self-hosted runner" (Linux, x64)
3. Follow the listed steps (and add "sgx" as extra label)

This should be something like:
```
mkdir actions-runner && cd actions-runner
curl -o actions-runner-linux-x64-2.322.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.322.0/actions-runner-linux-x64-2.322.0.tar.gz
echo "b13b784808359f31bc79b08a191f5f83757852957dd8fe3dbfcc38202ccf5768  actions-runner-linux-x64-2.322.0.tar.gz" | shasum -a 256 -c
tar xzf ./actions-runner-linux-x64-2.322.0.tar.gz

./config.sh --url https://github.com/tlsnotary/tlsn --token AAFTQOACIGJCKLCVHHFS2DDHXWF6Y

```

You can test the runner with "./run.sh", however it is better to install it as a service (so it survives reboots):
```
sudo ./svc.sh install
sudo ./svc.sh start
```

## Install docker

```
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

Allow ubuntu user to use docker:
```
dockerd-rootless-setuptool.sh install
```

test:
```
docker run hello-world
```

### allow access to docker registry

Install azure cli: (https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-linux)
```
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

Login to Azure:
```
az login
az acr login --name notaryserverbuilds
```


### publish the builder docker container to Azure registry

Note: Make sure you are logged in with the "Pay-As-You-go" subscription, and not "pse". Otherwise you can not write to the registry.
