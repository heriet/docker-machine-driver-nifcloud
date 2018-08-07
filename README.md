# Docker Machine Driver NIFCLOUD

WIP: Docker Machine Driver for NIFCLOUD (Unofficial)

## Install

```
$ go get heriet/docker-machine-driver-nifcloud
```

## Usage

```
$ docker-machine create --driver=nifcloud --help
```

```
$ docker-machine create --driver=nifcloud \
   --nifcloud-access-key=$NIFCLOUD_ACCESS_KEY \
   --nifcloud-secret-access-key=$NIFCLOUD_SECRET_ACCESS_KEY \
   --nifcloud-instance-type=e-small \
   --nifcloud-region=jp-east-1 \
   --nifcloud-security-group=mygroup \
   myinstance
```

