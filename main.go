package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/heriet/docker-machine-driver-nifcloud/nifcloud"
)

func main() {
	plugin.RegisterDriver(new(nifcloud.Driver))
}
