module github.com/aws/amazon-ecs-agent/agent

go 1.12

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/aws/aws-sdk-go v1.27.0
	github.com/awslabs/go-config-generator-for-fluentd-and-fluentbit v0.0.0-20190829210224-55d4fd2e6f35
	github.com/boltdb/bolt v1.3.1
	github.com/cihub/seelog v0.0.0-20170130134532-f561c5e57575
	github.com/containerd/cgroups v0.0.0-20190919134610-bf292b21730f
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.8.7
	github.com/containers/podman/v2 v2.2.1
	github.com/deniswernert/udev v0.0.0-20140626150257-82fe5be8ca5f
	github.com/didip/tollbooth v3.0.2+incompatible
	github.com/docker/docker v17.12.0-ce-rc1.0.20201020191947-73dc6a680cdd+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-units v0.4.0
	github.com/fzipp/gocyclo v0.0.0-20150627053110-6acd4345c835
	github.com/godbus/dbus v4.1.0+incompatible // indirect
	github.com/golang/mock v1.3.1
	github.com/google/go-cmp v0.5.2 // indirect
	github.com/gorilla/context v1.1.1 // indirect
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/gotestyourself/gotestyourself v1.4.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.3-0.20200817204227-f9c09b4ea1df
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pborman/uuid v0.0.0-20150603214016-ca53cad383ca
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.1.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/stretchr/testify v1.6.1
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/net v0.0.0-20201006153459-a7d1128ccaa0
	golang.org/x/sys v0.0.0-20201018230417-eeed37f84f13
	golang.org/x/tools v0.0.0-20191112195655-aa38f8e97acc
	google.golang.org/grpc v1.32.0 // indirect
	honnef.co/go/tools v0.0.1-2019.2.3
)

replace github.com/docker/docker => github.com/docker/docker v17.12.0-ce-rc1.0.20200318231421-30d54e64f643+incompatible
replace github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.8.6
replace github.com/containerd/cgroups => github.com/containerd/cgroups v0.0.0-20210114181951-8a68de567b68
replace github.com/coreos/go-systemd => github.com/coreos/go-systemd v0.0.0-20180511133405-39ca1b05acc7