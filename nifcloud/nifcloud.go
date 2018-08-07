package nifcloud

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"text/template"

	"github.com/alice02/nifcloud-sdk-go/nifcloud"
	"github.com/alice02/nifcloud-sdk-go/nifcloud/awserr"
	"github.com/alice02/nifcloud-sdk-go/nifcloud/credentials"
	"github.com/alice02/nifcloud-sdk-go/nifcloud/session"
	"github.com/alice02/nifcloud-sdk-go/service/computing"

	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/mcnutils"
	"github.com/docker/machine/libmachine/ssh"
	"github.com/docker/machine/libmachine/state"
)

const (
	driverName            = "nifcloud"
	defaultRegion         = "jp-east-1"
	defaultImageID        = "89" // Ubuntu 16.04 64bit Plain
	defaultSSHUser        = "root"
	defaultAccountingType = "2" // measured rate
	defaultIPType         = "static"
)

// Ubuntu
const startupScriptForUbuntu = `#!/bin/bash

configure_private_network_interface () {

  PRIVATE_IP='{{ .PrivateIP }}'
  PRIVATE_NETMASK='{{ .PrivateNetmask }}'
  IP_TYPE='{{ .IPType }}'

  PATH_NET_INTERFACES='/etc/network/interfaces'

  if [ "${IP_TYPE}" != 'none' ]; then
    cat << _EOF_ > $PATH_NET_INTERFACES
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto ens160
iface ens160 inet dhcp

auto ens192
iface ens192 inet static
address ${PRIVATE_IP}
netmask ${PRIVATE_NETMASK}
_EOF_

  else
    cat << _EOF_ > $PATH_NET_INTERFACES
# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto ens160
iface ens160 inet static
address ${PRIVATE_IP}
netmask ${PRIVATE_NETMASK}
_EOF_
    
  fi

	reboot
}

ufw allow 2376/tcp
ufw allow 3376/tcp

PRIVATE_NETWORK_ID='{{ .PrivateNetworkID }}'
USE_PRIVATE_DHCP='{{ .UsePrivateDHCP }}'

if [ -n "${PRIVATE_NETWORK_ID}" ] && [ "${USE_PRIVATE_DHCP}" != 'true' ]; then
configure_private_network_interface
fi
`

// CentOS
const startupScriptForCentOS = `#!/bin/bash

configure_private_network_interface () {

  PRIVATE_IP='{{ .PrivateIP }}'
  PRIVATE_NETMASK='{{ .PrivateNetmask }}'
  IP_TYPE='{{ .IPType }}'

  if [ "${IP_TYPE}" != 'none' ]; then
    NIC_NAME='ens192'
  else
    NIC_NAME='ens160'
  fi

  cat << _EOF_ > /etc/sysconfig/network-scripts/ifcfg-${NIC_NAME}
DEVICE=${NIC_NAME}
BOOTPROTO=static
IPADDR=${PRIVATE_IP}
NETMASK=${PRIVATE_NETMASK}
ONBOOT=yes
PEERDNS=no
_EOF_
 
  systemctl restart network
}

PRIVATE_NETWORK_ID='{{ .PrivateNetworkID }}'
USE_PRIVATE_DHCP='{{ .UsePrivateDHCP }}'

if [ -n "${PRIVATE_NETWORK_ID}" ] && [ "${USE_PRIVATE_DHCP}" != 'true' ]; then
  configure_private_network_interface
fi
`

// Driver is the driver used when no driver is selected. It is used to
// connect to existing Docker hosts by specifying the URL of the host as
// an option.
type Driver struct {
	*drivers.BaseDriver
	computing *computing.Computing

	AccessKey        string
	SecretAccessKey  string
	Region           string
	AvailabilityZone string
	Endpoint         string
	ImageID          string
	KeyName          string
	SecurityGroup    string
	InstanceType     string
	AccountingType   string
	IPType           string
	PublicIP         string
	PrivateIP        string
	PrivateNetworkID string
	UsePrivateDHCP   bool

	InstanceID     string
	PrivateNetmask string

	UsePrivateIP bool
}

// NewDriver creates driver
func NewDriver(hostName, storePath string) *Driver {
	return &Driver{
		Region:         defaultRegion,
		ImageID:        defaultImageID,
		AccountingType: defaultAccountingType,
		IPType:         defaultIPType,

		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			SSHUser:     defaultSSHUser,
			StorePath:   storePath,
		},
	}
}

// GetCreateFlags registers the flags
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "nifcloud-access-key",
			Usage:  "NIFCLOUD Access Key",
			EnvVar: "NIFCLOUD_ACCESS_KEY",
		},
		mcnflag.StringFlag{
			Name:   "nifcloud-secret-access-key",
			Usage:  "NIFCLOUD Secret Access Key",
			EnvVar: "NIFCLOUD_SECRET_ACCESS_KEY",
		},
		mcnflag.StringFlag{
			Name:   "nifcloud-region",
			Usage:  "NIFCLOUD Region",
			Value:  defaultRegion,
			EnvVar: "NIFCLOUD_REGION",
		},
		mcnflag.StringFlag{
			Name:   "nifcloud-availability-zone",
			Usage:  "NIFCLOUD AvailabilityZone",
			EnvVar: "NIFCLOUD_AVAILABILITY_ZONE",
		},
		mcnflag.StringFlag{
			Name:   "nifcloud-endpoint",
			Usage:  "NIFCLOUD Endpoint",
			EnvVar: "NIFCLOUD_ENDPOINT",
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-image-id",
			Usage: "NIFCLOUD Image ID",
			Value: defaultImageID,
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-ssh-user",
			Usage: "NIFCLOUD SSH User",
			Value: defaultSSHUser,
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-key-name",
			Usage: "NIFCLOUD Key Name",
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-security-group",
			Usage: "NIFCLOUD Security Group",
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-instance-type",
			Usage: "NIFCLOUD Instance Type",
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-accounting-type",
			Usage: "NIFCLOUD Accounting Type",
			Value: defaultAccountingType,
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-ip-type",
			Usage: "NIFCLOUD IP Type [static|elastic|none]",
			Value: defaultIPType,
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-public-ip",
			Usage: "NIFCLOUD Public IP (IP Type elastic only)",
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-private-ip",
			Usage: "NIFCLOUD Private IP",
		},
		mcnflag.StringFlag{
			Name:  "nifcloud-private-network-id",
			Usage: "NIFCLOUD Private LAN Network ID",
		},
		mcnflag.BoolFlag{
			Name:  "nifcloud-use-private-dhcp",
			Usage: "NIFCLOUD Private LAN Network use DHCP",
		},
		mcnflag.BoolFlag{
			Name:  "nifcloud-use-private-ip",
			Usage: "Forse the usage of private IP",
		},
	}
}

// Create cretes nifcloud computing instance as docker host
func (d *Driver) Create() error {

	if err := d.createKeyPair(); err != nil {
		return fmt.Errorf("create key pair failed: %s", err)
	}

	input := computing.RunInstancesInput{
		InstanceId:            &d.MachineName,
		ImageId:               &d.ImageID,
		KeyName:               &d.KeyName,
		InstanceType:          &d.InstanceType,
		AccountingType:        &d.AccountingType,
		IpType:                &d.IPType,
		DisableApiTermination: nifcloud.Bool(false),
		SecurityGroup: []*string{
			&d.SecurityGroup,
		},
		Placement: &computing.RequestPlacementStruct{
			AvailabilityZone: &d.AvailabilityZone,
		},
	}

	if d.PrivateNetworkID != "" {
		if err := d.configureNetmask(); err != nil {
			return fmt.Errorf("network configure failed: %s", err)
		}
		var rnis *computing.RequestNetworkInterfaceStruct

		if d.UsePrivateDHCP {
			rnis = &computing.RequestNetworkInterfaceStruct{
				NetworkId: &d.PrivateNetworkID,
			}
		} else {
			rnis = &computing.RequestNetworkInterfaceStruct{
				NetworkId: &d.PrivateNetworkID,
				IpAddress: nifcloud.String("static"),
			}
		}

		input.NetworkInterface = []*computing.RequestNetworkInterfaceStruct{rnis}
	}

	// TODO UserScript mapping
	if d.ImageID == "89" { // Ubuntu 16
		log.Debugf("nifcloud UserScript added for ImageID : %s", d.ImageID)
		userData, err := d.generateUserData(startupScriptForUbuntu)
		if err != nil {
			return fmt.Errorf("userscript error: %s", err)
		}
		input.UserData = &userData
	} else if d.ImageID == "9" { // CentOS 7.4
		log.Debugf("nifcloud UserScript added for ImageID : %s", d.ImageID)
		userData, err := d.generateUserData(startupScriptForCentOS)
		if err != nil {
			return fmt.Errorf("userscript error: %s", err)
		}
		input.UserData = &userData
	}

	log.Infof("nicloud RunInstances: %s", d.MachineName)
	_, err := d.getComputing().RunInstances(&input)

	// TODO: do not skip error Serialize
	if err != nil {
		awsErr, _ := err.(awserr.Error)

		if awsErr.Code() != "SerializationError" {
			return fmt.Errorf("Error RunInstance: %s", err)
		}
	}

	d.InstanceID = d.MachineName

	d.waitForInstance()

	ip, err := d.GetIP()
	if err != nil {
		return err
	}

	d.IPAddress = ip
	log.Infof("IPAdress: %s", ip)

	return nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return driverName
}

// GetIP returns the IP address of the nifcloud computing instance
func (d *Driver) GetIP() (string, error) {
	if d.IPAddress != "" {
		return d.IPAddress, nil
	}

	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	instance, err := d.getInstance()
	if err != nil {
		return "", err
	}

	if !d.hasGlobalIP() {
		return *instance.PrivateIpAddress, nil
	} else if d.UsePrivateIP {
		return *instance.PrivateIpAddress, nil
	}

	return *instance.IpAddress, nil
}

// GetSSHHostname returns ssh hostname
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetSSHUsername returns username for ssh
func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = "docker"
	}
	return d.SSHUser
}

// GetURL returns the URL of docker instance
func (d *Driver) GetURL() (string, error) {
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

// GetState returns computing instance status
func (d *Driver) GetState() (state.State, error) {
	instance, err := d.getInstance()
	if err != nil {
		return state.Error, err
	}

	switch *instance.InstanceState.Name {
	case "pending":
		return state.Starting, nil
	case "creating":
		return state.Starting, nil
	case "waiting":
		return state.Starting, nil
	case "warning":
		return state.Error, nil
	case "suspending":
		return state.Stopping, nil
	case "running":
		return state.Running, nil
	case "stopped":
		return state.Stopped, nil
	default:
		log.Warnf("unrecognized instance state: %s", *instance.InstanceState)
		return state.Error, nil
	}
}

// Start stats the computing instance
func (d *Driver) Start() error {
	log.Debugf("nifcloud StartInstances: %s", d.InstanceID)

	_, err := d.getComputing().StartInstances(&computing.StartInstancesInput{
		InstanceId: []*string{&d.InstanceID},
	})
	if err != nil {
		return err
	}

	return d.waitForInstance()
}

// Stop stops the computing instance
func (d *Driver) Stop() error {
	log.Debugf("nifcloud StopInstances: %s", d.InstanceID)

	_, err := d.getComputing().StopInstances(&computing.StopInstancesInput{
		InstanceId: []*string{&d.InstanceID},
		Force:      nifcloud.Bool(false),
	})
	return err
}

// Kill stops the computing instance
func (d *Driver) Kill() error {
	log.Debugf("ninfcloud StopInstances(force): %s", d.InstanceID)

	_, err := d.getComputing().StopInstances(&computing.StopInstancesInput{
		InstanceId: []*string{&d.InstanceID},
		Force:      nifcloud.Bool(true),
	})
	return err
}

// Remove removes the computing instance
func (d *Driver) Remove() error {
	log.Debugf("nifcloud TerminateInstances: %s", d.InstanceID)

	_, err := d.getComputing().TerminateInstances(&computing.TerminateInstancesInput{
		InstanceId: []*string{&d.InstanceID},
	})

	if err != nil {
		return err
	}

	if err := d.deleteKeyPair(); err != nil {
		return err
	}

	return nil
}

// Restart restarts the computing instance
func (d *Driver) Restart() error {
	_, err := d.getComputing().RebootInstances(&computing.RebootInstancesInput{
		InstanceId: []*string{&d.InstanceID},
	})
	return err
}

// SetConfigFromFlags initializes the docker driver config
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.AccessKey = flags.String("nifcloud-access-key")
	d.SecretAccessKey = flags.String("nifcloud-secret-access-key")

	d.Region = flags.String("nifcloud-region")
	d.AvailabilityZone = flags.String("nifcloud-availability-zone")

	d.Endpoint = flags.String("nifcloud-endpoint")
	d.ImageID = flags.String("nifcloud-image-id")
	d.SSHUser = flags.String("nifcloud-ssh-user")
	d.SSHPort = 22
	d.KeyName = flags.String("nifcloud-key-name")
	d.SecurityGroup = flags.String("nifcloud-security-group")
	d.InstanceType = flags.String("nifcloud-instance-type")
	d.AccountingType = flags.String("nifcloud-accounting-type")

	d.IPType = flags.String("nifcloud-ip-type")
	d.PublicIP = flags.String("nifcloud-public-ip")
	d.PrivateIP = flags.String("nifcloud-private-ip")
	d.PrivateNetworkID = flags.String("nifcloud-private-network-id")
	d.UsePrivateDHCP = flags.Bool("nifcloud-use-private-dhcp")

	d.UsePrivateIP = flags.Bool("nifcloud-use-private-ip")

	d.SetSwarmConfigFromFlags(flags)

	if d.AccessKey == "" {
		return fmt.Errorf("--nifcloud-access-key is required")
	}
	if d.SecretAccessKey == "" {
		return fmt.Errorf("--nifcloud-secret-access-key is required")
	}

	if d.IPType == "elastic" {
		if d.PublicIP == "" {
			return fmt.Errorf("--nifcloud-public-ip is required when IP type is elastic")
		}

		// TODO impl elastic
		return fmt.Errorf("elastic ip is not implemented")
	}

	if d.PrivateNetworkID != "" {
		if d.UsePrivateDHCP {
			if d.PrivateIP != "" {
				return fmt.Errorf("do not set --nifcloud-private-ip when use DHCP")
			}

		} else {
			if d.PrivateIP == "" {
				return fmt.Errorf("--nifcloud-private-ip is required when not use DHCP")
			}
		}
	}

	return nil
}

func (d *Driver) getComputing() *computing.Computing {
	if d.computing == nil {
		conf := nifcloud.Config{
			Region:      nifcloud.String(d.Region),
			Credentials: credentials.NewStaticCredentials(d.AccessKey, d.SecretAccessKey, ""),
		}
		if d.Endpoint != "" {
			log.Debugf("nifcloud endpoint: %s", d.Endpoint)
			conf.Endpoint = &d.Endpoint
		}

		sess := session.Must(session.NewSession(&conf))
		d.computing = computing.New(sess)
	}

	return d.computing
}

func (d *Driver) createKeyPair() error {

	privateKeyPath := d.GetSSHKeyPath()

	if err := ssh.GenerateSSHKey(privateKeyPath); err != nil {
		return err
	}

	publicKey, err := ioutil.ReadFile(privateKeyPath + ".pub")
	if err != nil {
		return err
	}
	encodedKey := base64.StdEncoding.EncodeToString([]byte(publicKey))

	if d.KeyName == "" {
		uploadKeyName := d.MachineName
		d.KeyName = uploadKeyName
	}

	log.Infof("nicloud ImportKeyPair: %s", d.KeyName)

	_, err = d.getComputing().ImportKeyPair(&computing.ImportKeyPairInput{
		KeyName:           &d.KeyName,
		PublicKeyMaterial: &encodedKey,
	})

	if err != nil {
		return err
	}

	// TODO wait

	return nil
}

func (d *Driver) deleteKeyPair() error {

	_, err := d.getComputing().DeleteKeyPair(&computing.DeleteKeyPairInput{
		KeyName: &d.KeyName,
	})

	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) getInstance() (*computing.InstancesSetItem, error) {
	instances, err := d.getComputing().DescribeInstances(&computing.DescribeInstancesInput{
		InstanceId: []*string{&d.InstanceID},
	})
	if err != nil {
		return nil, err
	}
	return instances.ReservationSet[0].InstancesSet[0], nil
}

func (d *Driver) instanceIsRunning() bool {
	st, err := d.GetState()
	if err != nil {
		log.Debug(err)
	}
	if st == state.Running {
		return true
	}
	return false
}

func (d *Driver) waitForInstance() error {
	if err := mcnutils.WaitFor(d.instanceIsRunning); err != nil {
		return err
	}

	return nil
}

func (d *Driver) configureNetmask() error {
	lan, err := d.getPrivateLan()
	if err != nil {
		return err
	}

	log.Debugf("private lan name: %s", *lan.PrivateLanName)
	log.Debugf("cidr: %s", *lan.CidrBlock)

	netmask, err := generateCiderNetmask(*lan.CidrBlock)
	if err != nil {
		return err
	}

	d.PrivateNetmask = netmask
	log.Debugf("netmask: %s", d.PrivateNetmask)

	return nil
}

func (d *Driver) getPrivateLan() (*computing.PrivateLanSetItem, error) {

	log.Debugf("nifcloud NiftyDescribePrivateLans: %s", d.PrivateNetworkID)

	lans, err := d.getComputing().NiftyDescribePrivateLans(&computing.NiftyDescribePrivateLansInput{
		NetworkId: []*string{&d.PrivateNetworkID},
	})
	if err != nil {
		return nil, err
	}
	return lans.PrivateLanSet[0], nil
}

func (d *Driver) hasGlobalIP() bool {
	return d.IPType != "none"
}

func (d *Driver) generateUserData(scriptTemplate string) (string, error) {
	tpl, _ := template.New("UserScript").Parse(scriptTemplate)
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, d); err != nil {
		return "", err
	}
	userScript := buf.String()

	log.Debugf("userscript: %s", userScript)

	userData := base64.StdEncoding.EncodeToString([]byte(userScript))

	return userData, nil
}

func generateCiderNetmask(cidr string) (string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	return net.IP(ipnet.Mask).String(), nil
}
