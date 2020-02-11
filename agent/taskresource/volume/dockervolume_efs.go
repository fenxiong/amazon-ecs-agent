package volume

import (
	"fmt"

	"github.com/aws/amazon-ecs-agent/agent/config"

	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/cihub/seelog"
)

const (
	EFSDriverNameEFS = "amazon-ecs-volume-plugin"
	efsDriverTypeEFS = "efs"
	EFSDriverNameNFS = "local"
	efsDriverTypeNFS = "nfs"

	// Enums used by acs's api-2.json model.
	efsIAMAuthEnabled           = "ENABLED"
	efsTransitEncryptionEnabled = "ENABLED"
)

// EFSVolumeConfig represents efs volume configuration.
type EFSVolumeConfig struct {
	AuthConfig            EFSAuthConfig `json:"authorizationConfig"`
	FileSystemID          string        `json:"fileSystemId"`
	RootDirectory         string        `json:"rootDirectory"`
	TransitEncryption     string        `json:"transitEncryption"`
	TransitEncryptionPort int64         `json:"transitEncryptionPort"`
	// DockerVolumeName is internal docker name for this volume.
	DockerVolumeName string `json:"dockerVolumeName"`
}

// EFSAuthConfig contains auth config for an efs volume.
type EFSAuthConfig struct {
	AccessPointId string `json:"accessPointId"`
	Iam           string `json:"iam"`
}

func (efsVolCfg *EFSVolumeConfig) GetNFSDriverOptions(cfg *config.Config) map[string]string {
	domain := getDomainForPartition(cfg.AWSRegion)
	// These are the NFS options recommended by EFS, see:
	// https://docs.aws.amazon.com/efs/latest/ug/mounting-fs-mount-cmd-general.html
	ostr := fmt.Sprintf("addr=%s.efs.%s.%s,nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport", efsVolCfg.FileSystemID, cfg.AWSRegion, domain)
	devstr := fmt.Sprintf(":%s", efsVolCfg.RootDirectory)
	return map[string]string{
		"type":   efsDriverTypeNFS,
		"device": devstr,
		"o":      ostr,
	}
}

func (efsVolCfg *EFSVolumeConfig) GetEFSDriverOptions(credsRelativeURI string) map[string]string {
	seelog.Infof("REMOVEME efs volume config: %v", *efsVolCfg)
	device := efsVolCfg.FileSystemID
	if efsVolCfg.RootDirectory != "" {
		device = fmt.Sprintf("%s:%s", device, efsVolCfg.RootDirectory)
	}
	ostr := ""
	if efsVolCfg.TransitEncryption == efsTransitEncryptionEnabled {
		ostr += "tls"
	}
	if efsVolCfg.AuthConfig.Iam == efsIAMAuthEnabled {
		ostr += fmt.Sprintf(",iam,awscredentialsrelativeuri=%s", credsRelativeURI)
	}
	if efsVolCfg.AuthConfig.AccessPointId != "" {
		ostr += fmt.Sprintf(",accesspoint=%s", efsVolCfg.AuthConfig.AccessPointId)
	}
	options := map[string]string{
		"type":   efsDriverTypeEFS,
		"device": device,
		"o":      ostr,
	}
	return options
}

func getDomainForPartition(region string) string {
	partition, ok := endpoints.PartitionForRegion(endpoints.DefaultPartitions(), region)
	if !ok {
		seelog.Warnf("No partition resolved for region (%s). Using AWS default (%s)", region, endpoints.AwsPartition().DNSSuffix())
		return endpoints.AwsPartition().DNSSuffix()
	}
	return partition.DNSSuffix()
}
