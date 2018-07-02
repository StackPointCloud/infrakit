package instance

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/docker/infrakit/pkg/controller/group/util"
	logutil "github.com/docker/infrakit/pkg/log"
	"github.com/docker/infrakit/pkg/spi"
	"github.com/docker/infrakit/pkg/spi/instance"
	"github.com/docker/infrakit/pkg/types"
	"github.com/profitbricks/profitbricks-sdk-go"
	"github.com/satori/go.uuid"
)

const (
	stateFileExt  = ".pbstate"
	dataDirMode   = 0700
	stateFileMode = 0600
)

var log = logutil.New("module", "plugin/instance/profitbricks")

// NewInstancePlugin creates a new ProfitBricks instance plugin
func NewInstancePlugin(username, password, endpoint, dir string) instance.Plugin {
	client := profitbricks.NewClient(username, password)

	if endpoint != "" {
		client.SetURL(endpoint)
	}

	instancePlugin := &plugin{
		client: client,
		dir:    dir,
	}

	vendorInfo := instancePlugin.VendorInfo()
	client.SetUserAgent(fmt.Sprintf("%s %s/%s", client.GetUserAgent(), vendorInfo.Name, vendorInfo.Version))

	return instancePlugin
}

type plugin struct {
	client *profitbricks.Client
	dir    string
}

type createInstance struct {
	Tags                       map[string]string
	ProfitBricksInstancesInput InstancesInput
}

// InstancesInput spefies ProfitBricks instance input parameters
type InstancesInput struct {
	DatacenterID     string    `json:"DatacenterID,omitempty"`
	NamePrefix       string    `json:"NamePrefix,omitempty"`
	Image            string    `json:"Image,omitempty"`
	SSHKeyPath       string    `json:"SSHKeyPath,omitempty"`
	Location         string    `json:"Location,omitempty"`
	DiskSize         int       `json:"DiskSize,omitempty"`
	DiskType         string    `json:"DiskType,omitempty"`
	AvailabilityZone string    `json:"AvailabilityZone,omitempty"`
	StaticIP         bool      `json:"StaticIP,omitempty"`
	Cores            int       `json:"Cores,omitempty"`
	RAM              int       `json:"RAM,omitempty"`
	Firewall         *Firewall `json:"Firewall,omitempty"`
}

// Firewall type is ProfitBricks firewall rule
type Firewall struct {
	Name           string `json:"Name,omitempty"`
	Protocol       string `json:"Protocol,omitempty"`
	SourceMac      string `json:"SourceMac,omitempty"`
	SourceIP       string `json:"SourceIp,omitempty"`
	TargetIP       string `json:"TargetIp,omitempty"`
	IcmpCode       int    `json:"IcmpCode,omitempty"`
	IcmpType       int    `json:"IcmpType,omitempty"`
	PortRangeStart int    `json:"PortRangeStart,omitempty"`
	PortRangeEnd   int    `json:"PortRangeEnd,omitempty"`
}

// Info returns a vendor specific name and version
func (p *plugin) VendorInfo() *spi.VendorInfo {
	return &spi.VendorInfo{
		InterfaceSpec: spi.InterfaceSpec{
			Name:    "infrakit-instance-profitbricks",
			Version: "0.1.0",
		},
		URL: "https://github.com/docker/infrakit/pkg/provider/profitbricks",
	}
}

// Validate performs local validation on a provision request.
func (p *plugin) Validate(req *types.Any) error {
	properties := createInstance{}
	log.Info("Validating ProfitBricks data format...")
	if err := req.Decode(&properties); err != nil {
		return err
	}

	log.Info("Validating ProfitBricks input data...")
	locations, _ := p.client.ListLocations()

	if locations.StatusCode == http.StatusForbidden {
		return fmt.Errorf("ProfitBricks credentials you provided are incorrect")
	}

	if properties.ProfitBricksInstancesInput.DatacenterID == "" {
		return fmt.Errorf("DatacenterID parameter is required")
	}

	if properties.ProfitBricksInstancesInput.NamePrefix == "" {
		return fmt.Errorf("NamePrefix parameter is required")
	}

	if properties.ProfitBricksInstancesInput.Location == "" {
		return fmt.Errorf("Location parameter is required")
	}

	if properties.ProfitBricksInstancesInput.DiskType == "" {
		return fmt.Errorf("DiskType parameter is required")
	}

	if properties.ProfitBricksInstancesInput.Image == "" {
		return fmt.Errorf("Image parameter is required")
	}

	if properties.ProfitBricksInstancesInput.SSHKeyPath == "" {
		return fmt.Errorf("Path to SSH key is required")
	}

	if !pathExists(properties.ProfitBricksInstancesInput.SSHKeyPath) {
		return fmt.Errorf("Path '%s' does not exist", properties.ProfitBricksInstancesInput.SSHKeyPath)
	}

	if properties.ProfitBricksInstancesInput.Location == "" {
		return fmt.Errorf("Location parameter is required")
	}

	if properties.ProfitBricksInstancesInput.DiskSize == 0 {
		return fmt.Errorf("DiskSize parameter is required")
	}

	if properties.ProfitBricksInstancesInput.Cores == 0 {
		return fmt.Errorf("Cores parameter is required")
	}

	if properties.ProfitBricksInstancesInput.RAM == 0 {
		return fmt.Errorf("RAM parameter is required")
	}

	if properties.ProfitBricksInstancesInput.Firewall != nil {
		if properties.ProfitBricksInstancesInput.Firewall.Protocol == "" {
			return fmt.Errorf("Firewall protocol parameter is required")
		}
	}

	return nil
}

func (p *plugin) Provision(spec instance.Spec) (*instance.ID, error) {
	pbdata := &createInstance{}

	err := spec.Properties.Decode(pbdata)
	if err != nil {
		return nil, fmt.Errorf("Invalid input data: %s", err.Error())
	}

	log.Info("Provisioning a ProfitBricks server...")
	server, ipID, err := p.createPBMachine(pbdata.ProfitBricksInstancesInput)

	if err != nil {
		return nil, fmt.Errorf("Failed to create the server: %s", err.Error())
	}
	log.Info("ProfitBricks server has successfully been provisioned")

	err = p.recordInstanceState(spec, server, pbdata, ipID)
	if err != nil {
		log.Error(fmt.Sprintf("Error while recording instance state: %s", err.Error()))
		return nil, err
	}

	id := instance.ID(server.ID)

	return &id, err
}

// Label labels the instance
func (p *plugin) Label(instance instance.ID, labels map[string]string) error {
	// Labeling is not supported
	return nil
}

// DescribeInstances returns descriptions of all instances matching all of the provided tags.
// The properties flag indicates the client is interested in receiving details about each instance.
func (p *plugin) DescribeInstances(tags map[string]string, properties bool) ([]instance.Description, error) {
	return p.getExistingInstances(tags, properties)
}

func (p *plugin) Destroy(id instance.ID, context instance.Context) error {
	log.Info("Destroying server " + string(id))
	files, err := ioutil.ReadDir(p.dir)

	if err != nil {
		log.Error(fmt.Sprintf("Error occurred while reading directory %s , %s", p.dir, err.Error()))
		return err
	}

	for _, file := range files {
		if strings.Contains(file.Name(), stateFileExt) && file.Name() == (string(id)+stateFileExt) {
			fullPath := filepath.Join(p.dir, file.Name())
			bytes, err := ioutil.ReadFile(fullPath)
			if err != nil {
				log.Error(err.Error())
				return fmt.Errorf("Error occurred while reading content of '%s' %s", file.Name(), err)
			}
			var description instance.Description

			err = json.Unmarshal(bytes, &description)
			if err != nil {
				e := fmt.Errorf("Error occurred while parsing content of '%s' %s", file.Name(), err)
				log.Error(e.Error())
				return e
			}

			// p.authenticate()

			datacenterID := description.Tags["datacenterID"]
			_, err = p.client.DeleteServer(datacenterID, string(id))

			if err != nil {
				msg := "Error while deleting a server: " + err.Error()
				log.Error(msg)
				return errors.New(msg)
			}

			volumeID := description.Tags["volumeID"]
			_, err = p.client.DeleteVolume(datacenterID, volumeID)

			if err != nil {
				log.Warn(fmt.Sprintf("Error while deleting volume '%s', %s", volumeID, err.Error()))
			}

			ipID := description.Tags["ipID"]
			if ipID != "" {
				_, err = p.client.ReleaseIPBlock(ipID)

				if err != nil {
					log.Warn(fmt.Sprintf("Error while releasing IP block '%s', %s", ipID, err.Error()))
				}
			}
			log.Info("ProfitBricks server has successfully been deleted")

			return p.removeFile(string(id + stateFileExt))
		}
	}
	return nil
}

func (p *plugin) createPBMachine(input InstancesInput) (*profitbricks.Server, string, error) {
	// p.authenticate()
	p.client.SetDepth(5)

	SSHKey, err := getSSHKey(input.SSHKeyPath)
	if err != nil {
		return nil, "", err
	}

	var imageID, imageAlias string
	_, err = uuid.FromString(input.Image)
	if err != nil {
		log.Debug(fmt.Sprintf("Using image alias %s to deploy a server", input.Image))
		imageAlias = input.Image
	} else {
		log.Debug(fmt.Sprintf("Using image UUID %s to deploy a server", input.Image))
		imageID = input.Image
	}

	dc, err := p.client.GetDatacenter(input.DatacenterID)

	if err != nil {
		msg := fmt.Sprintf("An error occurred while fetching datacenter '%s', %s", input.DatacenterID, err)
		log.Crit(msg)
		return nil, "", fmt.Errorf(msg)
	}

	var lan *profitbricks.Lan

	lans, err := p.client.ListLans(dc.ID)
	if lans.StatusCode == http.StatusOK {
		if len(lans.Items) > 0 {
			for _, l := range lans.Items {
				if l.Properties.Public {
					lan = &l
					break
				}
			}
		}
	} else {
		return nil, "", fmt.Errorf("An error occurred while retrieving LANs: %s, %d", lans.Response, lans.StatusCode)
	}

	instanceName := input.NamePrefix + "-" + util.RandomAlphaNumericString(6)

	if lan == nil {
		lan = &profitbricks.Lan{
			Properties: profitbricks.LanProperties{
				Name:   instanceName,
				Public: true,
			},
		}
		tmp, err := p.client.CreateLan(dc.ID, *lan)

		if tmp.StatusCode > 299 {
			return nil, "", fmt.Errorf("An error occurred while provisioning a LAN: %s", err.Error())
		}

		err = p.client.WaitTillProvisioned(tmp.Headers.Get("Location"))
		if err != nil {
			return nil, "", fmt.Errorf("An error occurred while provisioning LAN: %s", err.Error())
		}

		tmp, err = p.client.GetLan(dc.ID, tmp.ID)
		if err != nil {
			return nil, "", fmt.Errorf("An error occurred while retrieving LAN: %s, %d", err.Error(), tmp.StatusCode)
		}
		lan = tmp
	}

	lanID, _ := strconv.Atoi(lan.ID)
	dhcp := true
	server := profitbricks.Server{
		Properties: profitbricks.ServerProperties{
			Name:  instanceName,
			Cores: input.Cores,
			RAM:   input.RAM,
		},
		Entities: &profitbricks.ServerEntities{
			Nics: &profitbricks.Nics{
				Items: []profitbricks.Nic{
					{
						Properties: &profitbricks.NicProperties{
							Name: instanceName,
							Dhcp: &dhcp,
							Lan:  lanID,
						},
					},
				},
			},
			Volumes: &profitbricks.Volumes{
				Items: []profitbricks.Volume{
					{
						Properties: profitbricks.VolumeProperties{
							Name:             instanceName,
							Size:             input.DiskSize,
							Type:             input.DiskType,
							SSHKeys:          []string{SSHKey},
							AvailabilityZone: input.AvailabilityZone,
							Image:            imageID,
							ImageAlias:       imageAlias,
						},
					},
				},
			},
		},
	}

	ipID := ""
	if input.StaticIP == true {
		req := profitbricks.IPBlock{
			Properties: profitbricks.IPBlockProperties{
				Size:     1,
				Location: input.Location,
			},
		}

		ipBlock, err := p.client.ReserveIPBlock(req)

		if err != nil {
			return nil, "", err
		}
		ipID = ipBlock.ID

		p.client.WaitTillProvisioned(ipBlock.Headers.Get("Location"))

		server.Entities.Nics.Items[0].Properties.Ips = ipBlock.Properties.IPs
		*server.Entities.Nics.Items[0].Properties.Dhcp = false
	}

	if input.Firewall != nil {
		server.Entities.Nics.Items[0].Properties.FirewallActive = true

		firewall := profitbricks.FirewallRule{
			Properties: profitbricks.FirewallruleProperties{
				Protocol: input.Firewall.Protocol,
			},
		}

		if input.Firewall.Name != "" {
			firewall.Properties.Name = input.Firewall.Name
		}

		if input.Firewall.IcmpCode != 0 {
			firewall.Properties.IcmpCode = &input.Firewall.IcmpCode
		}

		if input.Firewall.IcmpType != 0 {
			firewall.Properties.IcmpType = &input.Firewall.IcmpType
		}

		if input.Firewall.TargetIP != "" {
			firewall.Properties.TargetIP = &input.Firewall.TargetIP
		}

		if input.Firewall.SourceMac != "" {
			firewall.Properties.SourceMac = &input.Firewall.SourceMac
		}

		if input.Firewall.SourceIP != "" {
			firewall.Properties.SourceIP = &input.Firewall.SourceIP
		}

		if input.Firewall.PortRangeStart != 0 {
			firewall.Properties.PortRangeStart = &input.Firewall.PortRangeStart
		}

		if input.Firewall.PortRangeEnd != 0 {
			firewall.Properties.PortRangeEnd = &input.Firewall.PortRangeEnd
		}

		server.Entities.Nics.Items[0].Entities = &profitbricks.NicEntities{
			FirewallRules: &profitbricks.FirewallRules{
				Items: []profitbricks.FirewallRule{
					firewall,
				},
			},
		}
	}

	resp, err := p.client.CreateServer(dc.ID, server)

	if err != nil {
		return nil, "", err
	}

	err = p.client.WaitTillProvisioned(resp.Headers.Get("Location"))
	if err != nil {
		return nil, "", fmt.Errorf("An error occurred while provisioning Server: %s", err)
	}
	return resp, ipID, nil
}

func getSSHKey(path string) (string, error) {
	publicKey, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(publicKey), nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func (p *plugin) recordInstanceState(spec instance.Spec, server *profitbricks.Server, pbdata *createInstance, ipID string) error {
	if !pathExists(p.dir) {
		if err := os.MkdirAll(p.dir, dataDirMode); err != nil {
			log.Crit("An error occurred while attempting to create data directory", "error", err)
			os.Exit(-1)
		}
	}

	dc, err := p.client.GetDatacenter(pbdata.ProfitBricksInstancesInput.DatacenterID)

	server, err = p.client.GetServer(dc.ID, server.ID)

	if err != nil {
		return fmt.Errorf("Error fetching server: %s", err.Error())
	}

	spec.Tags["datacenterID"] = dc.ID
	spec.Tags["volumeID"] = server.Entities.Volumes.Items[0].ID
	spec.Tags["ipID"] = ipID

	logicalID := instance.LogicalID(server.Entities.Nics.Items[0].Properties.Ips[0])
	description := instance.Description{
		Tags:      spec.Tags,
		ID:        instance.ID(server.ID),
		LogicalID: &logicalID,
	}
	towrite, err := json.MarshalIndent(description, "", "\t")

	if err != nil {
		return fmt.Errorf("Error occurred while marshalling data into JSON: %s", err)
	}

	filePath := filepath.Join(p.dir, server.ID+stateFileExt)
	err = ioutil.WriteFile(filePath, towrite, stateFileMode)
	if err != nil {
		log.Crit(fmt.Sprintf("An error occurred while trying to write to file %s", filePath), "error", err)
		os.Exit(-1)
	}

	log.Debug("Instance state persisted to " + filePath)
	return nil
}

func (p *plugin) removeFile(file string) error {
	return os.Remove(filepath.Join(p.dir, file))
}

func (p *plugin) getExistingInstances(tags map[string]string, properties bool) (descriptions []instance.Description, err error) {
	if !pathExists(p.dir) {
		return descriptions, err
	}

	files, err := ioutil.ReadDir(p.dir)

	if err != nil {
		log.Error(fmt.Sprintf("Error occurred while reading directory %s %s", p.dir, err.Error()))
		return nil, err
	}

	for _, file := range files {
		if strings.Contains(file.Name(), stateFileExt) {
			fullPath := filepath.Join(p.dir, file.Name())
			bytes, err := ioutil.ReadFile(fullPath)
			if err != nil {
				return nil, fmt.Errorf("Error occurred while reading content of '%s' %s", file.Name(), err)
			}
			var description instance.Description

			err = json.Unmarshal(bytes, &description)
			if err != nil {
				return nil, fmt.Errorf("Error occurred while parsing content of '%s' %s", file.Name(), err)
			}
			serverID := file.Name()[0 : len(file.Name())-len(stateFileExt)]

			server, err := p.client.GetServer(description.Tags["datacenterID"], serverID)
			if err != nil {
				if server.StatusCode == http.StatusNotFound {
					log.Error(fmt.Sprintf("Instance %s seems to be removed. Skipping.", file.Name()), err)
					err := p.removeFile(fullPath)
					if err != nil {
						log.Error(fmt.Sprintf("Error occurred while attempting to remove file %s, %s", fullPath, err.Error()))
					}
				}
				continue
			}

			ip := instance.LogicalID(server.Entities.Nics.Items[0].Properties.Ips[0])

			description.ID = instance.ID(server.ID)
			description.LogicalID = &ip

			if properties {
				if any, err := types.AnyValue(server.Response); err == nil {
					description.Properties = any
				} else {
					log.Warn("Error encoding instance properties: ", err)
				}
			}
			descriptions = append(descriptions, description)
		}
	}

	return descriptions, err
}
