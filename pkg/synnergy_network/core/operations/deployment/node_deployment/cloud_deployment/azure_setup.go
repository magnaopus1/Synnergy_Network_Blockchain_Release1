package cloud_deployment

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/pkg/errors"
)

// AzureConfig holds configuration details for Azure deployment.
type AzureConfig struct {
	SubscriptionID      string
	ResourceGroupName   string
	Location            string
	VMSize              string
	ImagePublisher      string
	ImageOffer          string
	ImageSKU            string
	ImageVersion        string
	AdminUsername       string
	AdminPassword       string
	VNetName            string
	SubnetName          string
	PublicIPAddressName string
	NSGName             string
	IPConfigName        string
	InterfaceName       string
	VMName              string
	TagKey              string
	TagValue            string
}

// NodeDeployment holds the necessary information for deploying a node.
type NodeDeployment struct {
	Config    *AzureConfig
	Resources *armresources.Client
	Compute   *armcompute.Client
	Network   *armnetwork.Client
}

// NewAzureClient initializes a new Azure client.
func NewAzureClient(config *AzureConfig) (*NodeDeployment, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create Azure credential")
	}

	subscriptionClient := armsubscriptions.NewClient(cred, nil)
	ctx := context.Background()
	_, err = subscriptionClient.Get(ctx, config.SubscriptionID, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to validate subscription")
	}

	resourceClient := armresources.NewClient(config.SubscriptionID, cred, nil)
	computeClient := armcompute.NewClient(config.SubscriptionID, cred, nil)
	networkClient := armnetwork.NewClient(config.SubscriptionID, cred, nil)

	return &NodeDeployment{
		Config:    config,
		Resources: resourceClient,
		Compute:   computeClient,
		Network:   networkClient,
	}, nil
}

// CreateResourceGroup creates a resource group.
func (nd *NodeDeployment) CreateResourceGroup() error {
	ctx := context.Background()
	params := armresources.ResourceGroup{
		Location: &nd.Config.Location,
		Tags: map[string]*string{
			nd.Config.TagKey: &nd.Config.TagValue,
		},
	}
	_, err := nd.Resources.ResourceGroups.CreateOrUpdate(ctx, nd.Config.ResourceGroupName, params, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create resource group")
	}
	return nil
}

// CreateVirtualNetwork creates a virtual network.
func (nd *NodeDeployment) CreateVirtualNetwork() error {
	ctx := context.Background()
	params := armnetwork.VirtualNetwork{
		Location: &nd.Config.Location,
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{to.StringPtr("10.0.0.0/16")},
			},
		},
		Tags: map[string]*string{
			nd.Config.TagKey: &nd.Config.TagValue,
		},
	}
	_, err := nd.Network.VirtualNetworks.CreateOrUpdate(ctx, nd.Config.ResourceGroupName, nd.Config.VNetName, params, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create virtual network")
	}
	return nil
}

// CreateSubnet creates a subnet.
func (nd *NodeDeployment) CreateSubnet() error {
	ctx := context.Background()
	params := armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: to.StringPtr("10.0.1.0/24"),
		},
		Tags: map[string]*string{
			nd.Config.TagKey: &nd.Config.TagValue,
		},
	}
	_, err := nd.Network.Subnets.CreateOrUpdate(ctx, nd.Config.ResourceGroupName, nd.Config.VNetName, nd.Config.SubnetName, params, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create subnet")
	}
	return nil
}

// CreatePublicIPAddress creates a public IP address.
func (nd *NodeDeployment) CreatePublicIPAddress() error {
	ctx := context.Background()
	params := armnetwork.PublicIPAddress{
		Location: &nd.Config.Location,
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: armnetwork.IPAllocationMethodDynamic.ToPtr(),
		},
		Tags: map[string]*string{
			nd.Config.TagKey: &nd.Config.TagValue,
		},
	}
	_, err := nd.Network.PublicIPAddresses.CreateOrUpdate(ctx, nd.Config.ResourceGroupName, nd.Config.PublicIPAddressName, params, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create public IP address")
	}
	return nil
}

// CreateNetworkSecurityGroup creates a network security group.
func (nd *NodeDeployment) CreateNetworkSecurityGroup() error {
	ctx := context.Background()
	params := armnetwork.NetworkSecurityGroup{
		Location: &nd.Config.Location,
		Tags: map[string]*string{
			nd.Config.TagKey: &nd.Config.TagValue,
		},
	}
	_, err := nd.Network.NetworkSecurityGroups.CreateOrUpdate(ctx, nd.Config.ResourceGroupName, nd.Config.NSGName, params, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create network security group")
	}
	return nil
}

// CreateNetworkInterface creates a network interface.
func (nd *NodeDeployment) CreateNetworkInterface() error {
	ctx := context.Background()
	ipConfig := armnetwork.InterfaceIPConfiguration{
		Name: &nd.Config.IPConfigName,
		Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			Subnet: &armnetwork.Subnet{
				ID: to.StringPtr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/virtualNetworks/%s/subnets/%s",
					nd.Config.SubscriptionID, nd.Config.ResourceGroupName, nd.Config.VNetName, nd.Config.SubnetName)),
			},
			PrivateIPAllocationMethod: armnetwork.IPAllocationMethodDynamic.ToPtr(),
			PublicIPAddress: &armnetwork.PublicIPAddress{
				ID: to.StringPtr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/publicIPAddresses/%s",
					nd.Config.SubscriptionID, nd.Config.ResourceGroupName, nd.Config.PublicIPAddressName)),
			},
		},
	}

	params := armnetwork.Interface{
		Location: &nd.Config.Location,
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{&ipConfig},
		},
		Tags: map[string]*string{
			nd.Config.TagKey: &nd.Config.TagValue,
		},
	}
	_, err := nd.Network.Interfaces.CreateOrUpdate(ctx, nd.Config.ResourceGroupName, nd.Config.InterfaceName, params, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create network interface")
	}
	return nil
}

// CreateVirtualMachine creates a virtual machine.
func (nd *NodeDeployment) CreateVirtualMachine() error {
	ctx := context.Background()
	params := armcompute.VirtualMachine{
		Location: &nd.Config.Location,
		Properties: &armcompute.VirtualMachineProperties{
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: armcompute.VirtualMachineSizeTypes(nd.Config.VMSize).ToPtr(),
			},
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					Publisher: &nd.Config.ImagePublisher,
					Offer:     &nd.Config.ImageOffer,
					SKU:       &nd.Config.ImageSKU,
					Version:   &nd.Config.ImageVersion,
				},
			},
			OsProfile: &armcompute.OSProfile{
				ComputerName:  &nd.Config.VMName,
				AdminUsername: &nd.Config.AdminUsername,
				AdminPassword: &nd.Config.AdminPassword,
			},
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{
						ID: to.StringPtr(fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkInterfaces/%s",
							nd.Config.SubscriptionID, nd.Config.ResourceGroupName, nd.Config.InterfaceName)),
					},
				},
			},
		},
		Tags: map[string]*string{
			nd.Config.TagKey: &nd.Config.TagValue,
		},
	}

	_, err := nd.Compute.VirtualMachines.CreateOrUpdate(ctx, nd.Config.ResourceGroupName, nd.Config.VMName, params, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create virtual machine")
	}
	return nil
}

// DeployNode orchestrates the entire node deployment process.
func (nd *NodeDeployment) DeployNode() error {
	if err := nd.CreateResourceGroup(); err != nil {
		return err
	}
	if err := nd.CreateVirtualNetwork(); err != nil {
		return err
	}
	if err := nd.CreateSubnet(); err != nil {
		return err
	}
	if err := nd.CreatePublicIPAddress(); err != nil {
		return err
	}
	if err := nd.CreateNetworkSecurityGroup(); err != nil {
		return err
	}
	if err := nd.CreateNetworkInterface(); err != nil {
		return err
	}
	if err := nd.CreateVirtualMachine(); err != nil {
		return err
	}

	log.Printf("Node deployed successfully with VM name %s", nd.Config.VMName)
	return nil
}

// Main function for demonstration
func main() {
	config := &AzureConfig{
		SubscriptionID:      "your-subscription-id",
		ResourceGroupName:   "BlockchainResourceGroup",
		Location:            "eastus",
		VMSize:              "Standard_B1s",
		ImagePublisher:      "Canonical",
		ImageOffer:          "UbuntuServer",
		ImageSKU:            "18.04-LTS",
		ImageVersion:        "latest",
		AdminUsername:       "azureuser",
		AdminPassword:       "P@ssw0rd1234",
		VNetName:            "BlockchainVNet",
		SubnetName:          "BlockchainSubnet",
		PublicIPAddressName: "BlockchainPublicIP",
		NSGName:             "BlockchainNSG",
		IPConfigName:        "BlockchainIPConfig",
		InterfaceName:       "BlockchainNIC",
		VMName:              "BlockchainVM",
		TagKey:              "Environment",
		TagValue:            "Production",
	}

	deployment, err := NewAzureClient(config)
	if err != nil {
		log.Fatalf("Failed to initialize Azure client: %v", err)
	}

	err = deployment.DeployNode()
	if err != nil {
		log.Fatalf("Failed to deploy node: %v", err)
	}

	log.Println("Node deployment process completed successfully.")
}
