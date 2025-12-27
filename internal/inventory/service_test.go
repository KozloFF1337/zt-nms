package inventory

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestDevice(t *testing.T) {
	now := time.Now()
	device := &Device{
		ID:           uuid.New(),
		IdentityID:   uuid.New(),
		Hostname:     "router-01",
		Vendor:       "Cisco",
		Model:        "ISR 4431",
		SerialNumber: "SN12345",
		OSType:       "IOS-XE",
		OSVersion:    "17.3.4",
		Role:         DeviceRoleCore,
		Criticality:  DeviceCriticalityCritical,
		ManagementIP: "10.0.0.1",
		Status:       DeviceStatusOnline,
		TrustStatus:  TrustStatusVerified,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	assert.NotEqual(t, uuid.Nil, device.ID)
	assert.Equal(t, "router-01", device.Hostname)
	assert.Equal(t, DeviceRoleCore, device.Role)
	assert.Equal(t, DeviceCriticalityCritical, device.Criticality)
	assert.Equal(t, DeviceStatusOnline, device.Status)
	assert.Equal(t, TrustStatusVerified, device.TrustStatus)
}

func TestDeviceRoles(t *testing.T) {
	roles := []DeviceRole{
		DeviceRoleCore,
		DeviceRoleDistribution,
		DeviceRoleAccess,
		DeviceRoleEdge,
		DeviceRoleFirewall,
		DeviceRoleLoadBalancer,
		DeviceRoleWLC,
		DeviceRoleAP,
	}

	for _, role := range roles {
		assert.NotEmpty(t, string(role))
	}
}

func TestDeviceCriticality(t *testing.T) {
	levels := []DeviceCriticality{
		DeviceCriticalityCritical,
		DeviceCriticalityHigh,
		DeviceCriticalityMedium,
		DeviceCriticalityLow,
	}

	for _, level := range levels {
		assert.NotEmpty(t, string(level))
	}
}

func TestDeviceStatus(t *testing.T) {
	statuses := []DeviceStatus{
		DeviceStatusOnline,
		DeviceStatusOffline,
		DeviceStatusQuarantined,
		DeviceStatusMaintenance,
		DeviceStatusUnknown,
	}

	for _, status := range statuses {
		assert.NotEmpty(t, string(status))
	}
}

func TestTrustStatus(t *testing.T) {
	statuses := []TrustStatus{
		TrustStatusVerified,
		TrustStatusUntrusted,
		TrustStatusPending,
		TrustStatusUnknown,
	}

	for _, status := range statuses {
		assert.NotEmpty(t, string(status))
	}
}

func TestLocation(t *testing.T) {
	now := time.Now()
	parentID := uuid.New()
	loc := &Location{
		ID:       uuid.New(),
		Name:     "DC-1",
		Type:     LocationTypeDatacenter,
		ParentID: &parentID,
		Address: map[string]string{
			"city":    "New York",
			"country": "USA",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	assert.NotEqual(t, uuid.Nil, loc.ID)
	assert.Equal(t, "DC-1", loc.Name)
	assert.Equal(t, LocationTypeDatacenter, loc.Type)
	assert.NotNil(t, loc.ParentID)
}

func TestLocationTypes(t *testing.T) {
	types := []LocationType{
		LocationTypeDatacenter,
		LocationTypeOffice,
		LocationTypePOP,
		LocationTypeBranch,
		LocationTypeRack,
	}

	for _, lt := range types {
		assert.NotEmpty(t, string(lt))
	}
}

func TestInterface(t *testing.T) {
	iface := &Interface{
		ID:          uuid.New(),
		DeviceID:    uuid.New(),
		Name:        "GigabitEthernet0/0/0",
		Type:        InterfaceTypeEthernet,
		MACAddress:  "00:1A:2B:3C:4D:5E",
		Enabled:     true,
		Description: "Uplink to core",
		Speed:       1000000000,
		MTU:         1500,
	}

	assert.NotEqual(t, uuid.Nil, iface.ID)
	assert.Equal(t, "GigabitEthernet0/0/0", iface.Name)
	assert.Equal(t, InterfaceTypeEthernet, iface.Type)
	assert.True(t, iface.Enabled)
}

func TestInterfaceTypes(t *testing.T) {
	types := []InterfaceType{
		InterfaceTypeEthernet,
		InterfaceTypeLoopback,
		InterfaceTypeVLAN,
		InterfaceTypeTunnel,
		InterfaceTypeBond,
	}

	for _, it := range types {
		assert.NotEmpty(t, string(it))
	}
}

func TestIPAddress(t *testing.T) {
	ifaceID := uuid.New()
	ip := &IPAddress{
		ID:          uuid.New(),
		Address:     "10.0.0.1/24",
		InterfaceID: &ifaceID,
		Status:      "active",
		DNSName:     "router-01.example.com",
		Description: "Management IP",
	}

	assert.NotEqual(t, uuid.Nil, ip.ID)
	assert.Equal(t, "10.0.0.1/24", ip.Address)
	assert.Equal(t, "active", ip.Status)
}

func TestDeviceFilter(t *testing.T) {
	locID := uuid.New()
	filter := DeviceFilter{
		Role:        DeviceRoleCore,
		Criticality: DeviceCriticalityHigh,
		Status:      DeviceStatusOnline,
		TrustStatus: TrustStatusVerified,
		LocationID:  &locID,
		Vendor:      "Cisco",
		Search:      "router",
	}

	assert.Equal(t, DeviceRoleCore, filter.Role)
	assert.Equal(t, "Cisco", filter.Vendor)
	assert.Equal(t, "router", filter.Search)
}

func TestDeviceStats(t *testing.T) {
	stats := &DeviceStats{
		Total:       100,
		Online:      80,
		Offline:     10,
		Quarantined: 5,
		Maintenance: 3,
		Unknown:     2,
	}

	assert.Equal(t, 100, stats.Total)
	assert.Equal(t, 80, stats.Online)
	assert.Equal(t, 10, stats.Offline)
}

func TestErrors(t *testing.T) {
	assert.Error(t, ErrDeviceNotFound)
	assert.Error(t, ErrDeviceExists)
	assert.Error(t, ErrLocationNotFound)
	assert.Error(t, ErrInterfaceNotFound)

	assert.Equal(t, "device not found", ErrDeviceNotFound.Error())
	assert.Equal(t, "device already exists", ErrDeviceExists.Error())
}
