import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Server,
  Plus,
  Search,
  Filter,
  MoreHorizontal,
  Wifi,
  WifiOff,
  Shield,
  AlertTriangle,
  Eye,
  Settings,
  Trash2,
  RefreshCw,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { devicesApi } from '@/api/client'
import type { Device, DeviceTrustStatus } from '@/types/api'
import { formatRelativeTime } from '@/lib/utils'

// Mock data for development
const mockDevices: Device[] = [
  {
    id: '1',
    hostname: 'router-core-01',
    vendor: 'Cisco',
    model: 'ASR1001-X',
    serial_number: 'FXS12345678',
    os_type: 'IOS-XE',
    os_version: '17.3.4',
    role: 'core-router',
    criticality: 'critical',
    location_id: 'dc1',
    location_name: 'DC1 - Rack A01',
    management_ip: '10.0.0.1',
    last_seen: new Date().toISOString(),
    trust_status: 'verified',
    current_config_sequence: 1547,
    current_config_hash: 'abc123...',
    supported_protocols: ['ssh', 'netconf', 'restconf'],
  },
  {
    id: '2',
    hostname: 'switch-access-01',
    vendor: 'Juniper',
    model: 'EX4300-48T',
    serial_number: 'PE12345678',
    os_type: 'Junos',
    os_version: '21.4R3',
    role: 'access-switch',
    criticality: 'high',
    location_id: 'dc1',
    location_name: 'DC1 - Rack B05',
    management_ip: '10.0.1.10',
    last_seen: new Date(Date.now() - 300000).toISOString(),
    trust_status: 'verified',
    current_config_sequence: 234,
    current_config_hash: 'def456...',
    supported_protocols: ['ssh', 'netconf'],
  },
  {
    id: '3',
    hostname: 'firewall-edge-01',
    vendor: 'Palo Alto',
    model: 'PA-5220',
    serial_number: 'PA12345678',
    os_type: 'PAN-OS',
    os_version: '10.2.3',
    role: 'edge-firewall',
    criticality: 'critical',
    location_id: 'dc1',
    location_name: 'DC1 - Rack A02',
    management_ip: '10.0.0.10',
    last_seen: new Date(Date.now() - 86400000).toISOString(),
    trust_status: 'unknown',
    current_config_sequence: 89,
    current_config_hash: 'ghi789...',
    supported_protocols: ['ssh', 'restconf'],
  },
  {
    id: '4',
    hostname: 'router-edge-02',
    vendor: 'Cisco',
    model: 'ISR4451-X',
    serial_number: 'FXS87654321',
    os_type: 'IOS-XE',
    os_version: '17.6.1',
    role: 'edge-router',
    criticality: 'high',
    location_id: 'dc2',
    location_name: 'DC2 - Rack C01',
    management_ip: '10.1.0.1',
    last_seen: new Date().toISOString(),
    trust_status: 'compromised',
    current_config_sequence: 456,
    current_config_hash: 'jkl012...',
    supported_protocols: ['ssh', 'netconf', 'snmpv3'],
  },
]

function TrustStatusBadge({ status }: { status: DeviceTrustStatus }) {
  const variants: Record<DeviceTrustStatus, { variant: 'success' | 'destructive' | 'warning' | 'secondary'; icon: React.ReactNode }> = {
    verified: { variant: 'success', icon: <Shield className="mr-1 h-3 w-3" /> },
    compromised: { variant: 'destructive', icon: <AlertTriangle className="mr-1 h-3 w-3" /> },
    quarantined: { variant: 'warning', icon: <AlertTriangle className="mr-1 h-3 w-3" /> },
    unknown: { variant: 'secondary', icon: null },
  }

  const { variant, icon } = variants[status]

  return (
    <Badge variant={variant} className="capitalize">
      {icon}
      {status}
    </Badge>
  )
}

function OnlineStatus({ lastSeen }: { lastSeen: string }) {
  const now = new Date()
  const seen = new Date(lastSeen)
  const diff = now.getTime() - seen.getTime()
  const isOnline = diff < 5 * 60 * 1000 // 5 minutes

  return (
    <div className="flex items-center gap-2">
      {isOnline ? (
        <>
          <Wifi className="h-4 w-4 text-green-500" />
          <span className="text-green-500">Online</span>
        </>
      ) : (
        <>
          <WifiOff className="h-4 w-4 text-muted-foreground" />
          <span className="text-muted-foreground">{formatRelativeTime(lastSeen)}</span>
        </>
      )}
    </div>
  )
}

export function DevicesPage() {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false)

  // Use mock data for now
  const devices = mockDevices

  const filteredDevices = devices.filter((device) => {
    const matchesSearch =
      device.hostname.toLowerCase().includes(search.toLowerCase()) ||
      device.management_ip.includes(search) ||
      device.vendor.toLowerCase().includes(search.toLowerCase())
    const matchesRole = roleFilter === 'all' || device.role === roleFilter
    const matchesStatus = statusFilter === 'all' || device.trust_status === statusFilter
    return matchesSearch && matchesRole && matchesStatus
  })

  const roles = [...new Set(devices.map((d) => d.role))]
  const statuses: DeviceTrustStatus[] = ['verified', 'unknown', 'compromised', 'quarantined']

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Devices</h1>
          <p className="text-muted-foreground">Manage network devices in your infrastructure</p>
        </div>
        <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Add Device
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Add New Device</DialogTitle>
              <DialogDescription>Register a new network device in the ZT-NMS system</DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="hostname">Hostname</Label>
                  <Input id="hostname" placeholder="router-core-01" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="management-ip">Management IP</Label>
                  <Input id="management-ip" placeholder="10.0.0.1" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="vendor">Vendor</Label>
                  <Select>
                    <SelectTrigger>
                      <SelectValue placeholder="Select vendor" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="cisco">Cisco</SelectItem>
                      <SelectItem value="juniper">Juniper</SelectItem>
                      <SelectItem value="arista">Arista</SelectItem>
                      <SelectItem value="paloalto">Palo Alto</SelectItem>
                      <SelectItem value="fortinet">Fortinet</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="model">Model</Label>
                  <Input id="model" placeholder="ASR1001-X" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="role">Role</Label>
                  <Select>
                    <SelectTrigger>
                      <SelectValue placeholder="Select role" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="core-router">Core Router</SelectItem>
                      <SelectItem value="edge-router">Edge Router</SelectItem>
                      <SelectItem value="access-switch">Access Switch</SelectItem>
                      <SelectItem value="distribution-switch">Distribution Switch</SelectItem>
                      <SelectItem value="edge-firewall">Edge Firewall</SelectItem>
                      <SelectItem value="load-balancer">Load Balancer</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="criticality">Criticality</Label>
                  <Select>
                    <SelectTrigger>
                      <SelectValue placeholder="Select criticality" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="low">Low</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsAddDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={() => setIsAddDialogOpen(false)}>Add Device</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-wrap gap-4">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search devices..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10"
              />
            </div>
            <Select value={roleFilter} onValueChange={setRoleFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by role" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Roles</SelectItem>
                {roles.map((role) => (
                  <SelectItem key={role} value={role}>
                    {role.replace('-', ' ')}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Filter by status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Statuses</SelectItem>
                {statuses.map((status) => (
                  <SelectItem key={status} value={status} className="capitalize">
                    {status}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="outline" size="icon">
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Devices Table */}
      <Card>
        <CardHeader>
          <CardTitle>Managed Devices</CardTitle>
          <CardDescription>
            {filteredDevices.length} of {devices.length} devices
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Hostname</TableHead>
                <TableHead>Vendor / Model</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Management IP</TableHead>
                <TableHead>Trust Status</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Config Version</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredDevices.map((device) => (
                <TableRow key={device.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Server className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{device.hostname}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div>
                      <p className="font-medium">{device.vendor}</p>
                      <p className="text-xs text-muted-foreground">{device.model}</p>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="capitalize">
                      {device.role.replace('-', ' ')}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm">{device.management_ip}</TableCell>
                  <TableCell>
                    <TrustStatusBadge status={device.trust_status} />
                  </TableCell>
                  <TableCell>
                    <OnlineStatus lastSeen={device.last_seen} />
                  </TableCell>
                  <TableCell className="font-mono text-sm">v{device.current_config_sequence}</TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onClick={() => setSelectedDevice(device)}>
                          <Eye className="mr-2 h-4 w-4" />
                          View Details
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Settings className="mr-2 h-4 w-4" />
                          Configure
                        </DropdownMenuItem>
                        <DropdownMenuItem>
                          <Shield className="mr-2 h-4 w-4" />
                          Request Attestation
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-destructive">
                          <Trash2 className="mr-2 h-4 w-4" />
                          Remove Device
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Device Details Dialog */}
      <Dialog open={!!selectedDevice} onOpenChange={() => setSelectedDevice(null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              {selectedDevice?.hostname}
            </DialogTitle>
            <DialogDescription>Device details and configuration</DialogDescription>
          </DialogHeader>
          {selectedDevice && (
            <Tabs defaultValue="details">
              <TabsList>
                <TabsTrigger value="details">Details</TabsTrigger>
                <TabsTrigger value="config">Configuration</TabsTrigger>
                <TabsTrigger value="attestation">Attestation</TabsTrigger>
                <TabsTrigger value="history">History</TabsTrigger>
              </TabsList>
              <TabsContent value="details" className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-muted-foreground">Hostname</Label>
                    <p className="font-medium">{selectedDevice.hostname}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Management IP</Label>
                    <p className="font-mono">{selectedDevice.management_ip}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Vendor</Label>
                    <p>{selectedDevice.vendor}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Model</Label>
                    <p>{selectedDevice.model}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Serial Number</Label>
                    <p className="font-mono">{selectedDevice.serial_number}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">OS Version</Label>
                    <p>{selectedDevice.os_type} {selectedDevice.os_version}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Role</Label>
                    <p className="capitalize">{selectedDevice.role.replace('-', ' ')}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Criticality</Label>
                    <Badge variant={selectedDevice.criticality === 'critical' ? 'destructive' : 'secondary'}>
                      {selectedDevice.criticality}
                    </Badge>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Location</Label>
                    <p>{selectedDevice.location_name}</p>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Trust Status</Label>
                    <TrustStatusBadge status={selectedDevice.trust_status} />
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Supported Protocols</Label>
                    <div className="flex gap-1">
                      {selectedDevice.supported_protocols.map((proto) => (
                        <Badge key={proto} variant="outline">{proto}</Badge>
                      ))}
                    </div>
                  </div>
                  <div>
                    <Label className="text-muted-foreground">Config Version</Label>
                    <p className="font-mono">v{selectedDevice.current_config_sequence}</p>
                  </div>
                </div>
              </TabsContent>
              <TabsContent value="config">
                <div className="rounded-lg bg-muted p-4">
                  <pre className="text-sm">
                    {`! Configuration for ${selectedDevice.hostname}
! Last updated: ${new Date().toISOString()}
!
hostname ${selectedDevice.hostname}
!
interface GigabitEthernet0/0
  ip address ${selectedDevice.management_ip} 255.255.255.0
  no shutdown
!
`}
                  </pre>
                </div>
              </TabsContent>
              <TabsContent value="attestation">
                <div className="space-y-4">
                  <div className="flex items-center justify-between rounded-lg border p-4">
                    <div>
                      <p className="font-medium">Last Attestation</p>
                      <p className="text-sm text-muted-foreground">
                        {formatRelativeTime(selectedDevice.last_seen)}
                      </p>
                    </div>
                    <TrustStatusBadge status={selectedDevice.trust_status} />
                  </div>
                  <Button>
                    <RefreshCw className="mr-2 h-4 w-4" />
                    Request New Attestation
                  </Button>
                </div>
              </TabsContent>
              <TabsContent value="history">
                <p className="text-muted-foreground">Configuration history will be displayed here...</p>
              </TabsContent>
            </Tabs>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
