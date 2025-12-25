import {
  Server,
  Users,
  Key,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Activity,
  TrendingUp,
  TrendingDown,
} from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts'

// Mock data for dashboard
const stats = {
  devices: { total: 156, online: 148, offline: 5, quarantined: 3 },
  identities: { total: 234, operators: 45, devices: 156, services: 33, active: 220 },
  capabilities: { active: 89, pending_approval: 7, expired_today: 12 },
  policies: { total: 34, active: 28, evaluations_today: 15420, denials_today: 23 },
  deployments: { pending: 2, in_progress: 1, completed_today: 8, failed_today: 0 },
  audit: { events_today: 8934, security_events: 45, failed_auth: 12 },
}

const policyEvaluationsData = [
  { time: '00:00', allowed: 450, denied: 2 },
  { time: '04:00', allowed: 230, denied: 1 },
  { time: '08:00', allowed: 1200, denied: 5 },
  { time: '12:00', allowed: 1800, denied: 8 },
  { time: '16:00', allowed: 2100, denied: 4 },
  { time: '20:00', allowed: 980, denied: 3 },
]

const deviceStatusData = [
  { name: 'Online', value: 148, color: '#22c55e' },
  { name: 'Offline', value: 5, color: '#ef4444' },
  { name: 'Quarantined', value: 3, color: '#f59e0b' },
]

const configDeploymentsData = [
  { day: 'Mon', success: 12, failed: 0 },
  { day: 'Tue', success: 8, failed: 1 },
  { day: 'Wed', success: 15, failed: 0 },
  { day: 'Thu', success: 10, failed: 0 },
  { day: 'Fri', success: 8, failed: 0 },
  { day: 'Sat', success: 3, failed: 0 },
  { day: 'Sun', success: 2, failed: 0 },
]

const recentEvents = [
  { id: 1, type: 'security', message: 'Failed authentication attempt for user john.doe', time: '2 min ago' },
  { id: 2, type: 'config', message: 'Configuration deployed to router-edge-01', time: '15 min ago' },
  { id: 3, type: 'capability', message: 'Capability request approved for alice@company.com', time: '23 min ago' },
  { id: 4, type: 'attestation', message: 'Device switch-access-12 passed attestation', time: '45 min ago' },
  { id: 5, type: 'policy', message: 'Policy "emergency-access" activated by admin', time: '1 hour ago' },
]

function StatCard({
  title,
  value,
  description,
  icon: Icon,
  trend,
  trendValue,
}: {
  title: string
  value: string | number
  description: string
  icon: React.ElementType
  trend?: 'up' | 'down'
  trendValue?: string
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        <div className="flex items-center gap-1">
          {trend && (
            <>
              {trend === 'up' ? (
                <TrendingUp className="h-3 w-3 text-green-500" />
              ) : (
                <TrendingDown className="h-3 w-3 text-red-500" />
              )}
              <span className={trend === 'up' ? 'text-green-500' : 'text-red-500'}>{trendValue}</span>
            </>
          )}
          <p className="text-xs text-muted-foreground">{description}</p>
        </div>
      </CardContent>
    </Card>
  )
}

export function DashboardPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">Zero Trust Network Management System Overview</p>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          title="Total Devices"
          value={stats.devices.total}
          description={`${stats.devices.online} online`}
          icon={Server}
          trend="up"
          trendValue="+4"
        />
        <StatCard
          title="Active Identities"
          value={stats.identities.active}
          description={`of ${stats.identities.total} total`}
          icon={Users}
        />
        <StatCard
          title="Active Capabilities"
          value={stats.capabilities.active}
          description={`${stats.capabilities.pending_approval} pending`}
          icon={Key}
        />
        <StatCard
          title="Policy Evaluations"
          value={stats.policies.evaluations_today.toLocaleString()}
          description={`${stats.policies.denials_today} denied today`}
          icon={Shield}
        />
      </div>

      {/* Alerts Section */}
      {(stats.devices.quarantined > 0 || stats.policies.denials_today > 0) && (
        <div className="grid gap-4 md:grid-cols-2">
          {stats.devices.quarantined > 0 && (
            <Card className="border-yellow-500/50 bg-yellow-500/10">
              <CardContent className="flex items-center gap-4 pt-6">
                <AlertTriangle className="h-8 w-8 text-yellow-500" />
                <div>
                  <h3 className="font-semibold">Quarantined Devices</h3>
                  <p className="text-sm text-muted-foreground">
                    {stats.devices.quarantined} devices have failed attestation and are quarantined
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
          {stats.policies.denials_today > 0 && (
            <Card className="border-red-500/50 bg-red-500/10">
              <CardContent className="flex items-center gap-4 pt-6">
                <Shield className="h-8 w-8 text-red-500" />
                <div>
                  <h3 className="font-semibold">Access Denials</h3>
                  <p className="text-sm text-muted-foreground">
                    {stats.policies.denials_today} access requests were denied today
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Charts Row */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {/* Policy Evaluations Chart */}
        <Card className="col-span-2">
          <CardHeader>
            <CardTitle>Policy Evaluations (24h)</CardTitle>
            <CardDescription>Allowed vs denied access requests over time</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={policyEvaluationsData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="time" className="text-xs" />
                  <YAxis className="text-xs" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                    }}
                  />
                  <Line type="monotone" dataKey="allowed" stroke="#22c55e" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="denied" stroke="#ef4444" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Device Status Pie Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Device Status</CardTitle>
            <CardDescription>Current device health overview</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={deviceStatusData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {deviceStatusData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-4 flex justify-center gap-4">
              {deviceStatusData.map((entry) => (
                <div key={entry.name} className="flex items-center gap-2">
                  <div className="h-3 w-3 rounded-full" style={{ backgroundColor: entry.color }} />
                  <span className="text-sm">{entry.name}: {entry.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Deployments and Events Row */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Configuration Deployments Chart */}
        <Card>
          <CardHeader>
            <CardTitle>Configuration Deployments (7 days)</CardTitle>
            <CardDescription>Successful and failed deployments</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[250px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={configDeploymentsData}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis dataKey="day" className="text-xs" />
                  <YAxis className="text-xs" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                    }}
                  />
                  <Bar dataKey="success" fill="#22c55e" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="failed" fill="#ef4444" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Recent Events */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Events</CardTitle>
            <CardDescription>Latest system activity</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentEvents.map((event) => (
                <div key={event.id} className="flex items-start gap-3">
                  <div className="mt-0.5">
                    {event.type === 'security' && <AlertTriangle className="h-4 w-4 text-yellow-500" />}
                    {event.type === 'config' && <CheckCircle className="h-4 w-4 text-green-500" />}
                    {event.type === 'capability' && <Key className="h-4 w-4 text-blue-500" />}
                    {event.type === 'attestation' && <Shield className="h-4 w-4 text-green-500" />}
                    {event.type === 'policy' && <Activity className="h-4 w-4 text-purple-500" />}
                  </div>
                  <div className="flex-1">
                    <p className="text-sm">{event.message}</p>
                    <p className="text-xs text-muted-foreground">{event.time}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Pending Actions</CardTitle>
          <CardDescription>Items requiring your attention</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            {stats.capabilities.pending_approval > 0 && (
              <div className="flex items-center gap-3 rounded-lg border p-4">
                <Clock className="h-8 w-8 text-yellow-500" />
                <div>
                  <p className="font-medium">{stats.capabilities.pending_approval} Capability Requests</p>
                  <p className="text-sm text-muted-foreground">Awaiting approval</p>
                </div>
                <Badge variant="warning" className="ml-auto">Review</Badge>
              </div>
            )}
            {stats.deployments.pending > 0 && (
              <div className="flex items-center gap-3 rounded-lg border p-4">
                <Server className="h-8 w-8 text-blue-500" />
                <div>
                  <p className="font-medium">{stats.deployments.pending} Deployments</p>
                  <p className="text-sm text-muted-foreground">Ready to deploy</p>
                </div>
                <Badge variant="default" className="ml-auto">Deploy</Badge>
              </div>
            )}
            {stats.devices.offline > 0 && (
              <div className="flex items-center gap-3 rounded-lg border p-4">
                <AlertTriangle className="h-8 w-8 text-red-500" />
                <div>
                  <p className="font-medium">{stats.devices.offline} Devices Offline</p>
                  <p className="text-sm text-muted-foreground">Require investigation</p>
                </div>
                <Badge variant="destructive" className="ml-auto">Check</Badge>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
