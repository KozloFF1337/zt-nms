import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Server,
  Users,
  Shield,
  Key,
  Settings,
  FileText,
  Activity,
  ChevronLeft,
  ChevronRight,
  LogOut,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { useAuthStore } from '@/stores/auth'
import { useState } from 'react'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Devices', href: '/devices', icon: Server },
  { name: 'Identities', href: '/identities', icon: Users },
  { name: 'Policies', href: '/policies', icon: Shield },
  { name: 'Capabilities', href: '/capabilities', icon: Key },
  { name: 'Configurations', href: '/configs', icon: Settings },
  { name: 'Audit Logs', href: '/audit', icon: FileText },
  { name: 'Monitoring', href: '/monitoring', icon: Activity },
]

export function Sidebar() {
  const location = useLocation()
  const { logout, identity } = useAuthStore()
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div
      className={cn(
        'flex h-screen flex-col border-r bg-card transition-all duration-300',
        collapsed ? 'w-16' : 'w-64'
      )}
    >
      <div className="flex h-16 items-center justify-between border-b px-4">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-lg font-bold">ZT-NMS</span>
          </div>
        )}
        {collapsed && <Shield className="h-8 w-8 text-primary mx-auto" />}
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setCollapsed(!collapsed)}
          className={cn(collapsed && 'mx-auto')}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </Button>
      </div>

      <ScrollArea className="flex-1 py-4">
        <nav className="space-y-1 px-2">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href
            return (
              <Link
                key={item.name}
                to={item.href}
                className={cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                  isActive
                    ? 'bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                  collapsed && 'justify-center'
                )}
                title={collapsed ? item.name : undefined}
              >
                <item.icon className="h-5 w-5 shrink-0" />
                {!collapsed && <span>{item.name}</span>}
              </Link>
            )
          })}
        </nav>
      </ScrollArea>

      <div className="border-t p-4">
        {!collapsed && identity && (
          <div className="mb-3 truncate text-sm">
            <p className="font-medium">
              {(identity.attributes as { username?: string })?.username || 'User'}
            </p>
            <p className="text-xs text-muted-foreground">
              {(identity.attributes as { email?: string })?.email}
            </p>
          </div>
        )}
        <Button
          variant="ghost"
          className={cn('w-full justify-start gap-3', collapsed && 'justify-center px-0')}
          onClick={logout}
        >
          <LogOut className="h-5 w-5" />
          {!collapsed && <span>Logout</span>}
        </Button>
      </div>
    </div>
  )
}
