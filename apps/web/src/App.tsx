import { useEffect, useState, type ReactNode } from "react";
import {
  NavLink,
  Routes,
  Route,
  Navigate,
  useNavigate,
  useParams,
  Link,
} from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  Activity,
  ArrowDownToLine,
  ArrowUpRight,
  Bell,
  Check,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Clipboard,
  Eye,
  FileText,
  LayoutDashboard,
  LogOut,
  Menu,
  Monitor,
  Plus,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  Terminal,
  Wifi,
  X,
  BarChart3,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Users,
  Loader2,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { api, setSession, ApiError, download } from "./lib/api";
import { Button } from "./components/ui/button";
type Org = { id: string; name: string; role: string; demo: boolean };
type Session = {
  user: { id: string; name: string; email: string };
  csrf: string;
  organizations: Org[];
  currentOrganizationId: string;
};
type Device = {
  id: string;
  hostname: string;
  osVersion: string;
  agentVersion: string;
  active: boolean;
  lastHeartbeat: string | null;
  lastEvent: string | null;
  healthError: string | null;
  tags: string[];
  eventIds: number[];
  simulated: boolean;
};
type Event = {
  id: string;
  windowsEventId: number;
  timestamp: string;
  receivedAt: string;
  deviceId: string;
  device?: { hostname: string };
  category: string;
  username: string | null;
  sourceIp: string | null;
  processName: string | null;
  simulated: boolean;
  metadata: Record<string, unknown>;
};
type Alert = {
  id: string;
  name: string;
  severity: string;
  ruleId: string;
  explanation: string;
  status: string;
  detectedAt: string;
  device?: { hostname: string };
  simulated: boolean;
  eventIds: string[];
  events?: Event[];
  techniques: string[];
};
type Incident = {
  id: string;
  title: string;
  severity: string;
  status: string;
  description: string;
  updatedAt: string;
  assignedTo: string | null;
  resolutionNotes: string | null;
  events?: { event: Event }[];
  comments?: {
    id: string;
    body: string;
    authorId: string;
    createdAt: string;
  }[];
  investigations?: { id: string; provider: string; result: Investigation }[];
  actions?: { id: string; kind: string; recommendation: string }[];
};
type Investigation = {
  provider: string;
  summary: string;
  facts: { text: string; evidenceIds: string[] }[];
  hypotheses: string[];
  nextSteps: string[];
  limitations: string[];
};
type Page<T> = { items: T[]; total: number; page: number; limit: number };
type Trend = { hour: string; events: number; failures: number };
type Overview = {
  totalDevices: number;
  onlineDevices: number;
  offlineDevices: number;
  eventsToday: number;
  activeAlerts: number;
  criticalIncidents: number;
  resolvedIncidents: number;
  healthIssues: number;
  recentAlerts: Alert[];
  recentIncidents: Incident[];
  severities: { severity: string; _count: number }[];
};
const nav = [
  ["/", "Overview", LayoutDashboard],
  ["/devices", "Devices", Monitor],
  ["/events", "Live Events", Activity],
  ["/threats", "Threat Detection", ShieldAlert],
  ["/incidents", "Incidents", Clipboard],
  ["/investigator", "AI Investigator", Sparkles],
  ["/analytics", "Analytics", BarChart3],
  ["/reports", "Reports", FileText],
  ["/rules", "Detection Rules", SlidersHorizontal],
  ["/downloads", "Agent Downloads", ArrowDownToLine],
  ["/notifications", "Notifications", Bell],
  ["/settings", "Settings", Settings],
] as const;
const time = (s: string | null | undefined) =>
  s ? new Date(s).toLocaleString() : "No data";
const online = (d: Device) =>
  d.active &&
  !!d.lastHeartbeat &&
  Date.now() - Date.parse(d.lastHeartbeat) < 120000;
export function Badge({ value }: { value: string }) {
  return (
    <span className={"badge " + value.toLowerCase()}>
      {value.replaceAll("_", " ")}
    </span>
  );
}
function Empty({
  icon: Icon = Shield,
  title,
  body,
  action,
}: {
  icon?: typeof Shield;
  title: string;
  body: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon size={25} />
      </div>
      <h3>{title}</h3>
      <p>{body}</p>
      {action}
    </div>
  );
}
function ErrorNote({ error }: { error: Error | null | undefined }) {
  return error ? (
    <div className="error" role="alert">
      <AlertTriangle size={16} />
      {error.message}
    </div>
  ) : null;
}
function Loading() {
  return (
    <div className="loading">
      <Loader2 className="spin" size={20} />
      Loading security data…
    </div>
  );
}
function Header({
  eyebrow = "SECURITY OPERATIONS",
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
function Pager({
  page,
  total,
  onPage,
}: {
  page: number;
  total: number;
  onPage: (n: number) => void;
}) {
  return (
    <div className="pager">
      <span>
        {total} records · Page {page} of {Math.max(1, Math.ceil(total / 25))}
      </span>
      <div>
        <Button
          variant="secondary"
          size="sm"
          aria-label="Previous page"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
        >
          <ChevronLeft size={15} />
        </Button>
        <Button
          variant="secondary"
          size="sm"
          aria-label="Next page"
          disabled={page * 25 >= total}
          onClick={() => onPage(page + 1)}
        >
          <ChevronRight size={15} />
        </Button>
      </div>
    </div>
  );
}
function useData<T>(path: string) {
  return useQuery<T, Error>({ queryKey: [path], queryFn: () => api<T>(path) });
}
function useAction<T = unknown>(path: string, method = "POST") {
  const client = useQueryClient();
  return useMutation<T, Error, unknown>({
    mutationFn: (body) => api<T>(path, method, body),
    onSuccess: () => client.invalidateQueries(),
  });
}
export const authSchema = z.object({
  email: z.string().email("Enter a valid email address"),
  password: z.string().min(12, "Use at least 12 characters"),
  name: z.string().optional(),
  organization: z.string().optional(),
  demo: z.boolean().optional(),
});
export function Auth() {
  const [register, setRegister] = useState(false);
  const client = useQueryClient();
  const navigate = useNavigate();
  const form = useForm<z.infer<typeof authSchema>>({
    resolver: zodResolver(authSchema),
    defaultValues: { demo: false },
  });
  const action = useMutation({
    mutationFn: (v: z.infer<typeof authSchema>) =>
      api<{ csrf: string }>(
        "/auth/" + (register ? "register" : "login"),
        "POST",
        register ? v : { email: v.email, password: v.password },
      ),
    onSuccess: async () => {
      setSession("", "");
      client.removeQueries({ predicate: (q) => q.queryKey[0] !== "/auth/me" });
      await client.invalidateQueries();
      navigate("/");
    },
  });
  return (
    <div className="auth">
      <div className="auth-intro">
        <Brand />
        <div>
          <div className="eyebrow">VISIBILITY IS YOUR FIRST DEFENSE</div>
          <h1>
            Your endpoints.
            <br />
            Your evidence.
            <br />
            <span>Your control.</span>
          </h1>
          <p>
            Security operations for the Windows systems you administer. Turn
            event logs into evidence you can investigate.
          </p>
          <div className="auth-features">
            <span>
              <Eye size={18} /> Real endpoint telemetry
            </span>
            <span>
              <Shield size={18} /> Evidence-backed detections
            </span>
            <span>
              <Users size={18} /> Isolated organizations
            </span>
          </div>
        </div>
        <small>ZEROEYE · Detect. Investigate. Defend.</small>
      </div>
      <div className="auth-panel">
        <div className="auth-form">
          <div className="eyebrow">ZEROEYE CONSOLE</div>
          <h2>{register ? "Create your workspace" : "Welcome back"}</h2>
          <p>
            {register
              ? "Start with an empty organization and enroll your first device."
              : "Sign in to your security operations workspace."}
          </p>
          <form onSubmit={form.handleSubmit((v) => action.mutate(v))}>
            {register && (
              <>
                <label>
                  Your name
                  <input
                    autoComplete="name"
                    required
                    {...form.register("name")}
                  />
                </label>
                <label>
                  Organization
                  <input required {...form.register("organization")} />
                </label>
              </>
            )}
            <label>
              Email address
              <input
                autoComplete="email"
                type="email"
                {...form.register("email")}
              />
            </label>
            <label>
              Password
              <input
                autoComplete={register ? "new-password" : "current-password"}
                type="password"
                {...form.register("password")}
              />
            </label>
            {Object.entries(form.formState.errors).map(([key, e]) => (
              <div key={key} className="field-error">
                {e.message}
              </div>
            ))}
            {register && (
              <label className="checkbox">
                <input type="checkbox" {...form.register("demo")} /> Create an
                isolated demo organization for synthetic events
              </label>
            )}
            <ErrorNote error={action.error} />
            <Button disabled={action.isPending} type="submit">
              {action.isPending ? <Loader2 size={16} className="spin" /> : null}
              {register ? "Create workspace" : "Sign in"}
              <ArrowUpRight size={16} />
            </Button>
          </form>
          <button
            className="text-button"
            onClick={() => {
              setRegister(!register);
              action.reset();
              form.clearErrors();
            }}
          >
            {register
              ? "Already have an account? Sign in"
              : "New to ZEROEYE? Create a workspace"}
          </button>
          <div className="auth-foot">
            Monitor only systems you own or are authorized to administer.
          </div>
        </div>
      </div>
    </div>
  );
}
function Brand() {
  return (
    <div className="brand">
      <div className="brand-mark">
        <Eye size={21} />
      </div>
      <span>
        ZERO<span className="brand-light">EYE</span>
        <small>SECURITY OPERATIONS</small>
      </span>
    </div>
  );
}
export function App() {
  const me = useData<Session>("/auth/me");
  if (me.isPending) return <Loading />;
  if (me.error) {
    if (me.error instanceof ApiError && me.error.status === 401)
      return (
        <Routes>
          <Route path="/login" element={<Auth />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      );
    return (
      <div className="fatal">
        <ErrorNote error={me.error} />
        <Button onClick={() => me.refetch()}>Retry connection</Button>
      </div>
    );
  }
  return <Console session={me.data!} />;
}
function Console({ session }: { session: Session }) {
  const [orgId, setOrgId] = useState(session.currentOrganizationId);
  const [collapsed, setCollapsed] = useState(false);
  const [mobile, setMobile] = useState(false);
  const [connected, setConnected] = useState(false);
  const [search, setSearch] = useState("");
  const client = useQueryClient();
  const navigate = useNavigate();
  const org =
    session.organizations.find((o) => o.id === orgId) ??
    session.organizations[0]!;
  setSession(session.csrf, orgId);
  useEffect(() => {
    let disposed = false;
    let socket: WebSocket;
    let timer: ReturnType<typeof setTimeout>;
    const connect = () => {
      socket = new WebSocket(
        (location.protocol === "https:" ? "wss://" : "ws://") +
          location.host +
          "/api/live?orgId=" +
          encodeURIComponent(orgId),
      );
      socket.onopen = () => setConnected(true);
      socket.onmessage = () => client.invalidateQueries();
      socket.onclose = () => {
        setConnected(false);
        if (!disposed) timer = setTimeout(connect, 5000);
      };
    };
    connect();
    return () => {
      disposed = true;
      clearTimeout(timer);
      socket?.close();
    };
  }, [orgId, client]);
  const logout = useMutation({
    mutationFn: () => api("/auth/logout", "POST", {}),
    onSuccess: () => {
      setSession("", "");
      client.clear();
      location.assign("/login");
    },
  });
  const notifications =
    useData<{ id: string; reads: unknown[] }[]>("/notifications");
  const unread = notifications.data?.filter((n) => !n.reads.length).length ?? 0;
  return (
    <div
      className={
        "console " +
        (collapsed ? "collapsed " : "") +
        (mobile ? "mobile-open" : "")
      }
    >
      <aside>
        <Brand />
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {nav.map(([path, label, Icon]) => (
            <NavLink
              key={path}
              to={path}
              end={path === "/"}
              title={collapsed ? label : undefined}
              onClick={() => setMobile(false)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {path === "/notifications" && unread > 0 && <b>{unread}</b>}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="version">
            <span className="status-dot" />
            ZEROEYE 0.1.0<small>Local development</small>
          </div>
          <Button
            variant="ghost"
            onClick={() => setCollapsed(!collapsed)}
            aria-label="Toggle sidebar"
          >
            {collapsed ? (
              <ChevronsRight size={17} />
            ) : (
              <>
                <ChevronsLeft size={17} />
                <span>Collapse navigation</span>
              </>
            )}
          </Button>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <button
            className="mobile-toggle"
            aria-label="Open navigation"
            onClick={() => setMobile(!mobile)}
          >
            <Menu size={20} />
          </button>
          <div className="org-selector">
            <span className="org-icon">
              <Shield size={17} />
            </span>
            <select
              aria-label="Organization"
              value={orgId}
              onChange={(e) => {
                const next = e.target.value;
                setSession(session.csrf, next);
                setOrgId(next);
                client.removeQueries({
                  predicate: (q) => q.queryKey[0] !== "/auth/me",
                });
                navigate("/");
              }}
            >
              {session.organizations.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
            <Badge value={org.demo ? "DEMO" : "LIVE"} />
          </div>
          <form
            className="global-search"
            onSubmit={(e) => {
              e.preventDefault();
              navigate("/events?q=" + encodeURIComponent(search));
            }}
          >
            <Search size={16} />
            <input
              aria-label="Search security events"
              placeholder="Search events, accounts, processes…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <kbd>↵</kbd>
          </form>
          <div className="topbar-actions">
            <span className={"connection " + (connected ? "connected" : "")}>
              <span className="status-dot" />
              {connected ? "Live connection" : "Polling every 30s"}
            </span>
            <Link
              to="/notifications"
              className="notification-bell"
              aria-label="Notifications"
            >
              <Bell size={18} />
              {unread > 0 && <i />}
            </Link>
            <div className="profile" title={session.user.email}>
              <div className="avatar">
                {session.user.name.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <strong>{session.user.name}</strong>
                <small>{org.role.toLowerCase()}</small>
              </div>
            </div>
            <button
              className="icon-button"
              aria-label="Sign out"
              onClick={() => logout.mutate(undefined)}
            >
              <LogOut size={17} />
            </button>
          </div>
        </header>
        {org.demo && (
          <div className="demo-banner">
            <AlertTriangle size={15} /> DEMO ORGANIZATION · All enrolled
            devices, events and detections in this workspace are simulated.
          </div>
        )}
        <main>
          <ErrorNote error={logout.error} />
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route
              path="/devices"
              element={
                <DevicesPage canAdmin={["OWNER", "ADMIN"].includes(org.role)} />
              }
            />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/threats" element={<ThreatsPage />} />
            <Route path="/incidents" element={<IncidentsPage />} />
            <Route path="/incidents/:id" element={<IncidentPage />} />
            <Route path="/investigator" element={<InvestigatorPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route
              path="/rules"
              element={
                <RulesPage canAdmin={["OWNER", "ADMIN"].includes(org.role)} />
              }
            />
            <Route path="/downloads" element={<DownloadsPage />} />
            <Route path="/notifications" element={<NotificationsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
          <footer>
            ZEROEYE <span>Detect. Investigate. Defend.</span>
            <span>Metrics from stored telemetry · UTC reporting day</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
function TrendChart({ data }: { data: Trend[] }) {
  return (
    <div className="chart">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{ top: 12, right: 15, left: -20, bottom: 0 }}
        >
          <defs>
            <linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#94a3b8" stopOpacity={0.25} />
              <stop offset="100%" stopColor="#94a3b8" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid
            stroke="#252b37"
            vertical={false}
            strokeDasharray="3 3"
          />
          <XAxis
            dataKey="hour"
            tickFormatter={(s) =>
              new Date(s).toLocaleTimeString([], { hour: "2-digit" })
            }
            stroke="#69788c"
            fontSize={11}
            minTickGap={40}
          />
          <YAxis stroke="#69788c" fontSize={11} allowDecimals={false} />
          <Tooltip
            labelFormatter={(s) => time(String(s))}
            contentStyle={{
              background: "#141821",
              border: "1px solid #334155",
              borderRadius: 8,
            }}
          />
          <Area
            name="Events"
            dataKey="events"
            type="monotone"
            stroke="#94a3b8"
            strokeWidth={2}
            fill="url(#eventFill)"
          />
          <Area
            name="Failed logons"
            dataKey="failures"
            type="monotone"
            stroke="#ef4444"
            strokeWidth={2}
            fill="transparent"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
export function OverviewPage() {
  const q = useData<Overview>("/dashboard/overview");
  const t = useData<Trend[]>("/dashboard/trends");
  const devices = useData<Device[]>("/devices");
  const d = q.data;
  return (
    <>
      <Header
        title="Security overview"
        description="A clear view of your endpoints, activity, and active investigations."
        action={
          <Button asChild variant="secondary">
            <Link to="/devices">
              <Plus size={16} />
              Enroll a device
            </Link>
          </Button>
        }
      />
      <ErrorNote error={q.error ?? t.error ?? devices.error} />
      {q.isPending ? (
        <Loading />
      ) : (
        d && (
          <>
            <div className="overview-strip">
              <div>
                <span
                  className={
                    "status-dot " +
                    (d.healthIssues || d.offlineDevices ? "amber" : "")
                  }
                />
                <strong>
                  {d.totalDevices === 0
                    ? "Awaiting your first endpoint"
                    : d.healthIssues
                      ? "Agent health needs attention"
                      : d.offlineDevices
                        ? "Some endpoints are offline"
                        : "Endpoints are reporting"}
                </strong>
              </div>
              <span>
                <Clock size={13} /> Updated{" "}
                {new Date(q.dataUpdatedAt).toLocaleTimeString()}
              </span>
            </div>
            <div className="kpi-grid">
              {[
                {
                  label: "Monitored devices",
                  value: d.totalDevices,
                  Icon: Monitor,
                  sub:
                    d.onlineDevices +
                    " online · " +
                    d.offlineDevices +
                    " offline",
                },
                {
                  label: "Events today",
                  value: d.eventsToday,
                  Icon: Activity,
                  sub: "Received since 00:00 UTC",
                },
                {
                  label: "Active alerts",
                  value: d.activeAlerts,
                  Icon: ShieldAlert,
                  sub: "Open detections to review",
                  alert: true,
                },
                {
                  label: "Critical incidents",
                  value: d.criticalIncidents,
                  Icon: AlertTriangle,
                  sub: "Unresolved critical investigations",
                  alert: true,
                },
              ].map((k) => (
                <div className="kpi" key={k.label}>
                  <div>
                    <span>{k.label}</span>
                    <k.Icon size={18} />
                  </div>
                  <strong className={k.alert && k.value > 0 ? "red" : ""}>
                    {k.value.toLocaleString()}
                  </strong>
                  <small>{k.sub}</small>
                </div>
              ))}
            </div>
            <div className="dashboard-grid">
              <section className="panel chart-panel">
                <div className="panel-heading">
                  <div>
                    <h2>Security activity</h2>
                    <p>Events received across your endpoints</p>
                  </div>
                  <span className="chip">Last 24 hours</span>
                </div>
                {t.isPending ? <Loading /> : <TrendChart data={t.data ?? []} />}
                <div className="chart-legend">
                  <span>
                    <i />
                    Security events
                  </span>
                  <span>
                    <i className="red-bg" />
                    Failed logons
                  </span>
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Alert distribution</h2>
                    <p>Open alerts by severity</p>
                  </div>
                  <ShieldAlert size={18} />
                </div>
                <div className="severity-bars">
                  {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => {
                    const n =
                      d.severities.find((v) => v.severity === s)?._count ?? 0;
                    return (
                      <div key={s}>
                        <div>
                          <Badge value={s} />
                          <strong>{n}</strong>
                        </div>
                        <div className="bar">
                          <span
                            className={s.toLowerCase()}
                            style={{
                              width:
                                (d.activeAlerts
                                  ? (n / d.activeAlerts) * 100
                                  : 0) + "%",
                            }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div className="panel-foot">
                  {d.activeAlerts} alerts awaiting review
                  <Link to="/threats">
                    View alerts <ArrowUpRight size={14} />
                  </Link>
                </div>
              </section>
            </div>
            <div className="dashboard-grid">
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Recent detections</h2>
                    <p>Evidence from your event pipeline</p>
                  </div>
                  <Link to="/threats" className="quiet-link">
                    View all <ArrowUpRight size={14} />
                  </Link>
                </div>
                {d.recentAlerts.length ? (
                  <div className="list">
                    {d.recentAlerts.map((a) => (
                      <Link key={a.id} to="/threats" className="list-row">
                        <div
                          className={"list-symbol " + a.severity.toLowerCase()}
                        >
                          <ShieldAlert size={17} />
                        </div>
                        <div>
                          <strong>{a.name}</strong>
                          <small>
                            {a.device?.hostname} · {time(a.detectedAt)}
                          </small>
                        </div>
                        <Badge value={a.severity} />
                      </Link>
                    ))}
                  </div>
                ) : (
                  <Empty
                    title="No detections to review"
                    body="Alerts will appear when collected events match an enabled detection rule."
                  />
                )}
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Endpoint health</h2>
                    <p>Agent connectivity and diagnostics</p>
                  </div>
                  <Link className="quiet-link" to="/devices">
                    Manage <ArrowUpRight size={14} />
                  </Link>
                </div>
                {devices.data?.length ? (
                  <div className="list">
                    {devices.data.slice(0, 5).map((device) => (
                      <div key={device.id} className="list-row">
                        <div className="list-symbol">
                          <Monitor size={17} />
                        </div>
                        <div>
                          <strong>{device.hostname}</strong>
                          <small>
                            {device.healthError ??
                              "Agent " + device.agentVersion}
                          </small>
                        </div>
                        <Badge
                          value={
                            device.active
                              ? online(device)
                                ? "ONLINE"
                                : "OFFLINE"
                              : "REVOKED"
                          }
                        />
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty
                    icon={Monitor}
                    title="Connect your first endpoint"
                    body="Enroll a Windows device to start collecting authorized Security event logs."
                    action={
                      <Button asChild variant="secondary" size="sm">
                        <Link to="/devices">
                          <Plus size={14} />
                          Enroll device
                        </Link>
                      </Button>
                    }
                  />
                )}
              </section>
            </div>
            <div className="summary-grid">
              <div>
                <CheckCircle2 size={17} />
                <span>Resolved incidents</span>
                <strong>{d.resolvedIncidents}</strong>
              </div>
              <div>
                <Wifi size={17} />
                <span>Online devices</span>
                <strong>{d.onlineDevices}</strong>
              </div>
              <div>
                <AlertTriangle size={17} />
                <span>Agent health issues</span>
                <strong>{d.healthIssues}</strong>
              </div>
            </div>
          </>
        )
      )}
    </>
  );
}
function DevicesPage({ canAdmin }: { canAdmin: boolean }) {
  const q = useData<Device[]>("/devices");
  const enroll = useAction<{ token: string; expiresAt: string }>(
    "/devices/enrollment-token",
  );
  const [selected, setSelected] = useState<Device | null>(null);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const revoke = useAction("/devices/" + revokeId, "DELETE");
  return (
    <>
      <Header
        title="Devices"
        description="Manage enrollment, collection policies, and endpoint health."
        action={
          canAdmin ? (
            <Button
              onClick={() => enroll.mutate(undefined)}
              disabled={enroll.isPending}
            >
              <Plus size={16} />
              Generate enrollment token
            </Button>
          ) : null
        }
      />
      <ErrorNote error={q.error ?? enroll.error ?? revoke.error} />
      {enroll.data && (
        <section className="panel enrollment">
          <h2>One-use enrollment token</h2>
          <p>
            Expires {time(enroll.data.expiresAt)}. Copy it into the agent
            enrollment prompt on your authorized Windows device.
          </p>
          <code>{enroll.data.token}</code>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => navigator.clipboard.writeText(enroll.data!.token)}
          >
            <Clipboard size={14} />
            Copy
          </Button>
          <p className="muted">
            The server stores only its hash.{" "}
            <Link to="/downloads">View installation instructions →</Link>
          </p>
        </section>
      )}
      {revokeId && (
        <section className="panel enrollment">
          <h2>Revoke this device?</h2>
          <p>
            Uploads will stop immediately. Historical evidence is retained under
            your retention policy.
          </p>
          <Button
            variant="destructive"
            onClick={() => {
              revoke.mutate(undefined, { onSuccess: () => setRevokeId(null) });
            }}
          >
            Revoke credentials
          </Button>
          <Button variant="ghost" onClick={() => setRevokeId(null)}>
            Cancel
          </Button>
        </section>
      )}
      {q.isPending ? (
        <Loading />
      ) : !q.data?.length ? (
        <section className="panel">
          <Empty
            icon={Monitor}
            title="No devices enrolled"
            body="Generate a token, then enroll the Windows agent. Its heartbeat will establish online status."
          />
        </section>
      ) : (
        <section className="panel table-panel">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Status</th>
                  <th>Agent</th>
                  <th>Last heartbeat</th>
                  <th>Last event</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {q.data.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <button
                        className="table-link"
                        onClick={() => setSelected(d)}
                      >
                        <Monitor size={16} />
                        {d.hostname}
                      </button>
                      <small>
                        {d.osVersion}
                        {d.simulated ? " · SIMULATED" : ""}
                      </small>
                    </td>
                    <td>
                      <Badge
                        value={
                          d.active
                            ? online(d)
                              ? "ONLINE"
                              : "OFFLINE"
                            : "REVOKED"
                        }
                      />
                      {d.healthError && (
                        <small className="red">{d.healthError}</small>
                      )}
                    </td>
                    <td>{d.agentVersion}</td>
                    <td>{time(d.lastHeartbeat)}</td>
                    <td>{time(d.lastEvent)}</td>
                    <td>
                      {canAdmin && d.active && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setRevokeId(d.id)}
                        >
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      {selected && (
        <Modal title={selected.hostname} onClose={() => setSelected(null)}>
          <DeviceConfig device={selected} canAdmin={canAdmin} />
        </Modal>
      )}
    </>
  );
}
function DeviceConfig({
  device,
  canAdmin,
}: {
  device: Device;
  canAdmin: boolean;
}) {
  const [ids, setIds] = useState(device.eventIds);
  const [tags, setTags] = useState(device.tags.join(", "));
  const save = useAction("/devices/" + device.id, "PATCH");
  return (
    <>
      <p className="muted">Device ID: {device.id}</p>
      <h3>Collection policy</h3>
      <p>
        Only the selected Security event IDs are collected. Audit policy is
        never changed automatically.
      </p>
      <div className="policy-grid">
        {[4624, 4625, 4634, 4648, 4672, 4688, 4720, 4726, 4740, 1102].map(
          (id) => (
            <label className="checkbox" key={id}>
              <input
                type="checkbox"
                disabled={!canAdmin}
                checked={ids.includes(id)}
                onChange={(e) =>
                  setIds(
                    e.target.checked
                      ? [...ids, id]
                      : ids.filter((x) => x !== id),
                  )
                }
              />
              {id}
            </label>
          ),
        )}
      </div>
      <label>
        Tags, separated by commas
        <input
          value={tags}
          disabled={!canAdmin}
          onChange={(e) => setTags(e.target.value)}
        />
      </label>
      <ErrorNote error={save.error} />
      {canAdmin && (
        <Button
          disabled={!ids.length || save.isPending}
          onClick={() =>
            save.mutate({
              eventIds: ids,
              tags: tags
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
        >
          Save collection policy
        </Button>
      )}
      {save.isSuccess && (
        <p className="green">
          Saved. The agent receives the policy at its next heartbeat.
        </p>
      )}
    </>
  );
}
function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <section
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="panel-heading">
          <h2>{title}</h2>
          <button
            autoFocus
            className="icon-button"
            onClick={onClose}
            aria-label="Close"
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </section>
    </div>
  );
}
function EventsPage() {
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    q: new URLSearchParams(location.search).get("q") ?? "",
    deviceId: "",
    windowsEventId: "",
    category: "",
    username: "",
    sourceIp: "",
    from: "",
    to: "",
  });
  const [selected, setSelected] = useState<Event | null>(null);
  const [exportError, setExportError] = useState<Error | null>(null);
  const devices = useData<Device[]>("/devices");
  const params = new URLSearchParams({ page: String(page) });
  for (const [k, v] of Object.entries(filters))
    if (v)
      params.set(k, k === "from" || k === "to" ? new Date(v).toISOString() : v);
  const q = useData<Page<Event>>("/events?" + params);
  const update = (key: keyof typeof filters, value: string) => {
    setPage(1);
    setFilters({ ...filters, [key]: value });
  };
  return (
    <>
      <Header
        title="Live events"
        description="Search normalized Windows security events. Filters run on the server."
        action={
          <div className="actions">
            {["csv", "json"].map((format) => (
              <Button
                key={format}
                variant="secondary"
                onClick={() =>
                  download(
                    "/events/export?" + params + "&format=" + format,
                    "zeroeye-events." + format,
                  ).catch(setExportError)
                }
              >
                <ArrowDownToLine size={15} />
                {format.toUpperCase()}
              </Button>
            ))}
          </div>
        }
      />
      <div className="filters">
        <div className="search-input">
          <Search size={16} />
          <input
            aria-label="Search events"
            placeholder="Search accounts or processes"
            value={filters.q}
            onChange={(e) => update("q", e.target.value)}
          />
        </div>
        <select
          aria-label="Filter device"
          value={filters.deviceId}
          onChange={(e) => update("deviceId", e.target.value)}
        >
          <option value="">All devices</option>
          {devices.data?.map((d) => (
            <option key={d.id} value={d.id}>
              {d.hostname}
            </option>
          ))}
        </select>
        <input
          aria-label="Windows event ID"
          placeholder="Event ID"
          type="number"
          value={filters.windowsEventId}
          onChange={(e) => update("windowsEventId", e.target.value)}
        />
        <select
          aria-label="Event category"
          value={filters.category}
          onChange={(e) => update("category", e.target.value)}
        >
          <option value="">All categories</option>
          {["authentication", "account", "process", "audit"].map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
      </div>
      <details className="advanced">
        <summary>More filters</summary>
        <div className="filters">
          <input
            aria-label="Username"
            placeholder="Username"
            value={filters.username}
            onChange={(e) => update("username", e.target.value)}
          />
          <input
            aria-label="Source IP"
            placeholder="Source IP address"
            value={filters.sourceIp}
            onChange={(e) => update("sourceIp", e.target.value)}
          />
          <label>
            From
            <input
              type="datetime-local"
              value={filters.from}
              onChange={(e) => update("from", e.target.value)}
            />
          </label>
          <label>
            To
            <input
              type="datetime-local"
              value={filters.to}
              onChange={(e) => update("to", e.target.value)}
            />
          </label>
        </div>
      </details>
      <ErrorNote error={q.error ?? exportError} />
      {q.isPending ? (
        <Loading />
      ) : (
        <section className="panel table-panel">
          {q.data?.items.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Event ID</th>
                    <th>Device</th>
                    <th>Category</th>
                    <th>Account</th>
                    <th>Source</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {q.data.items.map((e) => (
                    <tr key={e.id}>
                      <td>
                        {time(e.timestamp)}
                        {e.simulated && (
                          <small className="amber">SIMULATED</small>
                        )}
                      </td>
                      <td>
                        <code>{e.windowsEventId}</code>
                      </td>
                      <td>{e.device?.hostname}</td>
                      <td>
                        <Badge value={e.category} />
                      </td>
                      <td>{e.username ?? "Unavailable"}</td>
                      <td className="mono">{e.sourceIp ?? "Unavailable"}</td>
                      <td>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setSelected(e)}
                        >
                          Inspect
                          <ArrowUpRight size={13} />
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={Activity}
              title="No events in this range"
              body="Check your filters, agent connection, and Windows audit policy. The default range is the last 24 hours."
            />
          )}
          <Pager page={page} total={q.data?.total ?? 0} onPage={setPage} />
        </section>
      )}
      {selected && (
        <Modal
          title={"Event " + selected.windowsEventId}
          onClose={() => setSelected(null)}
        >
          <pre>{JSON.stringify(selected, null, 2)}</pre>
        </Modal>
      )}
    </>
  );
}
function ThreatsPage() {
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const q = useData<Page<Alert>>(
    "/alerts?page=" +
      page +
      (severity ? "&severity=" + severity : "") +
      (status ? "&status=" + status : ""),
  );
  return (
    <>
      <Header
        title="Threat detection"
        description="Deterministic detections with links to the events that triggered them."
      />
      <div className="filters">
        <select
          aria-label="Alert severity"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All severities</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select
          aria-label="Alert status"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All statuses</option>
          <option>OPEN</option>
          <option>ACKNOWLEDGED</option>
        </select>
      </div>
      <ErrorNote error={q.error} />
      {q.isPending ? (
        <Loading />
      ) : (
        <section className="panel table-panel">
          {q.data?.items.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Detection</th>
                    <th>Severity</th>
                    <th>Device</th>
                    <th>Status</th>
                    <th>Detected</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {q.data.items.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <strong>{a.name}</strong>
                        <small>
                          {a.ruleId}
                          {a.simulated ? " · SIMULATED" : ""}
                        </small>
                      </td>
                      <td>
                        <Badge value={a.severity} />
                      </td>
                      <td>{a.device?.hostname}</td>
                      <td>
                        <Badge value={a.status} />
                      </td>
                      <td>{time(a.detectedAt)}</td>
                      <td>
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => setSelected(a.id)}
                        >
                          Review
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              title="No alerts match your filters"
              body="A rule match will create an alert with supporting evidence. A match alone does not confirm an attack."
            />
          )}
          <Pager page={page} total={q.data?.total ?? 0} onPage={setPage} />
        </section>
      )}
      {selected && (
        <Modal title="Review detection" onClose={() => setSelected(null)}>
          <AlertDetail id={selected} />
        </Modal>
      )}
    </>
  );
}
function AlertDetail({ id }: { id: string }) {
  const q = useData<Alert>("/alerts/" + id);
  const acknowledge = useAction("/alerts/" + id, "PATCH");
  const incident = useAction<Incident>("/incidents");
  const navigate = useNavigate();
  return q.isPending ? (
    <Loading />
  ) : (
    <>
      <ErrorNote error={q.error ?? acknowledge.error ?? incident.error} />
      {q.data && (
        <>
          <div className="actions">
            <Badge value={q.data.severity} />
            <Badge value={q.data.status} />
          </div>
          <h2>{q.data.name}</h2>
          <p>{q.data.explanation}</p>
          <small className="muted">
            Rule certainty: RULE MATCH · ATT&CK{" "}
            {q.data.techniques.join(", ") || "No mapping asserted"}
          </small>
          <h3>Supporting evidence</h3>
          {q.data.events?.map((e) => (
            <div key={e.id} className="evidence">
              <code>{e.windowsEventId}</code>
              <span>
                {time(e.timestamp)} · {e.username ?? "Account unavailable"}
              </span>
              <small className="mono">{e.id}</small>
            </div>
          ))}
          <div className="actions">
            <Button
              disabled={incident.isPending}
              onClick={() =>
                incident.mutate(
                  { alertId: id },
                  { onSuccess: (i) => navigate("/incidents/" + i.id) },
                )
              }
            >
              Create incident
            </Button>
            {q.data.status === "OPEN" && (
              <Button
                variant="secondary"
                onClick={() => acknowledge.mutate({ status: "ACKNOWLEDGED" })}
              >
                Acknowledge alert
              </Button>
            )}
          </div>
        </>
      )}
    </>
  );
}
function IncidentsPage() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const q = useData<Page<Incident>>(
    "/incidents?page=" + page + (status ? "&status=" + status : ""),
  );
  return (
    <>
      <Header
        title="Incidents"
        description="Track investigations from the first signal through resolution."
      />
      <div className="filters">
        <select
          aria-label="Incident status"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(1);
          }}
        >
          <option value="">All statuses</option>
          {[
            "NEW",
            "INVESTIGATING",
            "AWAITING_APPROVAL",
            "CONTAINED",
            "RESOLVED",
            "FALSE_POSITIVE",
          ].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </div>
      <ErrorNote error={q.error} />
      {q.isPending ? (
        <Loading />
      ) : (
        <section className="panel table-panel">
          {q.data?.items.length ? (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Incident</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Last updated</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {q.data.items.map((i) => (
                    <tr key={i.id}>
                      <td>
                        <Link className="table-link" to={"/incidents/" + i.id}>
                          {i.title}
                        </Link>
                        <small className="mono">{i.id.slice(0, 8)}</small>
                      </td>
                      <td>
                        <Badge value={i.severity} />
                      </td>
                      <td>
                        <Badge value={i.status} />
                      </td>
                      <td>{time(i.updatedAt)}</td>
                      <td>
                        <Link className="quiet-link" to={"/incidents/" + i.id}>
                          Open
                          <ArrowUpRight size={14} />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty
              icon={Clipboard}
              title="No incidents yet"
              body="Open a detection and create an incident to organize its evidence and analyst decisions."
              action={
                <Button asChild variant="secondary">
                  <Link to="/threats">Review detections</Link>
                </Button>
              }
            />
          )}
          <Pager page={page} total={q.data?.total ?? 0} onPage={setPage} />
        </section>
      )}
    </>
  );
}
function InvestigationResult({ result }: { result: Investigation }) {
  return (
    <div className="investigation">
      <Badge value={result.provider} />
      <h3>{result.summary}</h3>
      <h4>Evidence-backed facts</h4>
      {result.facts.map((f, n) => (
        <div className="fact" key={n}>
          <Check size={15} />
          <div>
            {f.text}
            <small className="mono">Evidence: {f.evidenceIds.join(", ")}</small>
          </div>
        </div>
      ))}
      <h4>Hypotheses · require verification</h4>
      <ul>
        {result.hypotheses.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ul>
      <h4>Next steps</h4>
      <ol>
        {result.nextSteps.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>
      <h4>Limitations</h4>
      <ul>
        {result.limitations.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ul>
    </div>
  );
}
function IncidentPage() {
  const { id } = useParams();
  const q = useData<Incident>("/incidents/" + id);
  const members = useData<{ user: { id: string; name: string } }[]>(
    "/organizations/members",
  );
  const save = useAction("/incidents/" + id, "PATCH");
  const comment = useAction("/incidents/" + id + "/comments");
  const ai = useAction<{ result: Investigation }>("/ai/investigate");
  const advisory = useAction("/incidents/" + id + "/recommendations");
  const [note, setNote] = useState("");
  const [resolution, setResolution] = useState("");
  const [recommendation, setRecommendation] = useState("");
  const [kind, setKind] = useState("ACCOUNT_REVIEW");
  const [attachIds, setAttachIds] = useState("");
  const attach = useAction("/incidents/" + id + "/events");
  const i = q.data;
  return (
    <>
      <Link to="/incidents" className="quiet-link">
        <ChevronLeft size={14} />
        All incidents
      </Link>
      <Header
        title={i?.title ?? "Investigation"}
        description={i?.description ?? "Loading incident evidence…"}
      />
      <ErrorNote
        error={
          q.error ??
          save.error ??
          comment.error ??
          ai.error ??
          advisory.error ??
          attach.error
        }
      />
      {q.isPending ? (
        <Loading />
      ) : (
        i && (
          <>
            <div className="actions incident-controls">
              <Badge value={i.severity} />
              <select
                aria-label="Incident status"
                value={i.status}
                onChange={(e) =>
                  save.mutate({
                    status: e.target.value,
                    ...(e.target.value === "RESOLVED"
                      ? { resolutionNotes: resolution }
                      : {}),
                  })
                }
              >
                {[
                  "NEW",
                  "INVESTIGATING",
                  "AWAITING_APPROVAL",
                  "CONTAINED",
                  "RESOLVED",
                  "FALSE_POSITIVE",
                ].map((s) => (
                  <option key={s}>{s}</option>
                ))}
              </select>
              <select
                aria-label="Assign analyst"
                value={i.assignedTo ?? ""}
                onChange={(e) =>
                  save.mutate({ assignedTo: e.target.value || null })
                }
              >
                <option value="">Unassigned</option>
                {members.data?.map((m) => (
                  <option key={m.user.id} value={m.user.id}>
                    {m.user.name}
                  </option>
                ))}
              </select>
              <Button
                disabled={ai.isPending}
                onClick={() => ai.mutate({ incidentId: id })}
              >
                <Sparkles size={16} />
                {ai.isPending ? "Analyzing evidence…" : "Investigate evidence"}
              </Button>
            </div>
            <div className="detail-grid">
              <section className="panel padded">
                <h2>Evidence timeline</h2>
                {i.events?.map(({ event: e }) => (
                  <div className="evidence" key={e.id}>
                    <code>{e.windowsEventId}</code>
                    <span>
                      {time(e.timestamp)} ·{" "}
                      {e.username ?? "Account unavailable"} ·{" "}
                      {e.sourceIp ?? "IP unavailable"}
                    </span>
                    <small className="mono">
                      {e.id}
                      {e.simulated ? " · SIMULATED" : ""}
                    </small>
                  </div>
                ))}
                <label>
                  Attach event IDs, separated by commas
                  <textarea
                    value={attachIds}
                    onChange={(e) => setAttachIds(e.target.value)}
                    placeholder="Paste event UUIDs from Live Events"
                  />
                </label>
                <Button
                  variant="secondary"
                  disabled={!attachIds.trim()}
                  onClick={() =>
                    attach.mutate(
                      {
                        eventIds: attachIds
                          .split(",")
                          .map((s) => s.trim())
                          .filter(Boolean),
                      },
                      { onSuccess: () => setAttachIds("") },
                    )
                  }
                >
                  Attach authorized evidence
                </Button>
                <h3>Analyst notes</h3>
                {i.comments?.map((c) => (
                  <div className="comment" key={c.id}>
                    <small>{time(c.createdAt)}</small>
                    <p>{c.body}</p>
                  </div>
                ))}
                <textarea
                  aria-label="Investigation note"
                  placeholder="Document your findings and decisions…"
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                />
                <Button
                  variant="secondary"
                  disabled={!note.trim() || comment.isPending}
                  onClick={() =>
                    comment.mutate(
                      { body: note },
                      { onSuccess: () => setNote("") },
                    )
                  }
                >
                  Add note
                </Button>
                <h3>Resolution notes</h3>
                <textarea
                  aria-label="Resolution notes"
                  value={resolution}
                  placeholder={
                    i.resolutionNotes ?? "Required before selecting Resolved"
                  }
                  onChange={(e) => setResolution(e.target.value)}
                />
                {i.resolutionNotes && (
                  <p className="muted">Saved: {i.resolutionNotes}</p>
                )}
              </section>
              <section className="panel padded">
                <h2>
                  <Sparkles size={19} />
                  Investigation findings
                </h2>
                {ai.data ? (
                  <InvestigationResult result={ai.data.result} />
                ) : i.investigations?.length ? (
                  <InvestigationResult
                    result={
                      i.investigations[i.investigations.length - 1]!.result
                    }
                  />
                ) : (
                  <Empty
                    icon={Sparkles}
                    title="Ready to review evidence"
                    body="The default service produces a deterministic evidence summary. An external LLM is optional and requires organization opt-in."
                  />
                )}
              </section>
            </div>
            <section className="panel padded">
              <h2>Advisory response</h2>
              <p>
                Recommendations record analyst intent. ZEROEYE does not execute
                endpoint changes.
              </p>
              {i.actions?.map((a) => (
                <div className="comment" key={a.id}>
                  <Badge value={a.kind} />
                  <p>{a.recommendation}</p>
                </div>
              ))}
              <div className="filters">
                <select
                  value={kind}
                  onChange={(e) => setKind(e.target.value)}
                  aria-label="Recommendation type"
                >
                  {[
                    "ACCOUNT_REVIEW",
                    "IP_BLOCK_REVIEW",
                    "CONTAINMENT_GUIDANCE",
                    "INVESTIGATION_TASK",
                  ].map((k) => (
                    <option key={k}>{k}</option>
                  ))}
                </select>
                <input
                  aria-label="Response recommendation"
                  placeholder="Record the recommended action…"
                  value={recommendation}
                  onChange={(e) => setRecommendation(e.target.value)}
                />
                <Button
                  disabled={!recommendation.trim()}
                  onClick={() =>
                    advisory.mutate(
                      { kind, recommendation },
                      { onSuccess: () => setRecommendation("") },
                    )
                  }
                >
                  Save recommendation
                </Button>
              </div>
            </section>
          </>
        )
      )}
    </>
  );
}
function InvestigatorPage() {
  const q = useData<Page<Incident>>("/incidents");
  return (
    <>
      <Header
        eyebrow="EVIDENCE ASSISTANCE"
        title="AI Investigator"
        description="Choose an incident to build an investigation from authorized evidence."
      />
      <div className="notice">
        <Sparkles size={20} />
        <div>
          <strong>Evidence first. Analyst in control.</strong>
          <p>
            Default mode is a local deterministic summary, clearly identified as
            such. External model processing is disabled unless your
            administrator opts in.
          </p>
        </div>
      </div>
      <ErrorNote error={q.error} />
      <section className="panel">
        {q.isPending ? (
          <Loading />
        ) : q.data?.items.length ? (
          <div className="list">
            {q.data.items.map((i) => (
              <Link className="list-row" key={i.id} to={"/incidents/" + i.id}>
                <div className="list-symbol">
                  <Clipboard size={18} />
                </div>
                <div>
                  <strong>{i.title}</strong>
                  <small>
                    {i.status.replaceAll("_", " ")} · {time(i.updatedAt)}
                  </small>
                </div>
                <Badge value={i.severity} />
                <ArrowUpRight size={16} />
              </Link>
            ))}
          </div>
        ) : (
          <Empty
            icon={Sparkles}
            title="An investigation starts with evidence"
            body="Create an incident from a detection, then use Investigate evidence on its detail page."
          />
        )}
      </section>
    </>
  );
}
function AnalyticsPage() {
  const t = useData<Trend[]>("/dashboard/trends");
  const o = useData<Overview>("/dashboard/overview");
  return (
    <>
      <Header
        title="Security analytics"
        description="Measured activity from stored security events and investigation records."
      />
      <ErrorNote error={t.error ?? o.error} />
      <section className="panel chart-panel">
        <div className="panel-heading">
          <h2>Event and authentication activity</h2>
          <span className="chip">Last 24 hours</span>
        </div>
        {t.isPending ? <Loading /> : <TrendChart data={t.data ?? []} />}
      </section>
      <div className="summary-grid">
        <div>
          <Activity size={18} />
          <span>Failed logons in chart range</span>
          <strong>
            {t.data ? t.data.reduce((sum, d) => sum + d.failures, 0) : '—'}
          </strong>
        </div>
        <div>
          <ShieldAlert size={18} />
          <span>Active detections</span>
          <strong>{o.data?.activeAlerts ?? '—'}</strong>
        </div>
        <div>
          <CheckCircle2 size={18} />
          <span>Resolved investigations</span>
          <strong>{o.data?.resolvedIncidents ?? '—'}</strong>
        </div>
      </div>
    </>
  );
}
function ReportsPage() {
  const q =
    useData<{ id: string; kind: string; createdAt: string }[]>("/reports");
  const generate = useAction("/reports/generate");
  const [error, setError] = useState<Error | null>(null);
  return (
    <>
      <Header
        title="Reports"
        description="Capture a timestamped security summary using current database metrics."
        action={
          <Button
            disabled={generate.isPending}
            onClick={() => generate.mutate({ kind: "SECURITY_SUMMARY" })}
          >
            <Plus size={16} />
            Generate summary
          </Button>
        }
      />
      <ErrorNote error={q.error ?? generate.error ?? error} />
      <section className="panel">
        {q.isPending ? (
          <Loading />
        ) : q.data?.length ? (
          <div className="list">
            {q.data.map((r) => (
              <div className="list-row" key={r.id}>
                <div className="list-symbol">
                  <FileText size={18} />
                </div>
                <div>
                  <strong>Security summary</strong>
                  <small>{time(r.createdAt)}</small>
                </div>
                <Button
                  variant="secondary"
                  onClick={() =>
                    download(
                      "/reports/" + r.id + "/export",
                      "zeroeye-report.json",
                    ).catch(setError)
                  }
                >
                  <ArrowDownToLine size={14} />
                  JSON
                </Button>
              </div>
            ))}
          </div>
        ) : (
          <Empty
            icon={FileText}
            title="No reports generated"
            body="Generate a security summary to preserve current totals and your UTC reporting period."
          />
        )}
      </section>
      <p className="muted">
        Event exports support CSV and JSON. PDF, Excel, and scheduled reports
        are planned.
      </p>
    </>
  );
}
type Rule = {
  id: string;
  name: string;
  description: string;
  severity: string;
  policy: {
    enabled?: boolean;
    threshold?: number;
    windowSeconds?: number;
    suppressionSeconds?: number;
    allowedHours?: number[];
    trustedUsers?: string[];
  };
};
function RulesPage({ canAdmin }: { canAdmin: boolean }) {
  const q = useData<Rule[]>("/rules");
  const [selected, setSelected] = useState<Rule | null>(null);
  return (
    <>
      <Header
        title="Detection rules"
        description="Review rule behavior and configure thresholds for your organization."
      />
      <ErrorNote error={q.error} />
      <section className="panel">
        {q.isPending ? (
          <Loading />
        ) : (
          q.data?.map((r) => (
            <div className="rule-row" key={r.id}>
              <div className="rule-id">{r.id}</div>
              <div>
                <strong>{r.name}</strong>
                <p>{r.description}</p>
                {["ZE-004", "ZE-007"].includes(r.id) && (
                  <small className="amber">
                    Requires an explicit trusted-user list or UTC schedule
                  </small>
                )}
              </div>
              <Badge value={r.severity} />
              <Badge
                value={r.policy.enabled === false ? "DISABLED" : "ENABLED"}
              />
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setSelected(r)}
              >
                {canAdmin ? "Configure" : "View policy"}
              </Button>
            </div>
          ))
        )}
      </section>
      {selected && (
        <Modal title={selected.name} onClose={() => setSelected(null)}>
          <RuleConfig rule={selected} canAdmin={canAdmin} />
        </Modal>
      )}
    </>
  );
}
function RuleConfig({ rule, canAdmin }: { rule: Rule; canAdmin: boolean }) {
  const [policy, setPolicy] = useState(rule.policy);
  const save = useAction("/rules/" + rule.id, "PATCH");
  const [hours, setHours] = useState(rule.policy.allowedHours?.join(",") ?? "");
  const [users, setUsers] = useState(rule.policy.trustedUsers?.join(",") ?? "");
  return (
    <>
      <label className="checkbox">
        <input
          disabled={!canAdmin}
          type="checkbox"
          checked={policy.enabled !== false}
          onChange={(e) => setPolicy({ ...policy, enabled: e.target.checked })}
        />
        Rule enabled
      </label>
      {["ZE-001", "ZE-002", "ZE-008"].includes(rule.id) && (
        <>
          <label>
            Failure / account threshold
            <input
              disabled={!canAdmin}
              type="number"
              min={2}
              max={100}
              value={policy.threshold ?? 5}
              onChange={(e) =>
                setPolicy({ ...policy, threshold: Number(e.target.value) })
              }
            />
          </label>
          <label>
            Window, seconds
            <input
              disabled={!canAdmin}
              type="number"
              min={30}
              max={600}
              value={policy.windowSeconds ?? (rule.id === "ZE-002" ? 300 : 120)}
              onChange={(e) =>
                setPolicy({ ...policy, windowSeconds: Number(e.target.value) })
              }
            />
          </label>
        </>
      )}
      <label>
        Alert suppression, seconds
        <input
          disabled={!canAdmin}
          type="number"
          min={0}
          max={3600}
          value={policy.suppressionSeconds ?? 120}
          onChange={(e) =>
            setPolicy({ ...policy, suppressionSeconds: Number(e.target.value) })
          }
        />
      </label>
      {rule.id === "ZE-007" && (
        <label>
          Allowed UTC hours, separated by commas
          <input
            disabled={!canAdmin}
            value={hours}
            onChange={(e) => setHours(e.target.value)}
            placeholder="8,9,10,11,12,13,14,15,16,17"
          />
        </label>
      )}
      {rule.id === "ZE-004" && (
        <label>
          Trusted accounts, separated by commas
          <input
            disabled={!canAdmin}
            value={users}
            onChange={(e) => setUsers(e.target.value)}
          />
        </label>
      )}
      <ErrorNote error={save.error} />
      {canAdmin && (
        <Button
          onClick={() =>
            save.mutate({
              ...policy,
              ...(rule.id === "ZE-007"
                ? {
                    allowedHours: hours
                      .split(",")
                      .filter((s) => s.trim())
                      .map(Number),
                  }
                : {}),
              ...(rule.id === "ZE-004"
                ? {
                    trustedUsers: users
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                  }
                : {}),
            })
          }
          disabled={save.isPending}
        >
          Save policy
        </Button>
      )}
      {save.isSuccess && <p className="green">Policy saved.</p>}
    </>
  );
}
function DownloadsPage() {
  return (
    <>
      <Header
        title="Windows agent"
        description="A visible Windows service for authorized Security log monitoring."
      />
      <section className="panel padded agent-download">
        <div className="agent-icon">
          <Monitor size={38} />
        </div>
        <div>
          <div className="eyebrow">WINDOWS · PYTHON AGENT 0.1.0</div>
          <h2>ZEROEYE monitoring agent</h2>
          <p>
            Collect selected event IDs, retain a bounded queue during outages,
            and send batches over HTTPS. The agent does not modify Windows audit
            policies.
          </p>
          <Badge value="SOURCE AVAILABLE" />
          <p className="amber">
            No verified installer is available in this build. Package and test
            it on a clean Windows machine before distribution.
          </p>
        </div>
      </section>
      <div className="detail-grid">
        <section className="panel padded">
          <h2>1. Prepare and enroll</h2>
          <p>From this repository in a PowerShell terminal:</p>
          <pre>
            {
              "python -m venv agents/windows/.venv\nagents/windows/.venv/Scripts/python -m pip install -r agents/windows/requirements.txt\nagents/windows/.venv/Scripts/python agents/windows/src/main.py enroll"
            }
          </pre>
          <p>
            The enrollment prompt asks for your backend URL and one-use token.
            Development HTTP is allowed only for loopback.
          </p>
          <Link to="/devices" className="quiet-link">
            Generate an enrollment token
            <ArrowUpRight size={14} />
          </Link>
        </section>
        <section className="panel padded">
          <h2>2. Run the visible service</h2>
          <p>
            Use the packaging guide in docs/windows-agent.md. Installing a
            service and reading protected logs requires an
            administrator-approved installation.
          </p>
          <div className="notice">
            <Shield size={18} />
            <p>
              Collected: selected Windows Security logs. Never collected:
              keystrokes, screens, passwords, browser tokens, or personal files.
            </p>
          </div>
          <p>
            Diagnostic logs rotate locally. Uninstall stops and removes the
            service and attempts credential revocation.
          </p>
        </section>
      </div>
    </>
  );
}
function NotificationsPage() {
  const q =
    useData<
      {
        id: string;
        title: string;
        link: string;
        createdAt: string;
        reads: unknown[];
      }[]
    >("/notifications");
  const read = useMutation({
    mutationFn: (id: string) => api("/notifications/" + id, "PATCH", {}),
    onSuccess: () => q.refetch(),
  });
  return (
    <>
      <Header
        title="Notifications"
        description="Enrollment, detection, and incident updates for this organization."
      />
      <ErrorNote error={q.error ?? read.error} />
      <section className="panel">
        {q.isPending ? (
          <Loading />
        ) : q.data?.length ? (
          <div className="list">
            {q.data.map((n) => (
              <div className="list-row" key={n.id}>
                <div className="list-symbol">
                  <Bell size={17} />
                </div>
                <div>
                  <Link to={n.link}>
                    <strong>{n.title}</strong>
                  </Link>
                  <small>{time(n.createdAt)}</small>
                </div>
                {!n.reads.length && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => read.mutate(n.id)}
                  >
                    Mark read
                  </Button>
                )}
              </div>
            ))}
          </div>
        ) : (
          <Empty
            icon={Bell}
            title="You're all caught up"
            body="New enrollment, detection and incident activity will appear here."
          />
        )}
      </section>
      <p className="muted">
        Email delivery and offline-device notifications are planned. Connection
        state is available on Devices.
      </p>
    </>
  );
}
function SettingsPage() {
  const q = useData<{ retentionDays: number; externalAiEnabled: boolean }>(
    "/settings",
  );
  const members = useData<
    { id: string; role: string; user: { name: string; email: string } }[]
  >("/organizations/members");
  const save = useAction("/settings", "PATCH");
  const org = useAction("/organizations");
  const member = useAction("/organizations/members");
  const audits =
    useData<
      { id: string; action: string; createdAt: string; actorId: string }[]
    >("/audit");
  const [days, setDays] = useState<number | undefined>();
  const [external, setExternal] = useState<boolean | undefined>();
  const [name, setName] = useState("");
  const [demo, setDemo] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("VIEWER");
  return (
    <>
      <Header
        title="Workspace settings"
        description="Manage membership, retention, and investigation privacy."
      />
      <ErrorNote error={q.error ?? save.error ?? org.error ?? member.error} />
      <div className="detail-grid">
        <section className="panel padded">
          <h2>Data and privacy</h2>
          <label>
            Event retention, days
            <input
              type="number"
              min={7}
              max={365}
              value={days ?? q.data?.retentionDays ?? 30}
              onChange={(e) => setDays(Number(e.target.value))}
            />
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={external ?? q.data?.externalAiEnabled ?? false}
              onChange={(e) => setExternal(e.target.checked)}
            />
            Allow external AI processing
          </label>
          <p className="muted">
            Only event IDs, timestamps, outcomes, and simulation flags are sent
            to the investigation service. Account names, IPs and command lines
            are excluded. External processing also requires a configured
            provider.
          </p>
          <Button
            onClick={() =>
              save.mutate({
                retentionDays: days ?? q.data?.retentionDays ?? 30,
                externalAiEnabled:
                  external ?? q.data?.externalAiEnabled ?? false,
              })
            }
          >
            Save settings
          </Button>
          {save.isSuccess && <p className="green">Settings saved.</p>}
        </section>
        <section className="panel padded">
          <h2>Create another organization</h2>
          <label>
            Organization name
            <input value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={demo}
              onChange={(e) => setDemo(e.target.checked)}
            />
            Isolated demo organization
          </label>
          <Button
            disabled={!name.trim()}
            variant="secondary"
            onClick={() =>
              org.mutate({ name, demo }, { onSuccess: () => setName("") })
            }
          >
            <Plus size={15} />
            Create organization
          </Button>
        </section>
      </div>
      <section className="panel padded">
        <h2>Organization members</h2>
        {members.data?.map((m) => (
          <div className="list-row" key={m.id}>
            <div className="avatar">
              {m.user.name.slice(0, 2).toUpperCase()}
            </div>
            <div>
              <strong>{m.user.name}</strong>
              <small>{m.user.email}</small>
            </div>
            <Badge value={m.role} />
          </div>
        ))}
        <p>
          Add an existing registered user. Administrator or owner role required.
        </p>
        <div className="filters">
          <input
            aria-label="Member email"
            type="email"
            placeholder="User email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <select
            aria-label="Member role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
          >
            {["VIEWER", "ANALYST", "ADMIN", "OWNER"].map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
          <Button
            disabled={!email}
            onClick={() =>
              member.mutate({ email, role }, { onSuccess: () => setEmail("") })
            }
          >
            Add member
          </Button>
        </div>
      </section>
      <section className="panel padded">
        <h2>Recent audit activity</h2>
        <ErrorNote error={audits.error} />
        {audits.data?.map((a) => (
          <div className="audit-row" key={a.id}>
            <code>{a.action}</code>
            <span>{time(a.createdAt)}</span>
            <small className="mono">{a.actorId}</small>
          </div>
        ))}
      </section>
    </>
  );
}
