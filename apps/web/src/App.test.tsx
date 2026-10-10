// @vitest-environment jsdom
import React from "react";
import { describe, it, expect, vi } from "vitest";
import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { Auth, OverviewPage } from "./App";
vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: any) => <div>{children}</div>,
  AreaChart: () => null,
  Area: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
}));
function wrap(element: React.ReactNode) {
  return render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>{element}</MemoryRouter>
    </QueryClientProvider>,
  );
}
describe("console states", () => {
  it("validates a short password before sending a login", async () => {
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    wrap(<Auth />);
    fireEvent.change(screen.getByLabelText("Email address"), {
      target: { value: "a@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "short" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(
      await screen.findByText("Use at least 12 characters"),
    ).toBeInTheDocument();
    expect(fetcher).not.toHaveBeenCalled();
    cleanup();
  });
  it("renders honest empty dashboard metrics from the API", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => ({
        ok: true,
        json: async () =>
          url.endsWith("/overview")
            ? {
                totalDevices: 0,
                onlineDevices: 0,
                offlineDevices: 0,
                eventsToday: 0,
                activeAlerts: 0,
                criticalIncidents: 0,
                resolvedIncidents: 0,
                healthIssues: 0,
                recentAlerts: [],
                recentIncidents: [],
                severities: [],
              }
            : [],
      })),
    );
    wrap(<OverviewPage />);
    expect(
      await screen.findByText("Connect your first endpoint"),
    ).toBeInTheDocument();
    expect(screen.getByText("No detections to review")).toBeInTheDocument();
    expect(screen.getAllByText("0").length).toBeGreaterThanOrEqual(4);
    cleanup();
  });
  it("surfaces backend failures", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: false,
        status: 503,
        json: async () => ({ error: "Database unavailable" }),
      })),
    );
    wrap(<OverviewPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Database unavailable",
    );
    cleanup();
  });
});
