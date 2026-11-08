import { describe, expect, it } from "vitest";
import { compareIp, describeEvent, duration, matchesQuery, sock } from "./format";

describe("format", () => {
  it("formats socket addresses for both families", () => {
    expect(sock("1.2.3.4", 443)).toBe("1.2.3.4:443");
    expect(sock("2001:db8::1", 443)).toBe("[2001:db8::1]:443");
    expect(sock("2001:db8::1", null)).toBe("2001:db8::1");
    expect(sock(null, 1)).toBe("—");
  });

  it("formats durations", () => {
    expect(duration(250)).toBe("250 мс");
    expect(duration(1500)).toBe("1.5 с");
    expect(duration(125_000)).toBe("2 мин 05 с");
    expect(duration(-1)).toBe("—");
  });

  it("matches all terms case-insensitively", () => {
    expect(matchesQuery(["162.159.130.234", 443, "ESTABLISHED"], "162.159 est")).toBe(true);
    expect(matchesQuery(["162.159.130.234", 443], "443 udp")).toBe(false);
    expect(matchesQuery([null, "x"], "")).toBe(true);
  });

  it("sorts IPv4 numerically and before IPv6", () => {
    const ips = ["10.0.0.10", "2001:db8::1", "10.0.0.9", "9.9.9.9", null];
    expect([...ips].sort(compareIp)).toEqual(["9.9.9.9", "10.0.0.9", "10.0.0.10", "2001:db8::1", null]);
  });

  it("describes events without inventing data", () => {
    const d = describeEvent({
      type: "endpointDisappeared",
      endpoint: { endpointId: 1, protocol: "udp", pid: 5, localAddr: "0.0.0.0", localPort: 5353, remoteAddr: null, remotePort: null },
      lastSeen: 0,
      lastState: null,
    });
    expect(d).toContain("UDP 0.0.0.0:5353");
    expect(d).toContain("нет в снимке");
  });
});
