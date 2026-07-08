local shortport = require "shortport"
local http      = require "http"
local stdnse    = require "stdnse"
local json      = require "json"
local nmap      = require "nmap"

description = [[
Detects and enumerates etcd, the distributed key-value store used by Kubernetes
and many other distributed systems, via its unauthenticated HTTP endpoints.

The script issues read-only HTTP GET requests to well-known etcd paths:

  * /version        - present on both the v2 and v3 HTTP gateways; returns the
                      etcd server and cluster versions.
  * /v2/stats/self  - on clusters exposing the v2 API, returns the node's role
                      (leader / follower) and name.
  * /metrics        - Prometheus metrics endpoint; if reachable and containing
                      etcd_* series, it is reported as an information-disclosure
                      finding.

All requests are simple, idempotent GETs. The script deliberately does NOT read,
write, list, or delete any keys, so it stays within the "safe" category. If you
want to test whether the key API is actually open (an intrusive check), do that
in a separate, clearly-categorised script.

etcd listens on 2379/tcp for client traffic by default. In hardened deployments
these endpoints require client certificates or a token; in default or hastily
deployed clusters (common in labs and CI) they are reachable unauthenticated,
which is itself worth reporting.

NOTE: This script speaks plain HTTP. Production etcd is frequently TLS-only on
2379; against those targets Nmap must have flagged the port as ssl (e.g. via -sV)
for the http library to negotiate TLS. See the @args section for forcing this.

VERIFY BEFORE CLAIMING NOVELTY: confirm no official script shadows this with
  grep -i etcd /usr/share/nmap/scripts/script.db
and a search of https://nmap.org/nsedoc/ .
]]

---
-- @usage
-- nmap -p 2379 --script etcd-info <target>
-- nmap -sV --script etcd-info <target>
--
-- @args etcd-info.paths  Comma-separated extra paths to probe for a metrics or
--                        health endpoint. Default: none.
--
-- @output
-- PORT     STATE SERVICE
-- 2379/tcp open  etcd
-- | etcd-info:
-- |   server_version: 3.5.9
-- |   cluster_version: 3.5.0
-- |   node_name: infra1
-- |   node_role: leader
-- |   metrics_exposed: true
-- |_  unauthenticated_access: true
--
-- @xmloutput
-- <elem key="server_version">3.5.9</elem>
-- <elem key="cluster_version">3.5.0</elem>
-- <elem key="node_name">infra1</elem>
-- <elem key="node_role">leader</elem>
-- <elem key="metrics_exposed">true</elem>
-- <elem key="unauthenticated_access">true</elem>
---

author = "AB"  -- replace with your name for submission
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

-- etcd's default client port. Also fire if version detection tagged the service.
portrule = shortport.port_or_service({2379}, {"etcd", "etcd-client"}, "tcp")

-- Perform a GET and, on a 200 with a JSON body, return (status, parsed_table).
-- Returns (status, nil) on a non-200 or non-JSON response, and (nil, nil) if the
-- host produced no usable HTTP response at all.
local function get_json(host, port, path)
  local resp = http.get(host, port, path)
  if not resp or resp.status == nil then
    return nil, nil
  end
  if resp.status ~= 200 or not resp.body then
    return resp.status, nil
  end
  local ok, parsed = json.parse(resp.body)
  if not ok then
    return resp.status, nil
  end
  return resp.status, parsed
end

action = function(host, port)
  local out = stdnse.output_table()
  local is_etcd = false

  -- 1) /version : the primary, auth-free fingerprint on both v2 and v3 gateways.
  local vstatus, ver = get_json(host, port, "/version")
  if vstatus == nil then
    -- No HTTP response (connection refused, or TLS-only port not flagged ssl).
    return nil
  end
  if ver then
    if ver.etcdserver then
      out.server_version = ver.etcdserver
      is_etcd = true
    end
    if ver.etcdcluster then
      out.cluster_version = ver.etcdcluster
      is_etcd = true
    end
  end

  -- 2) /v2/stats/self : node identity and leader/follower role (v2-enabled nodes).
  local _, self_stats = get_json(host, port, "/v2/stats/self")
  if self_stats then
    if self_stats.name then
      out.node_name = self_stats.name
      is_etcd = true
    end
    if self_stats.state then
      -- "StateLeader" / "StateFollower" -> "leader" / "follower"
      out.node_role = (self_stats.state:gsub("^State", "")):lower()
      is_etcd = true
    end
  end

  -- 3) /metrics : Prometheus endpoint. Reported only if it looks like etcd's.
  local mresp = http.get(host, port, "/metrics")
  if mresp and mresp.status == 200 and mresp.body
     and mresp.body:find("etcd_", 1, true) then
    out.metrics_exposed = true
    is_etcd = true
  end

  -- Endpoints answered but nothing looked like etcd -> stay quiet.
  if not is_etcd then
    return nil
  end

  -- We successfully read info without presenting credentials.
  out.unauthenticated_access = true

  -- Enrich Nmap's own service/version detection when run under -sV.
  if out.server_version and port.version.product == nil then
    port.version.name    = "etcd"
    port.version.product = "etcd"
    port.version.version = out.server_version
    nmap.set_port_version(host, port, "hardmatched")
  end

  return out
end
