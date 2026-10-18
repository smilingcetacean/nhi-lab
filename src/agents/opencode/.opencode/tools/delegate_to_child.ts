import { tool } from "@opencode-ai/plugin"
import { $ } from "bun"

// The only way this agent acts. One call runs a full delegation cycle through
// the parent harness: vend a fresh child identity, spawn the child pod, take
// its result over mTLS, dispose. Authorization is decided by the policy plane,
// never here.
export default tool({
  description:
    "Delegate one read to a freshly vended child agent. This vends a new child " +
    "identity scoped to the requested dataset, spawns the child, and returns " +
    "what the child read as JSON (ok, chain_id, child_spiffe_id, child_scopes, " +
    "status, data, disposed, error). A refused dataset comes back as ok=false " +
    "with the denial in the JSON, not as an exception.",
  args: {
    task: tool.schema.string().describe("Free-text description of what the child should read, for the audit trail"),
    dataset: tool.schema.enum(["A", "B"]).describe("Which protected dataset the child should read"),
  },
  async execute(args) {
    const payload = JSON.stringify(args)
    // quiet() keeps the harness narration (stderr) out of the TUI; nothrow()
    // turns a non-zero exit (e.g. a 403) into a normal result to hand back.
    const res = await $`python3 /app/parent.py tool ${payload}`.quiet().nothrow()
    const out = res.stdout.toString().trim()
    if (out) return out
    const tail = res.stderr.toString().trim().split("\n").slice(-5).join("\n")
    return `error: parent.py tool exited ${res.exitCode} with no result\n${tail}`
  },
})
