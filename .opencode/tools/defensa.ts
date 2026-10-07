import { tool } from "@opencode-ai/plugin"

const operations = new Set(["list_events", "get_report", "create_proposal"])

export default tool({
  description: "Read sanitized Defensa Azul events/reports or submit a typed defensive proposal; this tool cannot execute actions.",
  args: {
    operation: tool.schema.string().describe("One of: list_events, get_report, create_proposal"),
    run_id: tool.schema.string().optional().describe("Run identifier for reads"),
    proposal_json: tool.schema.string().optional().describe("Complete action proposal JSON for create_proposal"),
  },
  async execute(args) {
    if (!operations.has(args.operation)) throw new Error("unsupported operation")
    const base = process.env.DEFENSA_GATEWAY_URL ?? "http://127.0.0.1:8080"
    const token = process.env.DEFENSA_GATEWAY_TOKEN
    if (!token) throw new Error("DEFENSA_GATEWAY_TOKEN is required")

    let path: string
    let method = "GET"
    let body: string | undefined
    if (args.operation === "list_events") {
      path = `/v1/events${args.run_id ? `?run_id=${encodeURIComponent(args.run_id)}` : ""}`
    } else if (args.operation === "get_report") {
      if (!args.run_id) throw new Error("run_id is required")
      path = `/v1/report?run_id=${encodeURIComponent(args.run_id)}`
    } else {
      if (!args.proposal_json) throw new Error("proposal_json is required")
      JSON.parse(args.proposal_json)
      path = "/v1/proposals"
      method = "POST"
      body = args.proposal_json
    }

    const response = await fetch(`${base}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body,
    })
    const text = await response.text()
    if (!response.ok) throw new Error(`Defensa gateway returned ${response.status}: ${text}`)
    return text
  },
})

