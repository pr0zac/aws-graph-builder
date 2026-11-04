export async function get(path, params = {}, signal) {
  const response = await fetch(`${path}?${new URLSearchParams(params)}`, {signal});
  if (!response.ok) {
    let detail = response.statusText;
    try { detail = (await response.json()).detail || detail; } catch { /* Non-JSON server error. */ }
    throw new Error(`${response.status}: ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
  }
  return response.json();
}

export class LatestRequest {
  constructor() { this.ticket = null; }
  begin() {
    this.cancel();
    const controller = new AbortController();
    this.ticket = {signal: controller.signal, controller};
    return this.ticket;
  }
  cancel() { this.ticket?.controller.abort(); this.ticket = null; }
  valid(ticket) { return this.ticket === ticket && !ticket.signal.aborted; }
}
