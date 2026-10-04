import type { BgRequest, BgResponse } from "./types";

/** Send a request to the background worker and unwrap its {ok, data|error} envelope. */
export async function send<T>(message: BgRequest): Promise<T> {
  const response = (await chrome.runtime.sendMessage(message)) as BgResponse<T> | undefined;
  if (!response) throw new Error("No response from the extension background worker");
  if (!response.ok) throw new Error(response.error);
  return response.data;
}
