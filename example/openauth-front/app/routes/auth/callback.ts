import { client, setTokens } from "../../auth";
import type { Route } from "./+types/callback";

export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  try {
    const tokens = await client.exchange(code!, url.origin + "/callback");

    const rq = fetch("http://localhost:8080/verify", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokens.access}`,
        "X-Refresh-Token": tokens.refresh,
      },
    });

    const res = await rq;
    const json = await res.json();
    console.log(tokens);
    console.log("verify :", json);

    const headers = await setTokens(tokens.access, tokens.refresh);
    headers.append("Location", "/");
    return new Response(null, {
      headers,
      status: 302,
    });
  } catch (e) {
    return Response.json(e, {
      status: 400,
    });
  }
}
