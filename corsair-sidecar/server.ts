import http from "node:http";
import { corsair } from "./corsair";

const PORT = 9000;
const CHANNEL_ID = "C0C159X1A2X";

function sendJson(
  response: http.ServerResponse,
  status: number,
  body: unknown
): void {
  response.writeHead(status, {
    "Content-Type": "application/json",
  });

  response.end(
    JSON.stringify(body)
  );
}

async function readBody(
  request: http.IncomingMessage
): Promise<string> {
  const chunks: Buffer[] = [];

  for await (const chunk of request) {
    chunks.push(
      Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk)
    );
  }

  return Buffer.concat(chunks).toString(
    "utf-8"
  );
}

const server = http.createServer(
  async (request, response) => {
    if (
      request.method === "GET" &&
      request.url === "/health"
    ) {
      sendJson(
        response,
        200,
        {
          status: "ok",
          service: "corsair-sidecar",
        }
      );

      return;
    }

    if (
      request.method === "POST" &&
      request.url === "/notify"
    ) {
      try {
        const rawBody =
          await readBody(request);

        const body = JSON.parse(
          rawBody
        );

        const eventId =
          typeof body.event_id === "string"
            ? body.event_id
            : "unknown";

        const risk =
          typeof body.risk === "string"
            ? body.risk
            : "UNKNOWN";

        const detection =
          typeof body.detection === "string"
            ? body.detection
            : "Sensitive data";

        const dashboardUrl =
          typeof body.dashboard_url === "string"
            ? body.dashboard_url
            : "http://127.0.0.1:5173";

        const result =
          await corsair.slack.api.messages.post(
            {
              channel: CHANNEL_ID,
              text:
                `🚨 AI Guardian BLOCK\n\n` +
                `Event: ${eventId}\n` +
                `Risk: ${risk}\n` +
                `Detection: ${detection}\n\n` +
                `Review: ${dashboardUrl}`,
            }
          );

        sendJson(
          response,
          200,
          {
            ok: true,
            channel: result.channel,
            timestamp: result.ts,
          }
        );

        return;

      } catch (error) {
        console.error(
          "Corsair notification failed:",
          error
        );

        sendJson(
          response,
          500,
          {
            ok: false,
            error: String(error),
          }
        );

        return;
      }
    }

    sendJson(
      response,
      404,
      {
        error: "Not found",
      }
    );
  }
);

server.listen(
  PORT,
  "127.0.0.1",
  () => {
    console.log(
      `CORSair sidecar listening on http://127.0.0.1:${PORT}`
    );
  }
);