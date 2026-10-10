console.log("AI Guardian extension loaded.");

fetch("http://127.0.0.1:8000/ping", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({})
})
  .then(async (response) => {
    const data = await response.json();

    // Never log scan/backend responses; file responses may include redacted bytes.
  })
  .catch((error) => {
    console.error("Could not connect to AI Guardian backend:", error);
  });


const BACKEND = "http://127.0.0.1:8000";
const RELEASE_ALARM = "ai-guardian-release-poll";
const OVERRIDE_OFFERS_KEY = "overrideOffers";
const OVERRIDE_OFFER_MAX_AGE_MS = 30 * 60 * 1000;
const OVERRIDE_OFFER_MAX_ENTRIES = 20;

function safeSiteHost(value) {
  try {
    const hostname = new URL(value).hostname.toLowerCase();
    return /^[a-z0-9.-]{1,253}$/.test(hostname) ? `https://${hostname}` : "https://unknown";
  } catch (_) {
    return "https://unknown";
  }
}

async function getPendingEvents() {
  const data = await chrome.storage.session.get("pendingReleases");
  return data.pendingReleases || {};
}

async function savePendingEvents(pending) {
  await chrome.storage.session.set({ pendingReleases: pending });
}

async function registerPendingRelease(
  eventId,
  releaseToken,
  tabId,
  payloadType
) {
  if (!eventId || !releaseToken || typeof tabId !== "number") {
    return;
  }

  const pending = await getPendingEvents();

  pending[eventId] = {
    eventId,
    releaseToken,
    tabId,
    payloadType,
    createdAt: Date.now(),
    releaseAuthorized: false
  };

  await savePendingEvents(pending);

  await chrome.alarms.create(RELEASE_ALARM, {
    periodInMinutes: 0.5
  });
}

async function removePendingRelease(eventId) {
  const pending = await getPendingEvents();

  delete pending[eventId];

  await savePendingEvents(pending);

  if (Object.keys(pending).length === 0) {
    await chrome.alarms.clear(RELEASE_ALARM);
  }
}

// --------------------------------------------------
// REDACTION OVERRIDE — offer storage and pending entries
// --------------------------------------------------
// Override tokens live only in chrome.storage.session. They are never
// forwarded to content.js and never logged.

async function getOverrideOffers() {
  const data = await chrome.storage.session.get(OVERRIDE_OFFERS_KEY);
  return data[OVERRIDE_OFFERS_KEY] || {};
}

async function saveOverrideOffers(offers) {
  await chrome.storage.session.set({ [OVERRIDE_OFFERS_KEY]: offers });
}

function pruneOverrideOffers(offers) {
  const now = Date.now();

  for (const [eventId, offer] of Object.entries(offers)) {
    if (
      !offer ||
      typeof offer.token !== "string" ||
      typeof offer.createdAt !== "number" ||
      now - offer.createdAt >= OVERRIDE_OFFER_MAX_AGE_MS
    ) {
      delete offers[eventId];
    }
  }

  const entries = Object.entries(offers);

  if (entries.length > OVERRIDE_OFFER_MAX_ENTRIES) {
    entries.sort((a, b) => a[1].createdAt - b[1].createdAt);

    for (const [eventId] of entries.slice(0, entries.length - OVERRIDE_OFFER_MAX_ENTRIES)) {
      delete offers[eventId];
    }
  }

  return offers;
}

async function saveOverrideOffer(eventId, token) {
  if (typeof eventId !== "string" || !eventId || typeof token !== "string" || !token) {
    throw new Error("Invalid override offer.");
  }

  const offers = pruneOverrideOffers(await getOverrideOffers());

  offers[eventId] = {
    token,
    createdAt: Date.now()
  };

  await saveOverrideOffers(pruneOverrideOffers(offers));
}

async function getOverrideToken(eventId) {
  const offers = await getOverrideOffers();
  const offer = offers[eventId];

  if (
    !offer ||
    typeof offer.token !== "string" ||
    typeof offer.createdAt !== "number" ||
    Date.now() - offer.createdAt >= OVERRIDE_OFFER_MAX_AGE_MS
  ) {
    return null;
  }

  return offer.token;
}

async function removeOverrideOffer(eventId) {
  const offers = await getOverrideOffers();

  if (eventId in offers) {
    delete offers[eventId];
    await saveOverrideOffers(offers);
  }
}

function overrideUrl(eventId, action) {
  return `${BACKEND}/release/override/${encodeURIComponent(eventId)}/${action}`;
}

async function registerPendingOverride(eventId, overrideToken, tabId) {
  if (!eventId || !overrideToken || typeof tabId !== "number") {
    throw new Error("Cannot register override.");
  }

  const pending = await getPendingEvents();

  pending[eventId] = {
    kind: "override",
    eventId,
    overrideToken,
    tabId,
    payloadType: "file",
    createdAt: Date.now(),
    notified: false
  };

  await savePendingEvents(pending);

  await chrome.alarms.create(RELEASE_ALARM, {
    periodInMinutes: 0.5
  });
}

async function pollOverride(item, pending) {
  // `pending` is the snapshot taken by pollPendingReleases. Writes below
  // re-read the store so a concurrent register/remove is never overwritten.
  const response = await fetch(
    overrideUrl(item.eventId, "status"),
    {
      method: "GET",
      headers: {
        "X-Sentinel-Override-Token": item.overrideToken
      }
    }
  );

  if (!response.ok) {
    if (response.status === 401 || response.status === 404 || response.status === 410) {
      await chrome.tabs.sendMessage(item.tabId, {
        type: "OVERRIDE_TERMINAL",
        eventId: item.eventId,
        state: "EXPIRED"
      }).catch(() => {});
      await removePendingRelease(item.eventId);
      return;
    }

    console.warn(
      "[AI Guardian Background] Override status check failed:",
      item.eventId,
      response.status
    );
    return;
  }

  const data = await response.json();
  const state = data.state;

  if (state === "PENDING" || state === "AVAILABLE") {
    return;
  }

  if (state === "APPROVED") {
    if (item.notified) {
      return;
    }

    // The entry may have been consumed/cancelled while this poll was in flight.
    const current = await getPendingEvents();

    if (!current[item.eventId]) {
      return;
    }

    try {
      await chrome.tabs.sendMessage(item.tabId, {
        type: "OVERRIDE_APPROVED",
        eventId: item.eventId,
        reviewedBy: data.reviewed_by
      });
    } catch (error) {
      console.warn(
        "[AI Guardian Background] Could not deliver override approval to tab; will retry.",
        item.eventId
      );
      return;
    }

    item.notified = true;

    const latest = await getPendingEvents();

    if (latest[item.eventId]) {
      latest[item.eventId].notified = true;
      await savePendingEvents(latest);
    }

    return;
  }

  if (state === "REJECTED" || state === "EXPIRED" || state === "CANCELLED") {
    await chrome.tabs.sendMessage(item.tabId, {
      type: "OVERRIDE_TERMINAL",
      eventId: item.eventId,
      state
    }).catch(() => {});
    await removePendingRelease(item.eventId);
    return;
  }

  if (state === "RELEASED") {
    await removePendingRelease(item.eventId);
  }
}

async function pollPendingReleases() {
  const pending = await getPendingEvents();
  const entries = Object.values(pending);

  if (entries.length === 0) {
    await chrome.alarms.clear(RELEASE_ALARM);
    return;
  }

  for (const item of entries) {
    try {
      if (item.kind === "override") {
        await pollOverride(item, pending);
        continue;
      }

      if (Date.now() - item.createdAt >= 20 * 60 * 1000) {
        await chrome.tabs.sendMessage(item.tabId, {
          type: "RELEASE_TERMINAL",
          eventId: item.eventId,
          state: "EXPIRED",
          payloadType: item.payloadType
        }).catch(() => {});
        await removePendingRelease(item.eventId);
        continue;
      }

      const response = await fetch(
        `${BACKEND}/release/${encodeURIComponent(item.eventId)}/status`,
        {
          method: "GET",
          headers: {
            "X-Guardian-Release-Token": item.releaseToken
          }
        }
      );

      if (!response.ok) {
        if (response.status === 410) {
          await chrome.tabs.sendMessage(item.tabId, {
            type: "RELEASE_TERMINAL",
            eventId: item.eventId,
            state: "EXPIRED",
            payloadType: item.payloadType
          }).catch(() => {});
          await removePendingRelease(item.eventId);
          continue;
        }
        console.warn(
          "[AI Guardian Background] Release status check failed:",
          item.eventId,
          response.status
        );
        continue;
      }

      const data = await response.json();

      console.log(
        "[AI Guardian Background] Release status:",
        item.eventId,
        data.state
      );

      if (data.state === "APPROVED" && !item.releaseAuthorized) {
        const releaseResponse = await fetch(
          `${BACKEND}/release/${encodeURIComponent(item.eventId)}`,
          {
            method: "POST",
            headers: {
              "X-Guardian-Release-Token": item.releaseToken
            }
          }
        );

        if (!releaseResponse.ok) {
          console.warn(
            "[AI Guardian Background] Release failed:",
            item.eventId,
            releaseResponse.status
          );
          continue;
        }

        item.releaseAuthorized = true;
        pending[item.eventId] = item;
        await savePendingEvents(pending);
      }

      if (data.state === "RELEASED" && !item.releaseAuthorized) {
        item.releaseAuthorized = true;
        pending[item.eventId] = item;
        await savePendingEvents(pending);
      }

      if (item.releaseAuthorized) {
        try {
          await chrome.tabs.sendMessage(item.tabId, {
            type: "RELEASE_APPROVED",
            eventId: item.eventId,
            payloadType: item.payloadType
          });

          await removePendingRelease(item.eventId);
        } catch (error) {
          console.warn(
            "[AI Guardian Background] Could not deliver approved release to tab; will retry.",
            item.eventId,
            error
          );
        }

        continue;
      }

      if (data.state === "REJECTED" || data.state === "EXPIRED") {
        await chrome.tabs.sendMessage(item.tabId, {
          type: "RELEASE_TERMINAL",
          eventId: item.eventId,
          state: data.state,
          payloadType: item.payloadType
        }).catch(() => {});

        await removePendingRelease(item.eventId);
      }
    } catch (error) {
      // Fail closed: network errors never release the held request.
      console.error(
        "[AI Guardian Background] Release polling error:",
        item.eventId,
        error
      );
    }
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === RELEASE_ALARM) {
    pollPendingReleases();
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  const pending = await getPendingEvents();
  let changed = false;

  for (const [eventId, item] of Object.entries(pending)) {
    if (item.tabId === tabId) {
      delete pending[eventId];
      changed = true;
    }
  }

  if (changed) {
    await savePendingEvents(pending);
  }

  if (Object.keys(pending).length === 0) {
    await chrome.alarms.clear(RELEASE_ALARM);
  }
});


chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {

    if (message.type === "REGISTER_PENDING_RELEASE") {
      registerPendingRelease(
        message.eventId,
        message.releaseToken,
        sender.tab?.id,
        message.payloadType
      )
        .then(() => sendResponse({ registered: true }))
        .catch((error) => {
          console.error(
            "[AI Guardian Background] Could not register pending release:",
            error
          );
          sendResponse({ registered: false });
        });

      return true;
    }


    /*
     * REDACTION OVERRIDE — request a reviewer's approval to release
     * the ORIGINAL of a REDACTED file. The override token never leaves
     * the extension background.
     */
    if (message.type === "OVERRIDE_REQUEST") {
      (async () => {
        let overrideToken = null;
        let requested = false;

        try {
          if (
            typeof message.eventId !== "string" || !message.eventId ||
            typeof message.sha256 !== "string" || !message.sha256 ||
            typeof sender.tab?.id !== "number"
          ) {
            sendResponse({ ok: false, error: "Invalid override request." });
            return;
          }

          overrideToken = await getOverrideToken(message.eventId);

          if (!overrideToken) {
            sendResponse({ ok: false, error: "Override offer is no longer available." });
            return;
          }

          const response = await fetch(
            overrideUrl(message.eventId, "request"),
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Sentinel-Override-Token": overrideToken
              },
              body: JSON.stringify({
                sha256: message.sha256,
                risk_acknowledged: true
              })
            }
          );

          if (!response.ok) {
            sendResponse({
              ok: false,
              error: `Override request failed (HTTP ${response.status}).`
            });
            return;
          }

          requested = true;

          const data = await response.json();

          await registerPendingOverride(
            message.eventId,
            overrideToken,
            sender.tab.id
          );
          await removeOverrideOffer(message.eventId);

          sendResponse({ ok: true, expiresAt: data.expires_at });
        } catch (error) {
          console.error("[AI Guardian Background] Override request failed.");

          if (requested && overrideToken) {
            // Request reached the backend but could not be tracked locally:
            // best-effort cancel so no unwatched approval can linger.
            fetch(overrideUrl(message.eventId, "cancel"), {
              method: "POST",
              headers: { "X-Sentinel-Override-Token": overrideToken }
            }).catch(() => {});
          }

          sendResponse({ ok: false, error: "Override request failed." });
        }
      })();

      return true;
    }


    if (message.type === "OVERRIDE_CONSUME") {
      (async () => {
        let entry = null;

        try {
          if (typeof message.eventId !== "string" || typeof message.sha256 !== "string" || !message.sha256) {
            sendResponse({ ok: false, error: "Invalid override release request." });
            return;
          }

          const pending = await getPendingEvents();
          entry = pending[message.eventId];

          if (!entry || entry.kind !== "override" || !entry.overrideToken) {
            entry = null;
            sendResponse({ ok: false, error: "No approved override is available." });
            return;
          }

          const response = await fetch(
            overrideUrl(message.eventId, "consume"),
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Sentinel-Override-Token": entry.overrideToken
              },
              body: JSON.stringify({ sha256: message.sha256 })
            }
          );

          if (!response.ok) {
            sendResponse({
              ok: false,
              error: `Override release failed (HTTP ${response.status}).`
            });
            return;
          }

          const data = await response.json();

          sendResponse({ ok: true, reviewedBy: data.reviewed_by });
        } catch (error) {
          console.error("[AI Guardian Background] Override release failed.");

          // Fail closed: the original is never released on error.
          sendResponse({ ok: false, error: "Override release failed." });
        } finally {
          // Single use: the pending entry is always removed afterwards.
          if (entry && entry.kind === "override") {
            await removePendingRelease(message.eventId).catch(() => {});
          }
        }
      })();

      return true;
    }


    if (message.type === "OVERRIDE_CANCEL") {
      (async () => {
        let entry = null;

        try {
          if (typeof message.eventId === "string" && message.eventId) {
            const pending = await getPendingEvents();
            entry = pending[message.eventId];

            const overrideToken =
              (entry && entry.kind === "override" && entry.overrideToken) ||
              (await getOverrideToken(message.eventId));

            if (overrideToken) {
              await fetch(
                overrideUrl(message.eventId, "cancel"),
                {
                  method: "POST",
                  headers: {
                    "X-Sentinel-Override-Token": overrideToken
                  }
                }
              ).catch(() => {});
            }
          }
        } catch (_) {
          // Cancel is best-effort; errors are ignored.
        }

        try {
          if (typeof message.eventId === "string" && message.eventId) {
            if (entry && entry.kind === "override") {
              await removePendingRelease(message.eventId);
            }
            await removeOverrideOffer(message.eventId);
          }
        } catch (_) {
          // Ignore local cleanup errors.
        }

        sendResponse({ ok: true });
      })();

      return true;
    }


    /*
     * STEP 5B:
     * Receive file metadata only.
    */
    if (message.type === "FILE_METADATA") {
      return;
    }


    /*
     * STEP 5C:
     * Receive actual file bytes as a Base64 string.
     *
     * We do NOT send anything to FastAPI yet.
     * This step only proves that the bytes survived
     * content.js -> background.js -> Base64 -> bytes.
    */
    if (message.type === "FILE_UPLOAD") {
      try {
        if (typeof message.data !== "string") {
          throw new Error(
            "FILE_UPLOAD data is not a Base64 string."
          );
        }

        // Convert the Base64 string back into the original binary bytes.
        const binaryString = atob(message.data);
        const decodedBytes = new Uint8Array(binaryString.length);

        for (let i = 0; i < binaryString.length; i++) {
          decodedBytes[i] = binaryString.charCodeAt(i);
        }

        // Verify that the bytes survived the extension message intact.
        if (decodedBytes.length !== message.size) {
          throw new Error(
            "File transfer size validation failed."
          );
        }

        // Convert the bytes into a Blob for the multipart HTTP upload.
        const blob = new Blob(
          [decodedBytes],
          {
            type: message.fileType || "application/octet-stream"
          }
        );

        // FormData creates a standard multipart/form-data file request.
        // Do not manually set Content-Type; fetch() adds the boundary.
        const formData = new FormData();

        formData.append(
          "file",
          blob,
          message.name || "upload"
        );

        console.log(
          "[AI Guardian Background] Sending file to FastAPI /scan-file..."
        );

        fetch(
          "http://127.0.0.1:8000/scan-file",
          {
            method: "POST",
            headers: {
              "X-Sentinel-Site": safeSiteHost(message.site || sender.tab?.url),
              "X-Sentinel-Mode": "extension_enforced",
              "X-Sentinel-Cache-Choice": message.cacheChoice || ""
            },
            body: formData
          }
        )
          .then(async (response) => {
            if (!response.ok) {
              throw new Error(
                `File backend returned HTTP ${response.status}`
              );
            }

            const data = await response.json();

            // 5G.2: return the backend decision to content.js.
            if (
              data.decision === "BLOCK" &&
              data.event_id &&
              data.release_token
            ) {
              await registerPendingRelease(
                data.event_id,
                data.release_token,
                sender.tab?.id,
                "file"
              );
            }

            // Redaction override: keep the token inside the extension and
            // expose only override_available to content.js.
            let overrideStored = false;

            if (
              data.decision === "REDACT" &&
              data.event_id &&
              data.override_token
            ) {
              try {
                await saveOverrideOffer(data.event_id, data.override_token);
                overrideStored = true;
              } catch (_) {
                console.warn(
                  "[AI Guardian Background] Could not store override offer."
                );
              }
            }

            delete data.override_token;

            if (overrideStored) {
              data.override_available = true;
            } else if ("override_available" in data) {
              data.override_available = false;
            }

            sendResponse(data);
          })
          .catch((error) => {
            console.error(
              "[AI Guardian Background] /scan-file request failed:",
              error
            );

            // Fail closed: if the file scan cannot complete, do not release it.
            sendResponse({
              entities: [],
              risk: "UNKNOWN",
              decision: "INCOMPLETE",
              scan_status: "FAILED",
              enforcement_status: "blocked_by_extension",
              error: "AI Guardian file backend unavailable."
            });
          });
      } catch (error) {
        console.error(
          "[AI Guardian Background] File upload to backend failed:",
          error
        );

        // Fail closed for malformed Base64 / decode errors too.
        sendResponse({
          entities: [],
          risk: "UNKNOWN",
          decision: "INCOMPLETE",
          scan_status: "FAILED",
          enforcement_status: "blocked_by_extension",
          error: error.message || "AI Guardian file processing failed."
        });
      }

      // Keep the message channel open until the async backend response arrives.
      return true;
    }


    /*
     * Existing text scanning flow.
     * DO NOT CHANGE.
     */
    if (message.type !== "SCAN_REQUEST") {
      return;
    }

    console.log("[AI Guardian Background] SCAN_REQUEST received.");

    fetch("http://127.0.0.1:8000/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Sentinel-Site": safeSiteHost(message.site || sender.tab?.url),
        "X-Sentinel-Mode": "extension_enforced"
      },
      body: JSON.stringify({
        text: message.text
      })
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(
            `Backend returned HTTP ${response.status}`
          );
        }

        const data = await response.json();

        if (
          data.decision === "BLOCK" &&
          data.event_id &&
          data.release_token
        ) {
          await registerPendingRelease(
            data.event_id,
            data.release_token,
            sender.tab?.id,
            "text"
          );
        }

        sendResponse(data);
      })
      .catch((error) => {
        console.error(
          "[AI Guardian Background] Scan request failed:",
          error
        );

        /*
         * Fail closed:
         * if the security backend cannot be reached,
         * do not silently allow the message through.
         */
        sendResponse({
          entities: [],
          risk: "UNKNOWN",
          decision: "INCOMPLETE",
          scan_status: "FAILED",
          enforcement_status: "blocked_by_extension",
          error: "AI Guardian backend unavailable."
        });
      });

    /*
     * fetch() is asynchronous.
     *
     * Returning true keeps the message channel open
     * until sendResponse() is called later.
     */
    return true;
  }
);